from __future__ import annotations
from pathlib import Path
import asyncio, json, ipaddress, os, re, shlex, socket, ssl, sys, tempfile, uuid
import html as html_lib
from urllib.parse import quote_plus, parse_qsl, urlencode, urlsplit
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import APIRouter, Request, UploadFile, File, Form, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse

from sqlalchemy import select, func, text, or_
from sqlalchemy.orm import Session

from .. import netproxy
from .. import nsecatalog
from ..nse import SEVERITY_RANK
from ..models import (
    Host,
    Service,
    Subdomain,
    Email,
    Artifact,
    ServiceEvidence,
    Document,
    Note,
    GlobalNote,
    ScopeItem,
    ScopeExclusion,
    CloudItem,
    ValidUser,
    Credential,
    NameItem,
    SocialMedia,
    WebUrl,
    DomainInfo,
    PasswordSprayService,
    PasswordSprayAttempt,
    ProfilingRow,
    RegistrarInfo,
    AppSettings,
    UploadLog,
    SmbShare,
    TimelineDay,
    TimelineEntry,
    WebScreenshot,
    WebProtocolProbe,
    ServiceApiKey,
    NseResult,
    ServiceFinding,
)
from ..parsers import (
    upsert_artifact,
    import_nmap_xml,
    import_subdomains,
    import_emails,
    import_document,
    extract_doc_names,
    extract_doc_software,
    upsert_host,
    import_ad_users,
    import_names_emails,
    import_creds_to_names,
    import_web_urls,
    import_names,
    import_prowl_phase1,
    import_zone_transfers,
    import_smtp,
    import_bbot,
    import_bbot_cloud,
    import_mixed_hashes,
    import_smbmap,
    resolve_ips_concurrent,
    DOMAIN_RE,
    hostname_as_domain,
    link_host_domain as parser_link_host_domain,
)
from ..tools import (
    build_tools,
    find_tool,
    run_tool,
    run_cero,
    run_vhost_socket,
    run_builtin,
    _CERO_DEFAULT_PORTS,
    keys_for_tool,
    parse_tool_config,
    service_key_registry,
    tool_config_preview,
    tool_version,
    validate_target,
    validate_wordlist,
    validate_socket,
    validate_ip,
    validate_resolvers,
    run_rev_dns,
    REVDNS_RESOLVERS,
    REVDNS_MAX_IPS,
    _materialize_wordlist,
)

from ..helpers import (
    _WEB_PORTS, _VHOST_SOCKET_PORTS, _WEB_SERVICE_NAME_RE,
    _WEB_PRODUCT_RE, _HTTP_STATUS_RE, _HTTP_HTML_RE,
    _HTTP_CONTENT_TYPE_RE, _HTTP_HEADER_RE, _hostname_as_domain,
    _web_url_host_from_domain, _like_escape, _web_url_host_from_url,
    _smb_user_label, load_scope_exclusions, scope_sets,
    ip_in_scope, domain_in_scope, host_in_scope,
    email_in_scope, list_host_domains, list_all_host_domains,
    _split_lines, list_subdomain_ips, list_all_subdomain_ips,
    list_subdomain_hosts, list_hosts_by_ip, get_open_web_ports_by_ip,
    link_host_domain,
)
from ..state import AppState


def build(st: AppState, app) -> APIRouter:
    router = APIRouter()

    @router.get("/api/tools/discoveries")
    def api_tools_discoveries():
        with st.SessionLocal() as s:
            arts = (
                s.query(Artifact)
                .filter(Artifact.type == "subdomains_tool")
                .order_by(Artifact.created_at.desc())
                .all()
            )
            if not arts:
                return {"ok": True, "tools": [], "subdomains": []}
            parsed = []
            for art in arts:
                tool = ""
                target = ""
                job_id = ""
                ts = art.created_at.isoformat() if art.created_at else ""
                added_hdr = None
                error = ""
                fqdns = []
                logs = []
                p = Path(art.stored_path)
                if p.exists():
                    try:
                        text = p.read_text(errors="ignore")
                    except OSError:
                        text = ""
                    for line in text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith("# done"):
                            for part in line[7:].split():
                                k, _, v = part.partition("=")
                                if k == "added" and v.isdigit():
                                    added_hdr = int(v)
                            continue
                        if line.startswith("# tool="):
                            for part in line[2:].split():
                                k, _, v = part.partition("=")
                                if k == "tool":
                                    tool = v
                                elif k == "target":
                                    target = v
                                elif k == "job":
                                    job_id = v
                                elif k == "ts" and not ts:
                                    ts = v
                            continue
                        if line.startswith("# error="):
                            error = line[len("# error="):].strip()
                            continue
                        if line.startswith("# log|"):
                            logs.append(line[len("# log|"):])
                            continue
                        tok = line.split()[0].lower().rstrip(".")
                        if tok and DOMAIN_RE.match(tok) and tok not in fqdns:
                            fqdns.append(tok)
                parsed.append(
                    {
                        "artifact_id": art.id,
                        "tool": tool,
                        "target": target,
                        "job_id": job_id,
                        "ts": ts,
                        "added": added_hdr,
                        "error": error,
                        "fqdns": fqdns,
                        "logs": logs,
                    }
                )
            # Group artifacts into runs: one run per job (older artifacts without a
            # job id fall back to one run per artifact). Ascending time order keeps
            # targets in the order the job actually ran them.
            runs_by_key: dict = {}
            for item in sorted(parsed, key=lambda i: i["ts"] or ""):
                key = (item["tool"], item["job_id"] or f"art:{item['artifact_id']}")
                run = runs_by_key.get(key)
                if run is None:
                    run = {
                        "job_id": item["job_id"] or None,
                        "tool": item["tool"],
                        "created_at": item["ts"],
                        "targets": [],
                        "found": 0,
                        "added": None if item["added"] is None else 0,
                        "fqdns": [],
                        "errors": [],
                        "logs": [],
                    }
                    runs_by_key[key] = run
                if item["target"] and item["target"] not in run["targets"]:
                    run["targets"].append(item["target"])
                if item["error"] and item["error"] not in run["errors"]:
                    run["errors"].append(item["error"])
                if item["logs"]:
                    run["logs"].append({"target": item["target"], "lines": item["logs"]})
                run["found"] += len(item["fqdns"])
                if item["added"] is None:
                    run["added"] = None
                elif run["added"] is not None:
                    run["added"] += item["added"]
                if item["ts"] and (not run["created_at"] or item["ts"] < run["created_at"]):
                    run["created_at"] = item["ts"]
                for f in item["fqdns"]:
                    if f not in run["fqdns"]:
                        run["fqdns"].append(f)
            runs = list(runs_by_key.values())
            runs.sort(key=lambda r: r["created_at"])
            # A subdomain is "new" in a run if no earlier run found it.
            first_seen: dict = {}
            for r in runs:
                for f in r["fqdns"]:
                    if f not in first_seen:
                        first_seen[f] = r
            for r in runs:
                r["new_set"] = {f for f in r["fqdns"] if first_seen[f] is r}
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            resolved = list_all_subdomain_ips(s)
            scope_of: dict = {}
            for r in runs:
                for f in r["fqdns"]:
                    if f in scope_of:
                        continue
                    scope_of[f] = bool(
                        domain_in_scope(
                            f,
                            domains,
                            domain_all_subs,
                            domain_subs_if_ip,
                            resolved.get(f, []),
                            ips,
                            subnets,
                            excluded,
                        )
                    )
            # Flat union of every subdomain found across all runs, with the
            # runs that found it (deduped; one entry per fqdn).
            union: dict = {}
            for r in runs:
                for f in r["fqdns"]:
                    e = union.get(f)
                    if e is None:
                        e = union[f] = {
                            "fqdn": f,
                            "in_scope": scope_of[f],
                            "runs": [],
                        }
                    e["runs"].append({"tool": r["tool"], "created_at": r["created_at"]})
            subdomains_out = [union[f] for f in sorted(union)]
            tools_out = []
            for spec in app.state.tools_registry.values():
                truns = [r for r in runs if r["tool"] == spec.name]
                if not truns:
                    continue
                unique = {f for r in truns for f in r["fqdns"]}
                tools_out.append(
                    {
                        "name": spec.name,
                        "unique": len(unique),
                        "runs": [
                            {
                                "job_id": r["job_id"],
                                "created_at": r["created_at"],
                                "targets": r["targets"],
                                "found": r["found"],
                                "added": r["added"],
                                "new_count": len(r["new_set"]),
                                "errors": r["errors"],
                                "logs": r["logs"],
                            }
                            for r in reversed(truns)
                        ],
                    }
                )
            return {"ok": True, "tools": tools_out, "subdomains": subdomains_out}

    # ---- Global "running processes" registry (top-right indicator) ----
    def _register_process_provider(fn) -> None:
        app.state.process_providers.append(fn)

    def _tool_processes() -> list:
        st._prune_tool_jobs()
        out = []
        for job in app.state.tool_jobs.values():
            if job["status"] not in ("pending", "running"):
                continue
            label = job.get("current_label") or ""
            if not label or label in ("Starting...", "Queued..."):
                label = f"{job['tool']}: {job['target']}"
            if job["status"] == "pending":
                label = f"queued — {label}"
            out.append(
                {
                    "kind": "tool",
                    "id": job["id"],
                    "status": job["status"],
                    "label": label,
                    "href": "/subdomains-discovery",
                }
            )
        return out

    def _screenshot_processes() -> list:
        st._prune_screenshot_jobs()
        current = st._get_current_screenshot_job()
        if not current:
            return []
        if current["status"] == "running":
            label = f"Screenshots {current['completed']}/{current['total']}"
        else:
            label = "Screenshots queued"
        return [
            {
                "kind": "screenshot",
                "id": current["id"],
                "status": current["status"],
                "label": label,
                "href": "/subdomains",
            }
        ]

    _register_process_provider(_tool_processes)
    _register_process_provider(_screenshot_processes)

    @router.get("/api/jobs/active")
    def api_all_jobs_active():
        jobs = []
        for provider in list(app.state.process_providers):
            try:
                jobs.extend(provider())
            except Exception:
                continue
        return {"ok": True, "jobs": jobs}

    return router
