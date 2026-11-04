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

    # ---- External recon tools (subfinder, theHarvester) ----
    def _tool_queue_position(job_id: str) -> int:
        # Position in line, counting the currently-running job as position 1.
        ahead = 0
        for jid in app.state.tool_queue_ids:
            if jid == job_id:
                return ahead + 1 + (1 if app.state.active_tool_job_id else 0)
            ahead += 1
        return 0

    def _tool_queued_count() -> int:
        return len(app.state.tool_queue_ids)

    def _tool_public_job(job: dict) -> dict:
        return {
            "id": job["id"],
            "tool": job["tool"],
            "target": job["target"],
            "status": job["status"],
            "current_label": job.get("current_label", ""),
            "keys_applied": job.get("keys_applied", []),
            "found": job.get("found", 0),
            "added": job.get("added", 0),
            "skipped": job.get("skipped", 0),
            "artifact_id": job.get("artifact_id"),
            "error": job.get("error", ""),
            "queue_position": _tool_queue_position(job["id"]),
            "queued_count": _tool_queued_count(),
        }

    def _prune_tool_jobs() -> None:
        now = datetime.utcnow()
        for job_id in list(app.state.tool_jobs):
            job = app.state.tool_jobs.get(job_id)
            if not job or job["status"] in ("pending", "running"):
                continue
            finished_at = job.get("finished_at")
            if not finished_at:
                continue
            if (now - finished_at).total_seconds() > 3600:
                app.state.tool_jobs.pop(job_id, None)
                if job_id in app.state.tool_queue_ids:
                    app.state.tool_queue_ids.remove(job_id)

    async def _run_tool_job(job_id: str) -> None:
        job = app.state.tool_jobs.get(job_id)
        if not job:
            return
        try:
            job["status"] = "running"
            job["updated_at"] = datetime.utcnow().isoformat()
            spec = app.state.tools_registry[job["tool"]]
            targets = job.get("targets") or [job["target"]]
            keys = st._tool_keys_for(job["tool"])
            total_found = 0
            total_added = 0
            last_artifact_id = None
            target_errors = []
            current_target = job.get("target") or ""

            def _log_lines(result: dict) -> list:
                lines = []
                for stream in (result.get("raw_error") or "", result.get("raw") or ""):
                    for ln in stream.splitlines():
                        if ln.strip():
                            lines.append(f"# log|{ln}")
                return lines

            if spec.name == "cero":
                # Cero is a batch tool: one run over the whole host list (stdin),
                # not a per-target argv loop.
                ports = job.get("ports") or _CERO_DEFAULT_PORTS
                host_list = [h for h in targets if h]
                job["current_label"] = (
                    f"Probing {len(host_list)} host(s) with {spec.label} (ports {ports})..."
                )
                job["updated_at"] = datetime.utcnow().isoformat()
                result = await asyncio.to_thread(run_cero, spec, host_list, ports, st.ws.bin_dir)
                header = (
                    f"# tool=cero hosts={len(host_list)} ports={ports} job={job_id} "
                    f"ts={datetime.utcnow().isoformat()}"
                )
                if result.get("fqdns"):
                    body = "\n".join([header, *result["fqdns"]]) + "\n"
                    stored = st.ws.store_text(
                        body, f"cero_batch_{job_id[:8]}.txt", prefix="tool_run"
                    )
                    with st.SessionLocal() as s:
                        art = upsert_artifact(s, "subdomains_tool", stored)
                        added = import_subdomains(s, art, stored)
                        last_artifact_id = art.id
                    tail = f"# done found={len(result['fqdns'])} added={added}\n"
                    if not result.get("ok"):
                        target_error = result.get("error") or "tool error"
                        target_errors.append(f"cero: {target_error[:300]}")
                        tail += (
                            f"# error=cero: {target_error.replace(chr(10), ' | ')[:500]}\n"
                        )
                    logs = _log_lines(result)
                    if logs:
                        tail += "\n".join(logs) + "\n"
                    with stored.open("a", encoding="utf-8") as fh:
                        fh.write(tail)
                    total_found = len(result["fqdns"])
                    total_added = added
                elif not result.get("ok"):
                    err_text = (
                        (result.get("error") or "cero produced no subdomains")
                        .replace("\n", " | ")[:500]
                    )
                    target_errors.append(err_text)
                    body = (
                        f"{header}\n"
                        f"# error={err_text}\n"
                        f"# done found=0 added=0\n"
                    )
                    logs = _log_lines(result)
                    if logs:
                        body += "\n".join(logs) + "\n"
                    stored = st.ws.store_text(
                        body, f"cero_batch_{job_id[:8]}_failed.txt", prefix="tool_run"
                    )
                    with st.SessionLocal() as s:
                        upsert_artifact(s, "subdomains_tool", stored)
                job["found"] = total_found
                job["added"] = total_added
                job["skipped"] = max(0, total_found - total_added)
                job["artifact_id"] = last_artifact_id
                if target_errors and total_found == 0:
                    job["status"] = "failed"
                    job["error"] = target_errors[0][:500]
                    job["current_label"] = "Failed"
                else:
                    job["status"] = "completed"
                    job["error"] = ""
                    if total_found:
                        job["current_label"] = (
                            f"Done: {total_added} new, {total_found - total_added} already known"
                        )
                    else:
                        job["current_label"] = "Done: no subdomains found"
                    if target_errors:
                        job["current_label"] += " · error (see log)"
                return

            if spec.name == "gobuster_vhost":
                # VHost brute-force: one gobuster vhost pass per ip:port socket;
                # catch-all responses are filtered and SHA-256 verified in-process
                # (see run_vhost_socket). One artifact per socket.
                sockets = [x for x in (job.get("sockets") or targets) if x]
                job["current_label"] = f"Brute-forcing vhosts on {len(sockets)} socket(s)..."
                job["updated_at"] = datetime.utcnow().isoformat()
                wl_path = ""
                used_discovered = False
                try:
                    wl = (job.get("wordlist") or "").strip()
                    used_discovered = job.get("wordlist_source") == "discovered"
                    if not used_discovered and not wl:
                        # Default: brute-force the subdomains already discovered
                        # in the database; fall back to the tool's generic
                        # wordlist only when nothing has been discovered yet.
                        with st.SessionLocal() as s:
                            used_discovered = (
                                s.scalar(select(func.count()).select_from(Subdomain)) > 0
                            )
                    if used_discovered:
                        with st.SessionLocal() as s:
                            fqdns = [
                                f for f in s.execute(
                                    select(Subdomain.fqdn).order_by(Subdomain.fqdn)
                                ).scalars().all() if f
                            ]
                        fd, wl_path = tempfile.mkstemp(prefix="vhost_discovered_", suffix=".txt")
                        try:
                            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                                fh.write("\n".join(fqdns) + ("\n" if fqdns else ""))
                        except Exception:
                            os.close(fd)
                            raise
                        wl_desc = f"discovered({len(fqdns)})"
                    else:
                        wl = wl or spec.wordlist_default or ""
                        if wl.lower().startswith(("http://", "https://")):
                            wl_path = await asyncio.to_thread(_materialize_wordlist, wl)
                        else:
                            wl_path = wl
                        wl_desc = wl
                    for i, sock in enumerate(sockets, 1):
                        n = len(sockets)
                        job["current_label"] = (
                            f"VHost {sock} ({i}/{n})..." if n > 1 else f"VHost {sock}..."
                        )
                        job["updated_at"] = datetime.utcnow().isoformat()
                        result = await asyncio.to_thread(
                            run_vhost_socket, spec, sock, wl_path, st.ws.bin_dir
                        )
                        lines = result.get("lines") or []
                        header = (
                            f"# tool=vhost target={sock} wordlist={wl_desc} job={job_id} "
                            f"ts={datetime.utcnow().isoformat()}"
                        )
                        fname = f"vhost_{sock.replace(':', '_')}_{job_id[:8]}.txt"
                        tail = ""
                        if lines:
                            total_found += len(lines)
                            stored = st.ws.store_text(
                                header + "\n" + "\n".join(lines) + "\n",
                                fname, prefix="tool_run",
                            )
                            with st.SessionLocal() as s:
                                art = upsert_artifact(s, "subdomains_tool", stored)
                                added = import_subdomains(s, art, stored)
                                last_artifact_id = art.id
                            total_added += added
                            tail = f"# done found={len(lines)} added={added}\n"
                            if not result.get("ok"):
                                err_text = result.get("error") or "vhost error"
                                target_errors.append(f"{sock}: {err_text[:300]}")
                                tail += (
                                    f"# error={sock}: {err_text.replace(chr(10), ' | ')[:500]}\n"
                                )
                        else:
                            if not result.get("ok"):
                                err_text = (result.get("error") or "no vhost hits")
                                target_errors.append(f"{sock}: {err_text[:300]}")
                                tail = (
                                    f"# error={sock}: {err_text.replace(chr(10), ' | ')[:500]}\n"
                                )
                            tail += "# done found=0 added=0\n"
                            stored = st.ws.store_text(header + "\n", fname, prefix="tool_run")
                            with st.SessionLocal() as s:
                                upsert_artifact(s, "subdomains_tool", stored)
                        logs = _log_lines(result)
                        if tail or logs:
                            with stored.open("a", encoding="utf-8") as fh:
                                fh.write(tail)
                                if logs:
                                    fh.write("\n".join(logs) + "\n")
                finally:
                    # Only unlink the discovered-subdomain temp list; wordlists
                    # materialized from URLs are cached and reused by other jobs.
                    if used_discovered and wl_path:
                        try:
                            os.unlink(wl_path)
                        except OSError:
                            pass
                job["found"] = total_found
                job["added"] = total_added
                job["skipped"] = max(0, total_found - total_added)
                job["artifact_id"] = last_artifact_id
                if target_errors and total_found == 0:
                    job["status"] = "failed"
                    job["error"] = target_errors[0][:500]
                    job["current_label"] = "Failed"
                else:
                    job["status"] = "completed"
                    job["error"] = ""
                    if total_found:
                        job["current_label"] = (
                            f"Done: {total_added} new, {total_found - total_added} already known"
                        )
                    else:
                        job["current_label"] = "Done: no vhosts found"
                    if target_errors:
                        job["current_label"] += f" · {len(target_errors)} socket(s) failed (see log)"
                return

            if spec.name == "dnsx_reverse":
                # Reverse DNS: one dnsx -ptr pass over all selected IPs
                # (stdin), single run against the resolver set. Found FQDNs
                # are imported directly; a zero-hit run is a legitimate
                # "no PTR records" completion, not a failure.
                ips = [x for x in (job.get("ips") or targets) if x]
                resolvers = (job.get("resolvers") or ",".join(REVDNS_RESOLVERS)).strip()
                job["current_label"] = f"Resolving PTR records for {len(ips)} IP(s)..."
                job["updated_at"] = datetime.utcnow().isoformat()
                result = await asyncio.to_thread(run_rev_dns, spec, ips, resolvers, st.ws.bin_dir)
                lines = result.get("lines") or []
                header = (
                    f"# tool=revdns target={len(ips)} "
                    f"resolvers={len(resolvers.split(','))} "
                    f"job={job_id} ts={datetime.utcnow().isoformat()}"
                )
                fname = f"revdns_{job_id[:8]}.txt"
                if lines:
                    total_found += len(lines)
                    stored = st.ws.store_text(header + "\n" + "\n".join(lines) + "\n", fname, prefix="tool_run")
                    with st.SessionLocal() as s:
                        art = upsert_artifact(s, "subdomains_tool", stored)
                        added = import_subdomains(s, art, stored)
                        last_artifact_id = art.id
                    total_added += added
                    tail = f"# done found={len(lines)} added={added}\n"
                    if not result.get("ok"):
                        err_text = result.get("error") or "revdns error"
                        target_errors.append(f"revdns: {err_text[:300]}")
                        tail += f"# error=revdns: {err_text.replace(chr(10), ' | ')[:500]}\n"
                else:
                    if not result.get("ok"):
                        err_text = result.get("error") or "no PTR records found"
                        target_errors.append(f"revdns: {err_text[:300]}")
                        tail = f"# error=revdns: {err_text.replace(chr(10), ' | ')[:500]}\n"
                    else:
                        tail = ""
                    tail += "# done found=0 added=0\n"
                    stored = st.ws.store_text(header + "\n", fname, prefix="tool_run")
                    with st.SessionLocal() as s:
                        upsert_artifact(s, "subdomains_tool", stored)
                logs = _log_lines(result)
                if tail or logs:
                    with stored.open("a", encoding="utf-8") as fh:
                        fh.write(tail)
                        if logs:
                            fh.write("\n".join(logs) + "\n")
                job["found"] = total_found
                job["added"] = total_added
                job["skipped"] = max(0, total_found - total_added)
                job["artifact_id"] = last_artifact_id
                if target_errors and total_found == 0:
                    job["status"] = "failed"
                    job["error"] = target_errors[0][:500]
                    job["current_label"] = "Failed"
                else:
                    job["status"] = "completed"
                    job["error"] = ""
                    if total_found:
                        job["current_label"] = (
                            f"Done: {total_added} new, {total_found - total_added} already known"
                        )
                    else:
                        job["current_label"] = "Done: no PTR records found"
                return

            wordlist_note = f" wordlist={job['wordlist']}" if job.get("wordlist") else ""
            for i, tgt in enumerate(targets, 1):
                n = len(targets)
                current_target = tgt
                job["current_label"] = (
                    f"Running {job['tool']} against {tgt} ({i}/{n})..."
                    if n > 1
                    else f"Running {job['tool']} against {tgt}..."
                )
                job["updated_at"] = datetime.utcnow().isoformat()
                if spec.builtin:
                    result = await asyncio.to_thread(run_builtin, spec, tgt)
                else:
                    result = await asyncio.to_thread(
                        run_tool, spec, tgt, st.ws.bin_dir, keys, job.get("wordlist")
                    )
                if not result.get("fqdns"):
                    if result.get("ok"):
                        # Tool ran fine but found nothing: a valid result, not an error.
                        continue
                    # Hard failure for this target: log it and keep running the rest.
                    target_error = result.get("error") or "tool produced no subdomains"
                    target_errors.append(f"{tgt}: {target_error[:300]}")
                    err_text = target_error.replace("\n", " | ")[:500]
                    header = (
                        f"# tool={job['tool']} target={tgt}{wordlist_note} job={job_id} "
                        f"ts={datetime.utcnow().isoformat()}"
                    )
                    body = (
                        f"{header}\n"
                        f"# error={tgt}: {err_text}\n"
                        f"# done found=0 added=0\n"
                    )
                    logs = _log_lines(result)
                    if logs:
                        body += "\n".join(logs) + "\n"
                    fname = f"{job['tool']}_{tgt.replace(' ', '_')}_failed.txt"
                    stored = st.ws.store_text(body, fname, prefix="tool_run")
                    with st.SessionLocal() as s:
                        upsert_artifact(s, "subdomains_tool", stored)
                    continue
                header = (
                    f"# tool={job['tool']} target={tgt}{wordlist_note} job={job_id} "
                    f"ts={datetime.utcnow().isoformat()}"
                )
                body = "\n".join([header, *result["fqdns"]]) + "\n"
                stored = st.ws.store_text(body, f"{job['tool']}_{tgt}.txt", prefix="tool_run")
                with st.SessionLocal() as s:
                    art = upsert_artifact(s, "subdomains_tool", stored)
                    added = import_subdomains(s, art, stored)
                    last_artifact_id = art.id
                tail = f"# done found={len(result['fqdns'])} added={added}\n"
                if not result.get("ok"):
                    # e.g. timeout that still produced output: keep the result, log the error.
                    target_error = result.get("error") or "tool error"
                    target_errors.append(f"{tgt}: {target_error[:300]}")
                    tail += (
                        f"# error={tgt}: {target_error.replace(chr(10), ' | ')[:500]}\n"
                    )
                logs = _log_lines(result)
                if logs:
                    tail += "\n".join(logs) + "\n"
                with stored.open("a", encoding="utf-8") as fh:
                    fh.write(tail)
                total_found += len(result["fqdns"])
                total_added += added
            job["found"] = total_found
            job["added"] = total_added
            job["skipped"] = max(0, total_found - total_added)
            job["artifact_id"] = last_artifact_id
            if target_errors and total_found == 0:
                job["status"] = "failed"
                job["error"] = (
                    f"{len(target_errors)} of {len(targets)} targets failed; {target_errors[0]}"
                )[:500]
                job["current_label"] = "Failed"
            else:
                job["status"] = "completed"
                job["error"] = ""
                if total_found:
                    job["current_label"] = (
                        f"Done: {total_added} new, {total_found - total_added} already known"
                    )
                else:
                    job["current_label"] = "Done: no subdomains found"
                if target_errors:
                    job["current_label"] += f" · {len(target_errors)} target(s) failed (see log)"
        except Exception as e:
            job["status"] = "failed"
            job["error"] = str(e)[:500]
            job["current_label"] = "Failed"
            try:
                err_text = str(e).replace("\n", " | ")[:500]
                header = (
                    f"# tool={job['tool']} target={current_target} job={job_id} "
                    f"ts={datetime.utcnow().isoformat()}"
                )
                body = (
                    f"{header}\n"
                    f"# error={err_text}\n"
                    f"# done found=0 added=0\n"
                )
                fname = f"{job['tool']}_{(current_target or 'run').replace(' ', '_')}_failed.txt"
                stored = st.ws.store_text(body, fname, prefix="tool_run")
                with st.SessionLocal() as s:
                    upsert_artifact(s, "subdomains_tool", stored)
            except Exception:
                pass
        finally:
            job["finished_at"] = datetime.utcnow()
            job["updated_at"] = datetime.utcnow().isoformat()
            if app.state.active_tool_job_id == job_id:
                app.state.active_tool_job_id = None
            app.state.tool_active_task = None

    async def _tool_worker() -> None:
        while True:
            job_id = await app.state.tool_queue.get()
            try:
                if job_id in app.state.tool_queue_ids:
                    app.state.tool_queue_ids.remove(job_id)
                job = app.state.tool_jobs.get(job_id)
                if not job or job["status"] != "pending":
                    continue
                app.state.active_tool_job_id = job_id
                app.state.tool_active_task = asyncio.current_task()
                await _run_tool_job(job_id)
            except Exception:
                job = app.state.tool_jobs.get(job_id)
                if job:
                    job["status"] = "failed"
                    job["error"] = "tool worker crashed"
                    job["finished_at"] = datetime.utcnow()
                    job["updated_at"] = datetime.utcnow().isoformat()
            finally:
                if app.state.active_tool_job_id == job_id:
                    app.state.active_tool_job_id = None
                app.state.tool_queue.task_done()

    def _ensure_tool_worker() -> None:
        task = app.state.tool_worker_task
        if task is not None and not task.done():
            return
        app.state.tool_worker_task = asyncio.create_task(_tool_worker())

    @router.get("/api/tools")
    def api_tools():
        out = []
        for spec in app.state.tools_registry.values():
            if spec.builtin:
                out.append(
                    {
                        "name": spec.name,
                        "label": spec.label,
                        "available": True,
                        "path": None,
                        "version": "",
                        "builtin": True,
                        "input_mode": spec.input_mode,
                        "network_note": spec.network_note,
                        "install_commands": spec.install_commands,
                        "repo_url": spec.repo_url,
                        "wordlist_default": spec.wordlist_default,
                    }
                )
                continue
            path = find_tool(spec.name, spec, st.ws.bin_dir)
            out.append(
                {
                    "name": spec.name,
                    "label": spec.label,
                    "available": path is not None,
                    "path": str(path) if path else None,
                    "version": tool_version(path) if path else "",
                    "builtin": False,
                    "input_mode": spec.input_mode,
                    "network_note": spec.network_note,
                    "install_commands": spec.install_commands,
                    "repo_url": spec.repo_url,
                    "wordlist_default": spec.wordlist_default,
                }
            )
        return {"ok": True, "bin_dir": str(st.ws.bin_dir), "tools": out}

    @router.get("/api/tools/cero/hosts")
    def api_tools_cero_hosts():
        """In-scope hosts (subdomains + IPs/subnets) selectable as cero targets."""
        with st.db() as s:
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            sub_ips = list_all_subdomain_ips(s)
            subs = s.execute(select(Subdomain).order_by(Subdomain.fqdn)).scalars().all()
            sub_hosts = []
            for sub in subs:
                fq = (sub.fqdn or "").strip().lower().rstrip(".")
                if not fq:
                    continue
                resolved = sub_ips.get(fq, [])
                if domain_in_scope(
                    fq, domains, domain_all_subs, domain_subs_if_ip,
                    resolved, ips, subnets, excluded,
                ):
                    sub_hosts.append({"label": fq, "type": "subdomain", "value": fq})
            ip_items = s.execute(
                select(ScopeItem)
                .where(ScopeItem.in_scope == 1, ScopeItem.kind.in_(["ip", "subnet"]))
                .order_by(ScopeItem.value)
            ).scalars().all()
            ip_hosts = []
            seen = set()
            for it in ip_items:
                v = (it.value or "").strip().lower().strip(".")
                if not v or v in seen:
                    continue
                seen.add(v)
                ip_hosts.append({
                    "label": v,
                    "type": "subnet" if it.kind == "subnet" else "ip",
                    "value": v,
                })
        return {
            "ok": True,
            "hosts": sub_hosts + ip_hosts,
            "default_ports": _CERO_DEFAULT_PORTS,
        }

    @router.get("/api/tools/vhost/sockets")
    def api_tools_vhost_sockets():
        """Open TCP ip:port sockets on web-ish ports, selectable as vhost targets."""
        with st.db() as s:
            rows = s.execute(
                select(Host.ip, Service.port, Service.service_name)
                .join(Service, Service.host_id == Host.id)
                .where(Service.proto == "tcp", Service.state == "open")
                .order_by(Host.ip, Service.port)
            ).all()
            items = []
            seen = set()
            for ip, port, svc in rows:
                ip = (ip or "").strip()
                if not ip or port is None:
                    continue
                if port not in _VHOST_SOCKET_PORTS:
                    continue
                key = f"{ip}:{port}"
                if key in seen:
                    continue
                seen.add(key)
                items.append({
                    "label": key + (f" ({svc})" if svc else ""),
                    "value": key,
                    "port": int(port),
                })
            discovered = s.scalar(select(func.count()).select_from(Subdomain))
        return {"ok": True, "sockets": items, "discovered_count": int(discovered or 0)}

    @router.get("/api/tools/revdns/ips")
    def api_tools_revdns_ips():
        """IPs from the hosts table, selectable as reverse-DNS targets."""
        with st.db() as s:
            rows = s.execute(
                select(Host.ip, Host.hostname, Host.tag).order_by(Host.ip)
            ).all()
            items = []
            seen = set()
            for ip, hostname, tag in rows:
                ip = (ip or "").strip()
                if not ip or ip in seen:
                    continue
                try:
                    canon = validate_ip(ip)
                except ValueError:
                    continue  # skip non-literal entries (defensive)
                if canon in seen:
                    continue
                seen.add(canon)
                label = canon
                if hostname:
                    label = f"{canon} ({hostname})"
                elif tag:
                    label = f"{canon} ({tag})"
                items.append({"label": label, "value": canon})
        return {
            "ok": True,
            "ips": items,
            "default_resolvers": ",".join(REVDNS_RESOLVERS),
        }

    @router.post("/api/tools/run")
    async def api_tools_run(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
        tool = str(body.get("tool") or "").strip()
        target_raw = str(body.get("target") or "").strip()
        spec = app.state.tools_registry.get(tool)
        if not spec:
            return JSONResponse({"ok": False, "error": "Unknown tool"}, status_code=400)
        if spec.name == "cero":
            raw_hosts = body.get("hosts")
            if not isinstance(raw_hosts, list):
                return JSONResponse({"ok": False, "error": "hosts must be a list"}, status_code=400)
            hosts: list = []
            for h in raw_hosts:
                h = str(h or "").strip()
                if not h:
                    continue
                if h.startswith("-"):
                    return JSONResponse({"ok": False, "error": "invalid host"}, status_code=400)
                if h in hosts:
                    continue
                hosts.append(h)
            if not hosts:
                return JSONResponse({"ok": False, "error": "select at least one host"}, status_code=400)
            if len(hosts) > 500:
                return JSONResponse(
                    {"ok": False, "error": "too many hosts (max 500 per run)"}, status_code=400
                )
            ports = re.sub(r"[^0-9,]", "", str(body.get("ports") or ""))
            if not ports.strip(","):
                return JSONResponse({"ok": False, "error": "ports are required"}, status_code=400)
            if not find_tool(spec.name, spec, st.ws.bin_dir):
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"{spec.label} is not installed — see the Tools page for install commands.",
                    },
                    status_code=400,
                )
            _prune_tool_jobs()
            if len(app.state.tool_queue_ids) >= 5:
                return JSONResponse(
                    {"ok": False, "error": "Tool run queue is full (max 5 waiting)"},
                    status_code=409,
                )
            job_id = uuid.uuid4().hex
            now = datetime.utcnow()
            job = {
                "id": job_id,
                "tool": spec.name,
                "target": f"{len(hosts)} host(s)",
                "targets": hosts,
                "ports": ports,
                "status": "pending",
                "current_label": "Queued...",
                "keys_applied": sorted(st._tool_keys_for(spec.name).keys()),
                "found": 0,
                "added": 0,
                "skipped": 0,
                "artifact_id": None,
                "error": "",
                "created_at": now,
                "updated_at": now,
                "finished_at": None,
            }
            app.state.tool_jobs[job_id] = job
            app.state.tool_queue_ids.append(job_id)
            app.state.tool_queue.put_nowait(job_id)
            _ensure_tool_worker()
            return {"ok": True, "job": _tool_public_job(job), "queue_position": _tool_queue_position(job_id)}
        if spec.name == "gobuster_vhost":
            raw_sockets = body.get("sockets")
            if not isinstance(raw_sockets, list):
                return JSONResponse({"ok": False, "error": "sockets must be a list"}, status_code=400)
            sockets: list = []
            for v in raw_sockets:
                try:
                    sock = validate_socket(str(v or ""))
                except ValueError:
                    return JSONResponse({"ok": False, "error": "invalid socket in list"}, status_code=400)
                if sock not in sockets:
                    sockets.append(sock)
            if not sockets:
                return JSONResponse({"ok": False, "error": "select at least one socket"}, status_code=400)
            if len(sockets) > 20:
                return JSONResponse(
                    {"ok": False, "error": "too many sockets (max 20 per run)"}, status_code=400
                )
            wordlist = str(body.get("wordlist") or "").strip()
            wordlist_source = str(body.get("wordlist_source") or "").strip()
            if wordlist_source not in ("", "discovered"):
                return JSONResponse({"ok": False, "error": "invalid wordlist_source"}, status_code=400)
            if wordlist_source == "discovered":
                with st.db() as s:
                    fq_count = s.scalar(select(func.count()).select_from(Subdomain))
                if not fq_count:
                    return JSONResponse(
                        {"ok": False, "error": "no discovered subdomains to use as a wordlist"},
                        status_code=400,
                    )
                wordlist = ""  # discovered source overrides any pasted wordlist
            elif wordlist:
                try:
                    wordlist = validate_wordlist(wordlist)
                except ValueError as e:
                    return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
            if not find_tool(spec.name, spec, st.ws.bin_dir):
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"{spec.label} is not installed — see the Tools page for install commands.",
                    },
                    status_code=400,
                )
            _prune_tool_jobs()
            if len(app.state.tool_queue_ids) >= 5:
                return JSONResponse(
                    {"ok": False, "error": "Tool run queue is full (max 5 waiting)"},
                    status_code=409,
                )
            job_id = uuid.uuid4().hex
            now = datetime.utcnow()
            job = {
                "id": job_id,
                "tool": spec.name,
                "target": f"{len(sockets)} socket(s)",
                "targets": sockets,
                "sockets": sockets,
                "wordlist": wordlist,
                "wordlist_source": wordlist_source,
                "status": "pending",
                "current_label": "Queued...",
                "keys_applied": sorted(st._tool_keys_for(spec.name).keys()),
                "found": 0,
                "added": 0,
                "skipped": 0,
                "artifact_id": None,
                "error": "",
                "created_at": now,
                "updated_at": now,
                "finished_at": None,
            }
            app.state.tool_jobs[job_id] = job
            app.state.tool_queue_ids.append(job_id)
            app.state.tool_queue.put_nowait(job_id)
            _ensure_tool_worker()
            return {"ok": True, "job": _tool_public_job(job), "queue_position": _tool_queue_position(job_id)}
        if spec.name == "dnsx_reverse":
            raw_ips = body.get("ips")
            if not isinstance(raw_ips, list):
                return JSONResponse({"ok": False, "error": "ips must be a list"}, status_code=400)
            ips: list = []
            for v in raw_ips:
                try:
                    ip = validate_ip(str(v or ""))
                except ValueError:
                    return JSONResponse(
                        {"ok": False, "error": "invalid IP in list (IPv4/IPv6 literals only)"},
                        status_code=400,
                    )
                if ip not in ips:
                    ips.append(ip)
            if not ips:
                return JSONResponse({"ok": False, "error": "select at least one IP"}, status_code=400)
            if len(ips) > REVDNS_MAX_IPS:
                return JSONResponse(
                    {"ok": False, "error": f"too many IPs (max {REVDNS_MAX_IPS} per run)"},
                    status_code=400,
                )
            try:
                resolvers = validate_resolvers(str(body.get("resolvers") or ""))
            except ValueError as e:
                return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
            if not find_tool(spec.name, spec, st.ws.bin_dir):
                return JSONResponse(
                    {
                        "ok": False,
                        "error": f"{spec.label} is not installed — see the Tools page for install commands.",
                    },
                    status_code=400,
                )
            _prune_tool_jobs()
            if len(app.state.tool_queue_ids) >= 5:
                return JSONResponse(
                    {"ok": False, "error": "Tool run queue is full (max 5 waiting)"},
                    status_code=409,
                )
            job_id = uuid.uuid4().hex
            now = datetime.utcnow()
            job = {
                "id": job_id,
                "tool": spec.name,
                "target": f"{len(ips)} IP(s)",
                "targets": ips,
                "ips": ips,
                "resolvers": resolvers,
                "status": "pending",
                "current_label": "Queued...",
                "keys_applied": sorted(st._tool_keys_for(spec.name).keys()),
                "found": 0,
                "added": 0,
                "skipped": 0,
                "artifact_id": None,
                "error": "",
                "created_at": now,
                "updated_at": now,
                "finished_at": None,
            }
            app.state.tool_jobs[job_id] = job
            app.state.tool_queue_ids.append(job_id)
            app.state.tool_queue.put_nowait(job_id)
            _ensure_tool_worker()
            return {"ok": True, "job": _tool_public_job(job), "queue_position": _tool_queue_position(job_id)}
        tokens = [t for t in re.split(r"[,\s]+", target_raw) if t]
        if not tokens:
            return JSONResponse({"ok": False, "error": "target is required"}, status_code=400)
        if len(tokens) > 20:
            return JSONResponse(
                {"ok": False, "error": "too many targets (max 20 per run)"}, status_code=400
            )
        targets = []
        try:
            for tok in tokens:
                t = validate_target(tok)
                if t not in targets:
                    targets.append(t)
        except ValueError as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        target = " ".join(targets)
        wordlist = str(body.get("wordlist") or "").strip()
        if wordlist:
            try:
                wordlist = validate_wordlist(wordlist)
            except ValueError as e:
                return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        if not spec.builtin and not find_tool(spec.name, spec, st.ws.bin_dir):
            return JSONResponse(
                {
                    "ok": False,
                    "error": f"{spec.label} is not installed — see the Tools page for install commands.",
                },
                status_code=400,
            )
        _prune_tool_jobs()
        if len(app.state.tool_queue_ids) >= 5:
            return JSONResponse(
                {"ok": False, "error": "Tool run queue is full (max 5 waiting)"},
                status_code=409,
            )
        job_id = uuid.uuid4().hex
        now = datetime.utcnow()
        job = {
            "id": job_id,
            "tool": spec.name,
            "target": target,
            "targets": targets,
            "wordlist": wordlist,
            "status": "pending",
            "current_label": "Queued...",
            "keys_applied": sorted(st._tool_keys_for(spec.name).keys()),
            "found": 0,
            "added": 0,
            "skipped": 0,
            "artifact_id": None,
            "error": "",
            "created_at": now,
            "updated_at": now,
            "finished_at": None,
        }
        app.state.tool_jobs[job_id] = job
        app.state.tool_queue_ids.append(job_id)
        app.state.tool_queue.put_nowait(job_id)
        _ensure_tool_worker()
        return {"ok": True, "job": _tool_public_job(job), "queue_position": _tool_queue_position(job_id)}

    @router.get("/api/tools/jobs/active")
    def api_tools_jobs_active():
        _prune_tool_jobs()
        running = None
        queued_ids = list(app.state.tool_queue_ids)
        last = None
        for job in app.state.tool_jobs.values():
            if job["status"] == "running":
                running = job
                continue
            if job["status"] == "pending":
                continue
            finished_at = job.get("finished_at")
            if not finished_at:
                continue
            if last is None or finished_at > last.get("finished_at"):
                last = job
        active = running
        if active is None and queued_ids:
            active = app.state.tool_jobs.get(queued_ids[0])
        queued = [
            {"tool": app.state.tool_jobs[jid]["tool"], "target": app.state.tool_jobs[jid]["target"]}
            for jid in queued_ids
            if jid in app.state.tool_jobs
        ]
        return {
            "ok": True,
            "active_job": _tool_public_job(active) if active else None,
            "last_job": _tool_public_job(last) if last else None,
            "queued_count": len(queued),
            "queued": queued,
        }

    @router.get("/api/tools/jobs/{job_id}")
    def api_tools_job_status(job_id: str):
        job = app.state.tool_jobs.get(job_id)
        if not job:
            return JSONResponse({"ok": False, "error": "Job not found"}, status_code=404)
        return {"ok": True, "job": _tool_public_job(job)}

    st._prune_tool_jobs = _prune_tool_jobs
    st.api_tools = api_tools
    return router
