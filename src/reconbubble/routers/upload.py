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


def _fit_json_list(items, limit: int) -> str:
    """Serialize *items* as a JSON array of strings that fits in *limit* chars.

    Trailing items are dropped when the budget runs out; if the first item
    alone exceeds the budget it is truncated. The result is always valid JSON,
    unlike ``json.dumps(items)[:limit]`` which can cut mid-string.
    """
    out: list[str] = []
    size = 2  # length of "[]"
    for item in items:
        piece = json.dumps(str(item), ensure_ascii=False)
        if size + len(piece) + 1 > limit:
            if not out:
                # one item bigger than the whole budget: truncate it in place
                budget = max(limit - 2, 4)
                text = str(item)
                piece = json.dumps(text, ensure_ascii=False)
                while len(piece) > budget and len(text) > 1:
                    text = text[: max(1, len(text) // 2)]
                    piece = json.dumps(text + "…", ensure_ascii=False)
                out.append(piece)
            break
        out.append(piece)
        size += len(piece) + 1
    return "[" + ",".join(out) + "]"


def build(st: AppState, app) -> APIRouter:
    router = APIRouter()

    def _upload_counts(s: Session) -> tuple[list[dict], int]:
        rows = s.execute(
            select(UploadLog.kind, func.count(UploadLog.id)).group_by(UploadLog.kind)
        ).all()
        counts = {kind: int(count) for kind, count in rows}
        upload_type_labels = [
            ("nmap_xml", "Nmap XML"),
            ("doc", "OSINT document"),
            ("prowl_phase1", "Prowler phase 1"),
            ("zone_transfers", "Prowler zone transfers"),
            ("smtp", "Prowler SMTP"),
            ("names_emails", "Names - Email List"),
            ("names", "Names list"),
            ("bbot", "BBOT"),
            ("subdomains", "Subdomains list"),
            ("urls", "Web URLs list"),
            ("ad_users", "Active Directory Users"),
            ("mixed_hashes", "AD - Mixed Hashes"),
            ("name_creds", "Credentials → Users"),
            ("smb_shares", "SMB Shares"),
        ]
        type_counts = [
            {"kind": kind, "label": label, "count": counts.get(kind, 0)}
            for kind, label in upload_type_labels
        ]
        return type_counts, sum(entry["count"] for entry in type_counts)

    def _upload_context(request: Request, users: list, error: str | None = None, **extra) -> dict:
        with st.db() as s:
            type_counts, total_uploads = _upload_counts(s)
        ctx = {
            "request": request,
            "workspace": st.ws,
            "users": users,
            "user_label": _smb_user_label,
            "type_counts": type_counts,
            "total_uploads": total_uploads,
        }
        if error is not None:
            ctx["error"] = error
        ctx.update(extra)
        return ctx

    @router.get("/upload", response_class=HTMLResponse)
    def upload_page(request: Request):
        with st.db() as s:
            all_users = (
                s.execute(
                    select(NameItem).order_by(
                        NameItem.last_name.asc(), NameItem.first_name.asc()
                    )
                )
                .scalars()
                .all()
            )
            # Only users who can actually authenticate to an SMB share
            # (stored password or NTLM hash) are offered for the import.
            users = [
                u for u in all_users
                if (u.password or "").strip() or (u.ntlm_hash or "").strip()
            ]
        return st.templates.TemplateResponse("upload.html", _upload_context(request, users))

    @router.post("/upload")
    async def upload(
        request: Request,
        kind: str = Form(...),
        file: list[UploadFile] | None = File(None),
        raw_text: str = Form(""),
        raw_filename: str = Form(""),
        smb_user_id: int = Form(0),
    ):
        """Handle uploads (file or raw paste) and import into DB."""
        if kind == "smb_shares":
            if smb_user_id <= 0:
                return st.templates.TemplateResponse(
                    "upload.html",
                    _upload_context(request, [], error="Select a user for SMB share imports."),
                    status_code=400,
                )
            with st.db() as s:
                if s.get(NameItem, smb_user_id) is None:
                    return st.templates.TemplateResponse(
                        "upload.html",
                        _upload_context(request, [], error="Selected user not found."),
                        status_code=400,
                    )
        stored: str | None = None
        redirect_map = {
            "nmap_xml": "/assets",
            "subdomains": "/subdomains",
            "names_emails": "/users",
            "doc": "/docs",
            "ad_users": "/users",
            "name_creds": "/users",
            "urls": "/assets",
            "names": "/users",
            "bbot": "/subdomains",
            "prowl_phase1": "/subdomains",
            "zone_transfers": "/subdomains",
            "smtp": "/users",
            "mixed_hashes": "/users",
            "bbot_cloud": "/cloud",
            "smb_shares": "/smb-shares",
        }
        with st.db() as s:
            _all_upload_users = (
                s.execute(
                    select(NameItem).order_by(
                        NameItem.last_name.asc(), NameItem.first_name.asc()
                    )
                )
                .scalars()
                .all()
            )
            # Mirror the upload page: only credential-bearing users are
            # re-offered when the form re-renders after a POST.
            upload_users = [
                u for u in _all_upload_users
                if (u.password or "").strip() or (u.ntlm_hash or "").strip()
            ]
        def _import_file(s: Session, art: Artifact, stored_path: str, fname: str, user_id: int | None = None) -> dict:
            """Run the appropriate parser and return normalized result dict."""
            p = Path(stored_path)
            try:
                if kind == "nmap_xml":
                    res = import_nmap_xml(s, art, p)
                elif kind == "subdomains":
                    count = import_subdomains(s, art, p)
                    fqdn_list = s.execute(select(Subdomain.fqdn)).scalars().all()
                    ip_map = resolve_ips_concurrent(list(fqdn_list))
                    for fqdn, ips in ip_map.items():
                        for ip in ips:
                            try:
                                h = upsert_host(s, ip, "", "")
                                link_host_domain(s, h.id, fqdn)
                            except Exception:
                                continue
                    res = {"added": count, "skipped": 0, "unmatched": []}
                elif kind == "names_emails":
                    res = {"added": import_names_emails(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "doc":
                    res = {"added": import_document(s, art, p), "skipped": 0, "unmatched": []}
                    extract_doc_names(s)
                    extract_doc_software(s)
                elif kind == "ad_users":
                    res = {"added": import_ad_users(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "name_creds":
                    res = import_creds_to_names(s, art, p)
                elif kind == "urls":
                    res = {"added": import_web_urls(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "names":
                    res = {"added": import_names(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "prowl_phase1":
                    res = {"added": import_prowl_phase1(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "zone_transfers":
                    res = {"added": import_zone_transfers(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "smtp":
                    res = {"added": import_smtp(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "bbot":
                    res = import_bbot(s, art, p)
                elif kind == "bbot_cloud":
                    res = import_bbot_cloud(s, art, p)
                elif kind == "mixed_hashes":
                    res = import_mixed_hashes(s, art, p)
                elif kind == "smb_shares":
                    res = import_smbmap(s, art, p, user_id=user_id)
                else:
                    res = {"added": 0, "skipped": 0, "unmatched": [f"Unknown type: {kind}"]}
            except Exception as e:
                res = {"added": 0, "skipped": 0, "unmatched": [f"Error parsing {fname}: {e}"]}
            return res

        def _normalize_result(res: dict) -> dict:
            """Normalize any parser result to {added, skipped, unmatched, details}."""
            if isinstance(res, dict):
                added = res.get("added", 0)
                skipped = res.get("skipped", 0)
                unmatched = res.get("unmatched", []) or []
                details = res.get("details", {})
                # Map known parser-specific keys
                if kind == "nmap_xml":
                    added = res.get("hosts_added", 0)
                    details = {
                        "hosts": res.get("hosts_added", 0),
                        "services": res.get("services_added", 0),
                        "evidence": res.get("evidence_added", 0),
                        "hosts_in_file": res.get("total_hosts", 0),
                    }
                    if res.get("notice"):
                        details["notice"] = res["notice"]
                    if res.get("total_hosts", 0) == 0:
                        unmatched = list(unmatched) + [
                            "Note: Nmap XML parsed OK but contained 0 <host> entries - the scan "
                            "likely found nothing (target unreachable / no open ports). No data imported."
                        ]
                elif kind == "bbot":
                    added = res.get("subdomains", 0) + res.get("hosts", 0)
                    details = {
                        "subdomains": res.get("subdomains", 0),
                        "hosts": res.get("hosts", 0),
                        "services": res.get("services", 0),
                        "urls": res.get("urls", 0),
                        "notes": res.get("notes", 0),
                    }
                elif kind == "bbot_cloud":
                    added = res.get("subdomains", 0) + res.get("hosts", 0)
                    details = {
                        "subdomains": res.get("subdomains", 0),
                        "hosts": res.get("hosts", 0),
                        "cloud_items": res.get("cloud_items", 0),
                        "notes": res.get("notes", 0),
                    }
                elif kind == "mixed_hashes":
                    counts = res.get("counts", {}) or {}
                    added = sum(
                        v for k, v in counts.items()
                        if k != "skipped" and isinstance(v, int)
                    )
                    skipped = counts.get("skipped", 0)
                    unmatched = res.get("unmatched", []) or []
                    details = {k: v for k, v in counts.items() if isinstance(v, int)}
                elif kind == "name_creds":
                    added = res.get("added", 0)
                    updated = res.get("updated", 0)
                    skipped = res.get("skipped", 0)
                    unmatched = res.get("unmatched", []) or []
                    conflicts = res.get("conflicts", []) or []
                    details = {"updated": updated, "conflicts": len(conflicts)}
                return {
                    "added": added,
                    "skipped": skipped,
                    "unmatched": unmatched,
                    "details": details,
                }
            return {"added": res, "skipped": 0, "unmatched": [], "details": {}}

        def _get_label(kind: str) -> str:
            return {
                "nmap_xml": "Nmap XML",
                "subdomains": "Subdomains",
                "names_emails": "Names & Emails",
                "doc": "OSINT Document",
                "ad_users": "AD Users",
                "name_creds": "Credentials → Users",
                "urls": "Web URLs",
                "names": "Names",
                "mixed_hashes": "Mixed Hashes",
                "bbot": "BBOT",
                "bbot_cloud": "BBOT Cloud",
                "prowl_phase1": "Prowler Phase 1",
                "zone_transfers": "Prowler Phase 2",
                "smtp": "Prowler Phase 3",
                "smb_shares": "SMB Shares",
            }.get(kind, kind)

        def _log_upload(kind: str, label: str, filename: str, norm: dict):
            """Persist upload result to DB."""
            with st.db() as s:
                s.add(UploadLog(
                    kind=kind,
                    label=label,
                    filename=filename,
                    added=norm["added"],
                    skipped=norm["skipped"],
                    failed=len(norm["unmatched"]),
                    unmatched=_fit_json_list(norm["unmatched"], 10000),
                    details=json.dumps(norm.get("details", {}))[:5000],
                ))
                s.commit()

        try:
            if raw_text and raw_text.strip():
                default = {
                    "nmap_xml": "pasted_scan.xml",
                    "subdomains": "pasted_subdomains.txt",
                    "names_emails": "pasted_names_emails.txt",
                    "doc": "pasted_document.bin",
                    "ad_users": "pasted_ad_users.txt",
                    "name_creds": "pasted_name_creds.txt",
                    "urls": "pasted_urls.txt",
                    "names": "pasted_names.txt",
                    "mixed_hashes": "pasted_mixed_hashes.txt",
                    "smb_shares": "pasted_smb_shares.txt",
                }.get(kind, "pasted.txt")
                fname = (
                    raw_filename.strip()
                    if raw_filename and raw_filename.strip()
                    else default
                )
                stored = st.ws.store_text(raw_text, fname, prefix=kind)
                with st.db() as s:
                    art = upsert_artifact(s, kind, Path(stored))
                    raw_result = _import_file(
                        s, art, stored, fname,
                        user_id=smb_user_id if kind == "smb_shares" else None,
                    )
                norm = _normalize_result(raw_result)
                _log_upload(kind, _get_label(kind), fname, norm)
                all_errors = list(norm["unmatched"])
                upload_results = [{
                    "type": kind,
                    "added": norm["added"],
                    "skipped": norm["skipped"],
                    "unmatched": norm["unmatched"],
                    "details": norm.get("details", {}),
                }]
                if kind == "name_creds":
                    upload_results[0]["conflicts"] = raw_result.get("conflicts", [])
                return st.templates.TemplateResponse(
                    "upload.html",
                    _upload_context(
                        request,
                        upload_users,
                        upload_results=upload_results,
                        upload_results_summary={
                            "files": [fname],
                            "redirect": redirect_map.get(kind, "/"),
                            "errors": all_errors,
                        },
                    ),
                )
            elif file:
                files = file if isinstance(file, list) else [file]
                stored_files = []
                fnames = []
                for f in files:
                    if f and f.filename:
                        tmp = st.ws.uploads_dir / f"tmp_{f.filename}"
                        tmp.write_bytes(await f.read())
                        stored = st.ws.store_upload(tmp, prefix=kind)
                        tmp.unlink(missing_ok=True)
                        stored_files.append(stored)
                        fnames.append(f.filename)
                if not stored_files:
                        return st.templates.TemplateResponse(
                        "upload.html",
                        _upload_context(request, upload_users, error="No valid files uploaded."),
                        status_code=400,
                    )
                upload_results = []
                all_errors = []
                with st.db() as s:
                    for i, stored_path in enumerate(stored_files):
                        fname = fnames[i] if i < len(fnames) else "file"
                        art = upsert_artifact(s, kind, Path(stored_path))
                        raw_result = _import_file(
                            s, art, stored_path, fname,
                            user_id=smb_user_id if kind == "smb_shares" else None,
                        )
                        norm = _normalize_result(raw_result)
                        _log_upload(kind, _get_label(kind), fname, norm)
                        all_errors.extend(norm["unmatched"])
                        upload_results.append({
                            "type": kind,
                            "added": norm["added"],
                            "skipped": norm["skipped"],
                            "unmatched": norm["unmatched"],
                            "details": norm.get("details", {}),
                        })
                        if kind == "name_creds":
                            upload_results[-1]["conflicts"] = raw_result.get("conflicts", [])
                return st.templates.TemplateResponse(
                    "upload.html",
                    _upload_context(
                        request,
                        upload_users,
                        upload_results=upload_results,
                        upload_results_summary={
                            "files": fnames,
                            "redirect": redirect_map.get(kind, "/"),
                            "errors": all_errors,
                        },
                    ),
                )
            else:
                return st.templates.TemplateResponse(
                    "upload.html",
                    _upload_context(
                        request,
                        upload_users,
                        error="No file uploaded and no raw text provided.",
                    ),
                    status_code=400,
                )

        except ValueError as e:
            return st.templates.TemplateResponse(
                "upload.html",
                _upload_context(request, upload_users, error=str(e)),
                status_code=400,
            )
        except Exception as e:
            return st.templates.TemplateResponse(
                "upload.html",
                _upload_context(request, upload_users, error=f"Upload failed: {e}"),
                status_code=500,
            )

    @router.get("/api/upload-log")
    def get_upload_log(request: Request):
        def _loads_json(raw, fallback):
            # tolerate rows written by older versions that hard-truncated the JSON
            if not raw:
                return fallback
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return [raw[:2000] + "… (truncated)"] if isinstance(fallback, list) else {}

        with st.db() as s:
            rows = s.execute(select(UploadLog).order_by(UploadLog.created_at.desc()).limit(50)).scalars().all()
        return {
            entry.id: {
                "id": entry.id,
                "kind": entry.kind,
                "label": entry.label,
                "filename": entry.filename,
                "added": entry.added,
                "skipped": entry.skipped,
                "failed": entry.failed,
                "unmatched": _loads_json(entry.unmatched, []),
                "details": _loads_json(entry.details, {}),
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
            }
            for entry in rows
        }

    @router.post("/api/upload-log/clear")
    def clear_upload_log(request: Request):
        with st.db() as s:
            s.execute(UploadLog.__table__.delete())
            s.commit()
        return {"ok": True}

    @router.post("/api/creds-conflict/resolve")
    async def resolve_creds_conflict(request: Request):
        """Resolve a credential username conflict by merging password into existing user or creating new."""
        data = await request.json()
        username = data.get("username", "")
        domain = data.get("domain", "")
        password = data.get("password", "")
        target_user_id = data.get("targetUserId")

        if not username:
            return {"ok": False, "error": "Missing username"}

        with st.db() as s:
            if target_user_id is not None:
                existing = s.get(NameItem, target_user_id)
                if existing:
                    if not existing.password:
                        existing.password = password
                    if domain and not existing.domain:
                        existing.domain = domain
                    s.commit()
                    return {"ok": True}
                return {"ok": False, "error": "Target user not found"}
            else:
                s.add(NameItem(
                    first_name="",
                    middle_name="",
                    last_name="",
                    ad_username=username,
                    domain=domain,
                    password=password,
                ))
                s.commit()
                return {"ok": True}

    # Assets
    return router
