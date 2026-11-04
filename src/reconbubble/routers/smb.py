from __future__ import annotations
from pathlib import Path
import asyncio, json, ipaddress, os, re, shlex, socket, ssl, sys, tempfile, uuid
import html as html_lib
from urllib.parse import quote_plus, parse_qsl, urlencode, urlsplit
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import APIRouter, Request, UploadFile, File, Form, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse, StreamingResponse

from sqlalchemy import select, func, text, or_
from sqlalchemy.orm import Session

from .. import netproxy
from .. import nsecatalog
from .. import smbbrowse
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

    @router.get("/smb-shares", response_class=HTMLResponse)
    def smb_shares_page(request: Request):
        with st.db() as s:
            shares = s.execute(
                select(SmbShare).order_by(SmbShare.host, SmbShare.share)
            ).scalars().all()
            all_users = (
                s.execute(
                    select(NameItem).order_by(
                        NameItem.last_name.asc(), NameItem.first_name.asc()
                    )
                )
                .scalars()
                .all()
            )
            access_user_ids = {
                sh.user_id for sh in shares if sh.user_id is not None
            }
            access_users = [u for u in all_users if u.id in access_user_ids]
            # Only users who can actually authenticate (stored password or
            # NTLM hash) are offered in the add/edit share dropdown.
            cred_users = [
                u
                for u in all_users
                if (u.password or "").strip() or (u.ntlm_hash or "").strip()
            ]
            user_map = {u.id: u for u in all_users}
            hosts_map: dict[str, list[dict]] = {}
            has_unassigned = False
            for sh in shares:
                if sh.user_id is None:
                    has_unassigned = True
                host_groups = hosts_map.setdefault(sh.host, {})
                group = host_groups.get(sh.share)
                if group is None:
                    group = {"share": sh.share, "by_user": {}, "unassigned": None}
                    host_groups[sh.share] = group
                if sh.user_id is None:
                    group["unassigned"] = sh
                else:
                    group["by_user"][sh.user_id] = sh
            hosts_list = [
                {
                    "host": host,
                    "groups": list(groups.values()),
                    "share_count": len(groups),
                }
                for host, groups in hosts_map.items()
            ]
            hosts_list.sort(key=lambda item: item["host"].lower())
            for item in hosts_list:
                item["groups"].sort(key=lambda g: g["share"].lower())
        return st.templates.TemplateResponse(
            "smb_shares.html",
            {
                "request": request,
                "shares": shares,
                "hosts_list": hosts_list,
                "column_users": access_users,
                "all_users": all_users,
                "cred_users": cred_users,
                "user_map": user_map,
                "has_unassigned": has_unassigned,
                "user_label": _smb_user_label,
            },
        )

    @router.post("/api/smb-shares/create", response_class=JSONResponse)
    def smb_shares_create(host: str = Form(""), shares: str = Form(""), user_id: list[int] = Form([])):
        """Create share rows; one row per selected user.

        ``user_id`` is a repeated form field so a share can be associated
        with several users at once (each user authenticates with their own
        stored password or NTLM hash).  Existing (host, share, user) rows
        are skipped, so re-adding a user to a known share is a no-op.
        """
        host = host.strip()
        if not host:
            return {"ok": False, "error": "Host is required."}
        lines = [l.strip() for l in shares.strip().split("\n") if l.strip()]
        if not lines:
            return {"ok": False, "error": "At least one share entry is required."}
        user_ids = []
        for uid in user_id:
            if uid > 0 and uid not in user_ids:
                user_ids.append(uid)
        if not user_ids:
            return {"ok": False, "error": "Select at least one user."}
        added = 0
        skipped = 0
        errors = []
        with st.db() as s:
            for uid in user_ids:
                if s.get(NameItem, uid) is None:
                    return {"ok": False, "error": "Selected user not found."}
            for idx, line in enumerate(lines, 1):
                parts = line.split(",")
                if len(parts) < 1:
                    errors.append(f"Row {idx}: empty line")
                    continue
                share_name = parts[0].strip()
                access_val = parts[1].strip().upper() if len(parts) > 1 else "NO_ACCESS"
                note_val = ", ".join(p.strip() for p in parts[2:]).strip() if len(parts) > 2 else ""
                if not share_name:
                    errors.append(f"Row {idx}: share name is empty")
                    continue
                for uid in user_ids:
                    existing = s.scalar(
                        select(SmbShare).where(
                            SmbShare.host == host,
                            SmbShare.share == share_name,
                            SmbShare.user_id == uid,
                        )
                    )
                    if existing:
                        skipped += 1
                        continue
                    s.add(SmbShare(host=host, share=share_name, access=access_val, notes=note_val, user_id=uid))
                    added += 1
            s.commit()
        return {"ok": True, "added": added, "skipped": skipped, "errors": errors}

    @router.post("/api/smb-shares/create-one", response_class=JSONResponse)
    def smb_shares_create_one(host: str = Form(""), share: str = Form(""), access: str = Form(""), notes: str = Form(""), user_id: int = Form(0)):
        host = host.strip()
        share = share.strip()
        access = access.strip().upper()
        notes = notes.strip()
        if not host or not share:
            return {"ok": False, "error": "Host and share are required."}
        if user_id <= 0:
            return {"ok": False, "error": "User is required."}
        with st.db() as s:
            if s.get(NameItem, user_id) is None:
                return {"ok": False, "error": "Selected user not found."}
            existing = s.scalar(
                select(SmbShare).where(
                    SmbShare.host == host,
                    SmbShare.share == share,
                    SmbShare.user_id == user_id,
                )
            )
            if existing:
                return {"ok": False, "error": "This share entry already exists."}
            s.add(SmbShare(host=host, share=share, access=access, notes=notes, user_id=user_id))
            s.commit()
        return {"ok": True}

    @router.post("/api/smb-shares/update", response_class=JSONResponse)
    def smb_shares_update(
        share_id: int = Form(0),
        host: str = Form(""),
        share: str = Form(""),
        access: str = Form(""),
        notes: str = Form(""),
        user_id: list[int] = Form([]),
    ):
        """Edit a share; the multi-select defines which users may authenticate.

        The edited (anchor) row takes the form's access/notes.  Newly
        selected users get a row with the same access/notes; users who
        already have a row for this share keep their own access (per-user
        privileges are preserved).  Rows for deselected users are removed.
        """
        if not share_id:
            return {"ok": False, "error": "share_id is required."}
        share = share.strip()
        access = access.strip().upper()
        notes = notes.strip()
        if not share or not access:
            return {"ok": False, "error": "Share and access are required."}
        user_ids = []
        for uid in user_id:
            if uid > 0 and uid not in user_ids:
                user_ids.append(uid)
        if not user_ids:
            return {"ok": False, "error": "Select at least one user."}
        with st.db() as s:
            target = s.get(SmbShare, share_id)
            if not target:
                return {"ok": False, "error": "Not found."}
            for uid in user_ids:
                if s.get(NameItem, uid) is None:
                    return {"ok": False, "error": "Selected user not found."}
            host = target.host  # host is fixed in edit mode (input disabled)
            group = s.execute(
                select(SmbShare).where(
                    SmbShare.host == host,
                    SmbShare.share == target.share,
                )
            ).scalars().all()
            selected = set(user_ids)
            # The anchor row keeps its own user while that user is still
            # selected; otherwise it is reassigned to the first selected
            # user without a row for this share (fallback: first selected).
            anchor_user = target.user_id if target.user_id in selected else None
            if anchor_user is None:
                taken = {
                    r.user_id for r in group
                    if r.id != target.id and r.user_id is not None
                }
                for uid in user_ids:
                    if uid not in taken:
                        anchor_user = uid
                        break
            if anchor_user is None:
                anchor_user = user_ids[0]
            target.share = share
            target.access = access
            target.notes = notes
            target.user_id = anchor_user
            for uid in user_ids:
                if uid == anchor_user:
                    continue
                existing = next(
                    (r for r in group if r.id != target.id and r.user_id == uid),
                    None,
                )
                if existing is None:
                    s.add(SmbShare(host=host, share=share, access=access, notes=notes, user_id=uid))
            # Drop rows the multi-select no longer covers; if a non-anchor
            # row now shares the anchor's user (merge case), the anchor wins.
            for r in group:
                if r.id == target.id:
                    continue
                if r.user_id == anchor_user or r.user_id not in selected:
                    s.delete(r)
            s.commit()
        return {"ok": True}

    @router.post("/api/smb-shares/delete", response_class=JSONResponse)
    def smb_shares_delete(share_id: int = Form(0)):
        if not share_id:
            return {"ok": False, "error": "share_id is required."}
        with st.db() as s:
            target = s.get(SmbShare, share_id)
            if not target:
                return {"ok": False, "error": "Not found."}
            s.delete(target)
            s.commit()
        return {"ok": True}

    @router.get("/api/smb-shares/list", response_class=JSONResponse)
    def smb_shares_list():
        with st.db() as s:
            shares = s.execute(
                select(SmbShare).order_by(SmbShare.host, SmbShare.share)
            ).scalars().all()
            user_ids = {sh.user_id for sh in shares if sh.user_id is not None}
            users = {}
            if user_ids:
                users = {
                    u.id: _smb_user_label(u)
                    for u in s.execute(
                        select(NameItem).where(NameItem.id.in_(user_ids))
                    ).scalars().all()
                }
            hosts_map: dict[str, list[dict]] = {}
            for sh in shares:
                hosts_map.setdefault(sh.host, []).append({
                    "id": sh.id,
                    "share": sh.share,
                    "access": sh.access,
                    "notes": sh.notes,
                    "user_id": sh.user_id,
                    "user": users.get(sh.user_id, "") if sh.user_id is not None else "",
                })
        return {"hosts": hosts_map, "total": len(shares)}

    # ------------------------------------------------------------------
    # Share browser (live SMB navigation)
    # ------------------------------------------------------------------
    # Both endpoints are plain sync defs on purpose: smbbrowse is built on
    # the blocking smbprotocol client and FastAPI runs these in its thread
    # pool. Errors follow the page convention: plain dict + HTTP 200.

    def _browse_timeout(raw) -> float:
        try:
            val = float(raw)
        except (TypeError, ValueError):
            val = 10.0
        return max(1.0, min(60.0, val))

    def _resolve_creds(user_id: int):
        """Look up stored credentials by name-item id (0 = anonymous).

        The browser only ever sends the id; usernames, passwords, NTLM
        hashes and domains are read from the database here so secrets
        never travel over HTTP or sit in the page markup.  Returns
        ``(username, password, ntlm_hash, domain)``.
        """
        uid = int(user_id or 0)
        if uid <= 0:
            return "", "", "", ""
        with st.db() as s:
            u = s.get(NameItem, uid)
        if u is None:
            raise smbbrowse.SmbBrowseError(
                "no_user",
                "The assigned user no longer exists in the names list.",
            )
        return (
            u.ad_username or "",
            u.password or "",
            u.ntlm_hash or "",
            u.domain or "",
        )

    @router.post("/api/smb/browse", response_class=JSONResponse)
    def smb_browse(
        host: str = Form(""),
        share: str = Form(""),
        path: str = Form(""),
        user_id: int = Form(0),
        timeout: float = Form(10),
        port: str = Form("445"),
    ):
        try:
            username, password, ntlm_hash, domain = _resolve_creds(user_id)
            entries = smbbrowse.list_share(
                host, share, path, username, password, _browse_timeout(timeout),
                domain=domain, port=port, ntlm_hash=ntlm_hash,
            )
        except smbbrowse.SmbBrowseError as exc:
            return {"ok": False, "error": exc.message, "code": exc.code}
        except Exception as exc:
            return {"ok": False, "error": f"Unexpected browse error: {exc}", "code": "smb_error"}
        return {
            "ok": True,
            "entries": [
                {
                    "name": e.name,
                    "is_dir": e.is_dir,
                    "size": e.size,
                    "mtime": (e.mtime.isoformat() + "Z") if e.mtime else None,
                }
                for e in entries
            ],
        }

    @router.get("/api/smb/download")
    def smb_download(
        host: str = Query(""),
        share: str = Query(""),
        path: str = Query(""),
        file: str = Query(""),
        user_id: int = Query(0),
        timeout: float = Query(10),
        port: str = Query("445"),
    ):
        try:
            username, password, ntlm_hash, domain = _resolve_creds(user_id)
            handle = smbbrowse.open_file_for_read(
                host, share, path, file, username, password, _browse_timeout(timeout),
                domain=domain, port=port, ntlm_hash=ntlm_hash,
            )
        except smbbrowse.SmbBrowseError as exc:
            return JSONResponse({"ok": False, "error": exc.message, "code": exc.code})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"Unexpected download error: {exc}", "code": "smb_error"})

        safe_name = "".join(
            c if (c.isascii() and c not in '\r\n"\\') else "_" for c in handle.name
        )

        def stream():
            try:
                yield from handle.iter_chunks()
            finally:
                handle.close()

        return StreamingResponse(
            stream(),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
        )

    _IMAGE_MEDIA = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "webp": "image/webp",
        "bmp": "image/bmp",
        "ico": "image/x-icon",
        "svg": "image/svg+xml",
    }

    @router.get("/api/smb/preview")
    def smb_preview(
        host: str = Query(""),
        share: str = Query(""),
        path: str = Query(""),
        file: str = Query(""),
        user_id: int = Query(0),
        timeout: float = Query(10),
        port: str = Query("445"),
        size: int = Query(0),
    ):
        """Stream a file for inline preview (text/image), served from the
        local cache when its stored size matches the listed ``size``."""
        try:
            username, password, ntlm_hash, domain = _resolve_creds(user_id)
            preview = smbbrowse.preview_file(
                host, share, path, file, username, password, _browse_timeout(timeout),
                domain=domain, port=port, ntlm_hash=ntlm_hash,
                expected_size=(size if size > 0 else None),
                cache_dir=st.ws.preview_cache_dir,
            )
        except smbbrowse.SmbBrowseError as exc:
            return JSONResponse({"ok": False, "error": exc.message, "code": exc.code})
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"Unexpected preview error: {exc}", "code": "smb_error"})

        if preview.kind == "text":
            media = "text/plain; charset=utf-8"
        elif preview.kind == "image":
            ext = file.rsplit(".", 1)[-1].lower() if "." in file else ""
            media = _IMAGE_MEDIA.get(ext, "image/octet-stream")
        else:
            media = "application/octet-stream"

        def stream():
            try:
                yield from preview.iter_chunks()
            finally:
                preview.close()

        return StreamingResponse(
            stream(),
            media_type=media,
            headers={
                "X-Preview-Kind": preview.kind,
                "X-Preview-Cache": "hit" if preview.from_cache else "miss",
                "Cache-Control": "no-store",
            },
        )

    return router
