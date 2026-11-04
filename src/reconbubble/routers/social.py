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

    @router.get("/social", response_class=HTMLResponse)
    def social_page(request: Request):
        with st.db() as s:
            rows = (
                s.execute(
                    select(SocialMedia).order_by(
                        SocialMedia.platform.asc(), SocialMedia.handle.asc()
                    )
                )
                .scalars()
                .all()
            )
        return st.templates.TemplateResponse(
            "social.html", {"request": request, "rows": rows}
        )

    @router.post("/api/social/create")
    async def api_social_create(
        request: Request,
        platform: str = Form(...),
        handle: str = Form(""),
        url: str = Form(""),
        notes: str = Form(""),
        screenshot: list[UploadFile] | None = File(None),
    ):
        artifact_ids = []
        if screenshot:
            for ss in screenshot:
                if ss and ss.filename:
                    tmp = st.ws.uploads_dir / f"tmp_{ss.filename}"
                    tmp.write_bytes(await ss.read())
                    stored = st.ws.store_upload(tmp, prefix="screenshot")
                    tmp.unlink(missing_ok=True)
                    with st.db() as s:
                        art = upsert_artifact(s, "screenshot", stored)
                        artifact_ids.append(art.id)

        artifact_id = artifact_ids[0] if artifact_ids else None

        with st.db() as s:
            item = SocialMedia(
                platform=platform[:64],
                handle=handle[:255],
                url=url[:512],
                notes=notes,
                artifact_id=artifact_id,
            )
            s.add(item)
            s.flush()
            s.commit()
            item_id = item.id
        return {"ok": True, "id": item_id}

    @router.post("/api/social/delete")
    def api_social_delete(social_id: int = Form(...)):
        with st.db() as s:
            item = s.scalar(select(SocialMedia).where(SocialMedia.id == social_id))
            if item:
                s.delete(item)
                s.commit()
        return {"ok": True}

    # Artifact serving
    return router
