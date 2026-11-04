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

    @router.get("/api/password-spray/services")
    def api_password_spray_services_list():
        with st.db() as s:
            services = (
                s.execute(
                    select(PasswordSprayService).order_by(PasswordSprayService.name.asc())
                )
                .scalars()
                .all()
            )
            result = []
            for svc in services:
                attempts = (
                    s.execute(
                        select(PasswordSprayAttempt)
                        .where(PasswordSprayAttempt.service_id == svc.id)
                        .order_by(PasswordSprayAttempt.created_at.asc())
                    )
                    .scalars()
                    .all()
                )
                result.append({
                    "id": svc.id,
                    "name": svc.name,
                    "attempts": [
                        {
                            "id": a.id,
                            "password": a.password or "",
                            "attempted_at": a.attempted_at or "",
                            "notes": a.notes or "",
                        }
                        for a in attempts
                    ],
                })
        return {"ok": True, "services": result}

    @router.post("/api/password-spray/service")
    def api_password_spray_service_create(name: str = Form("")):
        name = (name or "").strip()
        if not name:
            return JSONResponse({"ok": False, "error": "Service name is required"}, status_code=400)
        with st.db() as s:
            existing = s.scalar(select(PasswordSprayService).where(PasswordSprayService.name == name))
            if existing:
                return {"ok": True, "id": existing.id, "name": existing.name}
            svc = PasswordSprayService(name=name[:255])
            s.add(svc)
            s.commit()
            s.refresh(svc)
            return {"ok": True, "id": svc.id, "name": svc.name}

    @router.post("/api/password-spray/attempt")
    def api_password_spray_attempt_create(
        service_id: int = Form(...),
        password: str = Form(""),
        attempted_at: str = Form(""),
        notes: str = Form(""),
    ):
        pwd = (password or "").strip()
        at = (attempted_at or "").strip()
        note = (notes or "").strip()
        if not pwd and not at and not note:
            return JSONResponse({"ok": False, "error": "No attempt data provided"}, status_code=400)
        with st.db() as s:
            svc = s.scalar(select(PasswordSprayService).where(PasswordSprayService.id == int(service_id)))
            if not svc:
                return JSONResponse({"ok": False, "error": "Service not found"}, status_code=404)
            row = PasswordSprayAttempt(
                service_id=svc.id,
                password=pwd[:255],
                attempted_at=at[:64],
                notes=note,
            )
            s.add(row)
            s.commit()
            s.refresh(row)
            return {
                "ok": True,
                "id": row.id,
                "service_id": svc.id,
                "password": row.password,
                "attempted_at": row.attempted_at,
                "notes": row.notes,
            }

    @router.post("/api/password-spray/attempt/{attempt_id}")
    def api_password_spray_attempt_update(
        attempt_id: int,
        password: str = Form(""),
        attempted_at: str = Form(""),
        notes: str = Form(""),
    ):
        pwd = (password or "").strip()
        at = (attempted_at or "").strip()
        note = (notes or "").strip()
        with st.db() as s:
            row = s.scalar(
                select(PasswordSprayAttempt).where(PasswordSprayAttempt.id == attempt_id)
            )
            if not row:
                return JSONResponse(
                    {"ok": False, "error": "Attempt not found"}, status_code=404
                )
            row.password = pwd[:255]
            row.attempted_at = at[:64]
            row.notes = note
            s.commit()
            return {
                "ok": True,
                "id": row.id,
                "password": row.password,
                "attempted_at": row.attempted_at,
                "notes": row.notes,
            }

    @router.delete("/api/password-spray/attempt/{attempt_id}")
    def api_password_spray_attempt_delete(attempt_id: int):
        with st.db() as s:
            row = s.scalar(
                select(PasswordSprayAttempt).where(PasswordSprayAttempt.id == attempt_id)
            )
            if not row:
                return JSONResponse(
                    {"ok": False, "error": "Attempt not found"}, status_code=404
                )
            s.delete(row)
            s.commit()
            return {"ok": True}

    return router
