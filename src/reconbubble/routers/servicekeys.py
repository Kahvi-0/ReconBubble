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

    def _service_keys() -> dict:
        """All stored service keys as {service: {field: value}}."""
        try:
            with st.SessionLocal() as s:
                rows = s.query(ServiceApiKey).all()
        except Exception:
            return {}
        out: dict = {}
        for r in rows:
            if r.value:
                out.setdefault(r.service, {})[r.field] = r.value
        return out

    def _tool_keys_for(tool: str) -> dict:
        """Stored service keys mapped to one tool's {source: {field: value}}."""
        return keys_for_tool(tool, _service_keys())

    def _mask_key(value: str) -> str:
        if not value:
            return ""
        if len(value) <= 8:
            return "•" * len(value)
        return value[:4] + "…" + value[-4:]

    @router.get("/api/services/keys")
    def api_service_keys():
        with st.SessionLocal() as s:
            rows = (
                s.query(ServiceApiKey)
                .order_by(ServiceApiKey.service.asc(), ServiceApiKey.field.asc())
                .all()
            )
        return {
            "ok": True,
            "registry": service_key_registry(),
            "keys": [
                {
                    "service": r.service,
                    "field": r.field,
                    "masked": _mask_key(r.value),
                    "created_at": r.created_at.isoformat() if r.created_at else "",
                }
                for r in rows
            ],
        }

    @router.post("/api/services/keys")
    async def api_service_keys_set(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
        service = str(body.get("service") or "").strip()
        field = str(body.get("field") or "key").strip()
        value = str(body.get("value") or "")
        reg = service_key_registry()
        if service not in reg:
            return JSONResponse(
                {"ok": False, "error": f"Unknown service '{service}'"}, status_code=400
            )
        if field not in reg[service]["fields"]:
            return JSONResponse(
                {"ok": False, "error": f"Unknown field '{field}' for {service}"},
                status_code=400,
            )
        if not value:
            return JSONResponse({"ok": False, "error": "value is required"}, status_code=400)
        with st.SessionLocal() as s:
            row = (
                s.query(ServiceApiKey)
                .filter(ServiceApiKey.service == service, ServiceApiKey.field == field)
                .first()
            )
            if row:
                row.value = value
            else:
                s.add(ServiceApiKey(service=service, field=field, value=value))
            s.commit()
        return {"ok": True}

    @router.delete("/api/services/keys/{service}")
    def api_service_keys_delete(service: str):
        # No catalog check: stored services not in the current catalog stay deletable.
        with st.SessionLocal() as s:
            n = (
                s.query(ServiceApiKey)
                .filter(ServiceApiKey.service == service)
                .delete()
            )
            s.commit()
        return {"ok": True, "deleted": n}

    @router.post("/api/services/keys/import")
    async def api_service_keys_import(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
        content = str(body.get("content") or "")
        if not content.strip():
            return JSONResponse({"ok": False, "error": "content is required"}, status_code=400)
        try:
            parsed = parse_tool_config(content)
        except ValueError as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        saved = 0
        with st.SessionLocal() as s:
            for service, fields in parsed["services"].items():
                for field, value in fields.items():
                    row = (
                        s.query(ServiceApiKey)
                        .filter(ServiceApiKey.service == service, ServiceApiKey.field == field)
                        .first()
                    )
                    if row:
                        row.value = value
                    else:
                        s.add(ServiceApiKey(service=service, field=field, value=value))
                    saved += 1
            s.commit()
        return {
            "ok": True,
            "tool": parsed["tool"],
            "saved": saved,
            "services": sorted(parsed["services"].keys()),
            "skipped": parsed["skipped"],
        }

    @router.get("/api/services/keys/config-preview")
    def api_service_keys_config_preview():
        configs = {}
        for tool in ("theharvester", "subfinder"):
            spec = app.state.tools_registry[tool]
            configs[tool] = tool_config_preview(spec, _tool_keys_for(tool))
        return {"ok": True, "configs": configs}

    st._tool_keys_for = _tool_keys_for
    return router
