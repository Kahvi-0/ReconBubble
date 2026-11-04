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

    @router.get("/scope", response_class=HTMLResponse)
    def scope_page(request: Request):
        scope_error = (request.query_params.get("error") or "").strip()
        with st.db() as s:
            domains = (
                s.execute(
                    select(ScopeItem)
                    .where(ScopeItem.kind == "domain")
                    .order_by(ScopeItem.value.asc())
                )
                .scalars()
                .all()
            )
            ip_items = (
                s.execute(
                    select(ScopeItem)
                    .where(ScopeItem.kind.in_(["ip", "subnet"]))
                    .order_by(ScopeItem.kind.asc(), ScopeItem.value.asc())
                )
                .scalars()
                .all()
            )
            email_items = (
                s.execute(
                    select(ScopeItem)
                    .where(ScopeItem.kind == "email_domain")
                    .order_by(ScopeItem.value.asc())
                )
                .scalars()
                .all()
            )
            exclusions = (
                s.execute(
                    select(ScopeExclusion).order_by(ScopeExclusion.created_at.desc())
                )
                .scalars()
                .all()
            )

        return st.templates.TemplateResponse(
            "scope.html",
            {
                "request": request,
                "domains": domains,
                "ip_items": ip_items,
                "email_items": email_items,
                "scope_error": scope_error,
                "exclusions": exclusions,
            },
        )

    @router.post("/scope/add")
    def scope_add(
        kind: str = Form(...),
        value: str = Form(""),
        values_raw: str = Form(""),
        note: str = Form(""),
        apply_all_subdomains: int = Form(0),
        apply_subdomains_with_in_scope_ip: int = Form(0),
        sensitive: int = Form(0),
    ):
        items: list[str] = []
        if values_raw and values_raw.strip():
            items = [
                ln.strip()
                for ln in values_raw.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
        elif value and value.strip():
            items = [value.strip()]
        if not items:
            return RedirectResponse(url="/scope", status_code=303)

        if kind == "ip_or_subnet":
            invalid_items: list[str] = []
            normalized_items: list[str] = []
            for raw_item in items:
                raw_item = raw_item.strip()
                if "/" in raw_item:
                    try:
                        normalized_items.append(
                            str(ipaddress.ip_network(raw_item, strict=False))
                        )
                    except ValueError:
                        invalid_items.append(raw_item)
                else:
                    try:
                        normalized_items.append(str(ipaddress.ip_address(raw_item)))
                    except ValueError:
                        invalid_items.append(raw_item)

            if invalid_items:
                err = "Invalid IP/subnet format: " + ", ".join(invalid_items)
                return RedirectResponse(
                    url=f"/scope?error={quote_plus(err)}", status_code=303
                )
            items = normalized_items

        with st.db() as s:
            for v in items:
                v2 = v.strip()
                if kind == "ip_or_subnet":
                    actual_kind = "subnet" if "/" in v2 else "ip"
                else:
                    actual_kind = kind

                it = ScopeItem(
                    kind=actual_kind,
                    value=v2,
                    note=(note or "").strip(),
                    in_scope=1,
                    apply_all_subdomains=1
                    if (actual_kind == "domain" and apply_all_subdomains == 1)
                    else 0,
                    apply_subdomains_with_in_scope_ip=1
                    if (
                        actual_kind == "domain"
                        and apply_subdomains_with_in_scope_ip == 1
                    )
                    else 0,
                    sensitive=1 if sensitive == 1 else 0,
                )
                s.add(it)
                try:
                    s.commit()
                except Exception:
                    s.rollback()
        return RedirectResponse(url="/scope", status_code=303)

    @router.post("/scope/toggle")
    def scope_toggle(item_id: int = Form(...)):
        with st.db() as s:
            it = s.scalar(select(ScopeItem).where(ScopeItem.id == item_id))
            if it:
                it.in_scope = 0 if it.in_scope == 1 else 1
                s.commit()
        return RedirectResponse(url="/scope", status_code=303)

    @router.post("/scope/sensitive")
    def scope_sensitive(item_id: int = Form(...)):
        with st.db() as s:
            it = s.scalar(select(ScopeItem).where(ScopeItem.id == item_id))
            if it:
                it.sensitive = 0 if getattr(it, "sensitive", 0) == 1 else 1
                s.commit()
        return RedirectResponse(url="/scope", status_code=303)

    @router.post("/scope/delete")
    def scope_delete(item_id: int = Form(...)):
        with st.db() as s:
            it = s.scalar(select(ScopeItem).where(ScopeItem.id == item_id))
            if it:
                s.delete(it)
                s.commit()
        return RedirectResponse(url="/scope", status_code=303)

    @router.post("/scope/delete-checked")
    def scope_delete_checked(item_ids: list[int] = Form([])):
        ids = [int(x) for x in (item_ids or []) if int(x) > 0]
        if not ids:
            return RedirectResponse(url="/scope", status_code=303)
        with st.db() as s:
            rows = (
                s.execute(select(ScopeItem).where(ScopeItem.id.in_(ids)))
                .scalars()
                .all()
            )
            for it in rows:
                s.delete(it)
            s.commit()
        return RedirectResponse(url="/scope", status_code=303)

    # Upload
    return router
