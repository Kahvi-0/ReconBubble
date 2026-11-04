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

    @router.get("/cloud", response_class=HTMLResponse)
    def cloud(request: Request):
        with st.db() as s:
            rows = (
                s.execute(select(CloudItem).order_by(CloudItem.created_at.desc()))
                .scalars()
                .all()
            )
            out = []
            for r in rows:
                data = {}
                try:
                    data = json.loads(r.data_json) if r.data_json else {}
                except Exception:
                    data = {}
                out.append(
                    {
                        "id": r.id,
                        "provider": r.provider,
                        "name": r.name,
                        "notes": r.notes or "",
                        "data": data,
                        "created_at": r.created_at,
                    }
                )
        return st.templates.TemplateResponse(
            "cloud.html", {"request": request, "rows": out}
        )

    @router.post("/api/cloud/create")
    def api_cloud_create(
        provider: str = Form(...),
        name: str = Form(""),
        notes: str = Form(""),
        tenant_id: str = Form(""),
        account_id: str = Form(""),
        primary_domain: str = Form(""),
        regions: str = Form(""),
        subscriptions: str = Form(""),
        buckets: str = Form(""),
        projects: str = Form(""),
        app_ids: str = Form(""),
    ):
        provider = (provider or "").strip()
        name = (name or "").strip()
        notes = notes or ""
        data = {}
        # Provider-specific fields (best-effort defaults)
        if provider.lower() in ("aws",):
            data = {
                "account_id": account_id.strip(),
                "regions": _split_lines(regions),
                "buckets": _split_lines(buckets),
            }
        elif provider.lower() in ("azure",):
            data = {
                "tenant_id": tenant_id.strip(),
                "subscriptions": _split_lines(subscriptions),
                "regions": _split_lines(regions),
            }
        elif provider.lower() in ("digital ocean", "digitalocean", "do"):
            data = {
                "projects": _split_lines(projects),
                "spaces": _split_lines(buckets),
                "regions": _split_lines(regions),
            }
            provider = "Digital Ocean"
        elif provider.lower() in ("o365", "office365", "office 365"):
            data = {
                "tenant_id": tenant_id.strip(),
                "primary_domain": primary_domain.strip(),
                "email_domains": _split_lines(subscriptions),
            }
            provider = "O365"
        else:  # Microsoft (generic)
            data = {
                "tenant_id": tenant_id.strip(),
                "primary_domain": primary_domain.strip(),
                "app_ids": _split_lines(app_ids),
                "domains": _split_lines(subscriptions),
            }
            provider = "Microsoft"

        with st.db() as s:
            item = CloudItem(
                provider=provider[:64],
                name=name[:255],
                notes=notes,
                data_json=json.dumps(data, ensure_ascii=False),
            )
            s.add(item)
            s.commit()
            return {"ok": True, "id": item.id}

    @router.get("/api/cloud/{cloud_id}")
    def api_cloud_get(cloud_id: int):
        with st.db() as s:
            item = s.scalar(select(CloudItem).where(CloudItem.id == cloud_id))
            if not item:
                return JSONResponse({"ok": False}, status_code=404)
            try:
                data = json.loads(item.data_json) if item.data_json else {}
            except Exception:
                data = {}
            return {
                "ok": True,
                "id": item.id,
                "provider": item.provider,
                "name": item.name,
                "notes": item.notes or "",
                "data": data,
                "created_at": item.created_at.isoformat() if item.created_at else "",
            }

    @router.post("/api/cloud/update")
    def api_cloud_update(
        cloud_id: int = Form(...),
        provider: str = Form(...),
        name: str = Form(""),
        notes: str = Form(""),
        tenant_id: str = Form(""),
        account_id: str = Form(""),
        primary_domain: str = Form(""),
        regions: str = Form(""),
        subscriptions: str = Form(""),
        buckets: str = Form(""),
        projects: str = Form(""),
        app_ids: str = Form(""),
    ):
        with st.db() as s:
            item = s.scalar(select(CloudItem).where(CloudItem.id == cloud_id))
            if not item:
                return JSONResponse({"ok": False}, status_code=404)

            provider = (provider or "").strip()
            name = (name or "").strip()
            notes = notes or ""

            data = {}
            if provider.lower() in ("aws",):
                data = {
                    "account_id": account_id.strip(),
                    "regions": _split_lines(regions),
                    "buckets": _split_lines(buckets),
                }
                provider = "AWS"
            elif provider.lower() in ("azure",):
                data = {
                    "tenant_id": tenant_id.strip(),
                    "subscriptions": _split_lines(subscriptions),
                    "regions": _split_lines(regions),
                }
                provider = "Azure"
            elif provider.lower() in ("digital ocean", "digitalocean", "do"):
                data = {
                    "projects": _split_lines(projects),
                    "spaces": _split_lines(buckets),
                    "regions": _split_lines(regions),
                }
                provider = "Digital Ocean"
            elif provider.lower() in ("o365", "office365", "office 365"):
                data = {
                    "tenant_id": tenant_id.strip(),
                    "primary_domain": primary_domain.strip(),
                    "email_domains": _split_lines(subscriptions),
                }
                provider = "O365"
            else:
                data = {
                    "tenant_id": tenant_id.strip(),
                    "primary_domain": primary_domain.strip(),
                    "app_ids": _split_lines(app_ids),
                    "domains": _split_lines(subscriptions),
                }
                provider = "Microsoft"

            item.provider = provider[:64]
            item.name = name[:255]
            item.notes = notes
            item.data_json = json.dumps(data, ensure_ascii=False)
            s.commit()
        return {"ok": True}

    @router.post("/api/cloud/delete")
    def api_cloud_delete(cloud_id: int = Form(...)):
        with st.db() as s:
            item = s.scalar(select(CloudItem).where(CloudItem.id == cloud_id))
            if not item:
                return JSONResponse({"ok": False}, status_code=404)
            s.delete(item)
            s.commit()
        return {"ok": True}

    # Profiling page
    return router
