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

    # ---- Pages ----
    @router.get("/", response_class=HTMLResponse)
    def home(request: Request):
        with st.db() as s:
            # Get scope sets
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)

            # Get all hosts
            hosts = s.execute(select(Host)).scalars().all()

            # Count hosts in scope
            hosts_in_scope = sum(1 for h in hosts if host_in_scope(
                h.ip or "",
                h.hostname or "",
                ips, subnets, domains, domain_all_subs
            ))
            hosts_total = len(hosts)
            hosts_out_scope = hosts_total - hosts_in_scope

            # Get all services
            services = s.execute(select(Service)).scalars().all()
            services_total = len(services)

            # Count services by port
            services_by_port = {}
            for svc in services:
                port = str(svc.port)
                services_by_port[port] = services_by_port.get(port, 0) + 1

            # Convert to list for template
            services_by_port_list = list(services_by_port.items())

            stats = {
                "hosts_total": hosts_total,
                "hosts_in_scope": hosts_in_scope,
                "hosts_out_scope": hosts_out_scope,
                "services_total": services_total,
                "services_by_port": services_by_port_list,
            }

        return st.templates.TemplateResponse(
            "stats.html", {"request": request, "stats": stats}
        )

    # Stats
    @router.get("/stats", response_class=HTMLResponse)
    def stats_page(request: Request):
        with st.db() as s:
            # Get scope sets
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)

            # Get all hosts
            hosts = s.execute(select(Host)).scalars().all()

            # Count hosts in scope
            hosts_in_scope = sum(1 for h in hosts if host_in_scope(
                h.ip or "",
                h.hostname or "",
                ips, subnets, domains, domain_all_subs
            ))
            hosts_total = len(hosts)
            hosts_out_scope = hosts_total - hosts_in_scope

            # Get all services
            services = s.execute(select(Service)).scalars().all()
            services_total = len(services)

            # Count services by port (only in-scope services)
            services_by_port = {}
            for svc in services:
                # Check if host is in scope
                host = s.get(Host, svc.host_id)
                if host and host_in_scope(
                    host.ip or "",
                    host.hostname or "",
                    ips, subnets, domains, domain_all_subs
                ):
                    port = str(svc.port)
                    services_by_port[port] = services_by_port.get(port, 0) + 1

            # Convert to list for template
            services_by_port_list = list(services_by_port.items())

            stats = {
                "hosts_total": hosts_total,
                "hosts_in_scope": hosts_in_scope,
                "hosts_out_scope": hosts_out_scope,
                "services_total": services_total,
                "services_by_port": services_by_port_list,
            }

        return st.templates.TemplateResponse(
            "stats.html", {"request": request, "stats": stats}
        )

    # Scope
    return router
