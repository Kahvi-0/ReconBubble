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

    @router.get("/tools", response_class=HTMLResponse)
    def tools_page(request: Request):
        data = st.api_tools()
        groups = []
        for key, title in (("subdomain", "Subdomain Enumeration"), ("smb", "SMB Tools")):
            items = [t for t in data["tools"] if t.get("category") == key]
            if items:
                groups.append({"title": title, "tools": items})
        return st.templates.TemplateResponse(
            "tools.html",
            {"request": request, "groups": groups, "bin_dir": data["bin_dir"]},
        )

    @router.get("/subdomains-discovery", response_class=HTMLResponse)
    def subdomains_discovery_page(request: Request):
        data = st.api_tools()
        with st.db() as s:
            (
                ips, subnets, domains, _email_domains,
                domain_all_subs, domain_subs_if_ip, excluded,
            ) = scope_sets(s)
            in_scope_domains = sorted(domains)
            sub_rows = s.execute(
                select(Subdomain.fqdn, Subdomain.root_domain).order_by(
                    Subdomain.root_domain.asc(), Subdomain.fqdn.asc()
                )
            ).all()
            discovered_subdomains = [
                {"fqdn": fqdn, "root": (root or "").strip()}
                for fqdn, root in sub_rows
            ]
            # Out-of-scope root domains whose discovered subdomains resolve to
            # in-scope IPs — candidates for quick add / ignore.
            all_ips_map = list_all_subdomain_ips(s)
            group_ips: dict[str, set[str]] = {}
            for fqdn, root in sub_rows:
                rd = (root or "").strip().lower().strip(".")
                if not rd:
                    continue
                group_ips.setdefault(rd, set()).update(all_ips_map.get(fqdn, []))
            suggested_roots = []
            for rd, gips in sorted(group_ips.items()):
                if rd in excluded:
                    continue
                root_ips = all_ips_map.get(rd, [])
                # A root explicitly listed in scope is in scope even when
                # domain_in_scope() shadows that via the subs-with-in-scope-ip
                # branch (a root with no own resolved IPs would otherwise read
                # as out-of-scope).
                root_in_scope = (rd in domains) or domain_in_scope(
                    rd,
                    domains,
                    domain_all_subs,
                    domain_subs_if_ip,
                    root_ips,
                    ips,
                    subnets,
                    excluded,
                ) or any(
                    ip_in_scope(ip, ips, subnets, excluded) for ip in root_ips
                )
                if root_in_scope:
                    continue
                in_scope_ips = sorted(
                    ip for ip in gips if ip_in_scope(ip, ips, subnets, excluded)
                )
                if not in_scope_ips:
                    continue
                suggested_roots.append({"root": rd, "ips": in_scope_ips})
            exc_rows = s.execute(
                select(ScopeExclusion.fqdn, ScopeExclusion.created_at)
            ).all()
            ignored_roots = [
                {
                    "root": (fq or "").strip().lower().strip("."),
                    "ignored_at": (
                        created_at.strftime("%Y-%m-%d %H:%M:%S")
                        if created_at else ""
                    ),
                }
                for fq, created_at in exc_rows
                if (fq or "").strip().lower().strip(".") in group_ips
            ]
            ignored_roots.sort(key=lambda x: x["root"])
        return st.templates.TemplateResponse(
            "subdomains_discovery.html",
            {
                "request": request,
                "tools": data["tools"],
                "bin_dir": data["bin_dir"],
                "in_scope_domains": in_scope_domains,
                "discovered_subdomains": discovered_subdomains,
                "suggested_roots": suggested_roots,
                "ignored_roots": ignored_roots,
                "ignored_root_names": [r["root"] for r in ignored_roots],
            },
        )

    # Internal
    return router
