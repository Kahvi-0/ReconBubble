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

    @router.get("/api/subdomain")
    def api_subdomain(fqdn: str = Query(...)):
        fq = fqdn.strip().lower().rstrip(".")
        try:
            ipaddress.ip_address(fq)
            is_ip = True
        except ValueError:
            is_ip = False
        with st.db() as s:
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs, s_domain_subs_if_ip, s_excluded = (
                scope_sets(s, sensitive_only=True)
            )
            if is_ip:
                ips_found = [fq]
                in_scope = ip_in_scope(fq, ips, subnets, excluded)
                sensitive = ip_in_scope(fq, s_ips, s_subnets, s_excluded)
                hosts = list_hosts_by_ip(s, fq)
                in_scope_ips_found = [fq] if in_scope else []
                ip_ports_map = get_open_web_ports_by_ip(s, ips_found)
                sub_ports: dict[str, list[int]] = {
                    ip: sorted(set(ports)) for ip, ports in ip_ports_map.items()
                }
            else:
                all_ips = list_all_subdomain_ips(s)
                ips_found = all_ips.get(fq, [])
                in_dom = domain_in_scope(
                    fq, domains, domain_all_subs, domain_subs_if_ip, ips_found, ips, subnets, excluded
                )
                in_ip = any(ip_in_scope(ip, ips, subnets, excluded) for ip in ips_found)
                in_scope = bool(in_dom or in_ip)
                sensitive_dom = domain_in_scope(
                    fq,
                    s_domains,
                    s_domain_all_subs,
                    s_domain_subs_if_ip,
                    ips_found,
                    s_ips,
                    s_subnets,
                    s_excluded,
                )
                sensitive_ip = any(ip_in_scope(ip, s_ips, s_subnets, s_excluded) for ip in ips_found)
                sensitive = bool(sensitive_dom or sensitive_ip)
                hosts = list_subdomain_hosts(s, fq)
                ip_ports_map = get_open_web_ports_by_ip(s, ips_found)
                sub_ports = {}
                for ip in ips_found:
                    if ip in ip_ports_map:
                        sub_ports[ip] = sorted(set(ip_ports_map[ip]))
                in_scope_ips_found = [
                    ip for ip in dict.fromkeys(ips_found)
                    if ip_in_scope(ip, ips, subnets, excluded)
                ]
        return {
            "ok": True,
            "fqdn": fq,
            "is_ip": is_ip,
            "ips": ips_found,
            "in_scope": bool(in_scope),
            "in_scope_ips": in_scope_ips_found,
            "sensitive": bool(sensitive),
            "hosts": hosts,
            "ports": sub_ports,
        }

    return router
