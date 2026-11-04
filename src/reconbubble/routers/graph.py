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

    @router.get("/api/graph")
    def api_graph(only_in_scope: bool = Query(False)):
        nodes, edges = [], []
        with st.db() as s:
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs, s_domain_subs_if_ip, s_excluded = (
                scope_sets(s, sensitive_only=True)
            )
            subs = s.execute(select(Subdomain)).scalars().all()
            hosts = s.execute(select(Host)).scalars().all()
            svcs = s.execute(select(Service)).scalars().all()
            host_domains = list_all_host_domains(s)
            subdomain_ips = list_all_subdomain_ips(s)

        def nid(prefix: str, key: str) -> str:
            return f"{prefix}:{key}"

        def add_node(n: dict):
            if only_in_scope and not n.get("in_scope", False):
                return
            nodes.append(n)

        host_dict = {h.id: h for h in hosts}

        domain_nodes = {}
        for sub in subs:
            rd = (sub.root_domain or "").strip(".").lower()
            fq = sub.fqdn
            sub_ips = subdomain_ips.get(fq, [])
            sub_in = domain_in_scope(
                fq, domains, domain_all_subs, domain_subs_if_ip, sub_ips, ips, subnets, excluded
            )
            dom_in = (
                domain_in_scope(
                    rd,
                    domains,
                    domain_all_subs,
                    domain_subs_if_ip,
                    sub_ips,
                    ips,
                    subnets,
                    excluded,
                )
                if rd
                else False
            )
            sub_sensitive = domain_in_scope(
                fq,
                s_domains,
                s_domain_all_subs,
                s_domain_subs_if_ip,
                sub_ips,
                s_ips,
                s_subnets,
                s_excluded,
            )
            dom_sensitive = (
                domain_in_scope(
                    rd,
                    s_domains,
                    s_domain_all_subs,
                    s_domain_subs_if_ip,
                    sub_ips,
                    s_ips,
                    s_subnets,
                    s_excluded,
                )
                if rd
                else False
            )
            if rd and rd not in domain_nodes:
                did = nid("domain", rd)
                domain_nodes[rd] = did
                add_node(
                    {
                        "id": did,
                        "label": rd,
                        "type": "domain",
                        "in_scope": dom_in,
                        "sensitive": dom_sensitive,
                    }
                )
            sid = nid("sub", fq)
            add_node(
                {
                    "id": sid,
                    "label": fq,
                    "type": "subdomain",
                    "in_scope": sub_in,
                    "sensitive": sub_sensitive,
                }
            )
            if rd:
                edges.append({"from": domain_nodes[rd], "to": sid, "type": "has"})

        host_ids = {}
        host_scope = {}
        host_scope_sensitive = {}
        for h in hosts:
            hid = nid("host", h.ip)
            host_ids[h.id] = hid
            hin = ip_in_scope(h.ip, ips, subnets, excluded)
            hs = ip_in_scope(h.ip, s_ips, s_subnets, s_excluded)
            host_scope[h.id] = hin
            host_scope_sensitive[h.id] = hs
            label = h.ip + (("\n" + h.hostname) if h.hostname else "")
            add_node(
                {
                    "id": hid,
                    "label": label,
                    "type": "host",
                    "in_scope": hin,
                    "sensitive": hs,
                    "host_id": h.id,
                }
            )

        for svc in svcs:
            hin = host_scope.get(svc.host_id, False)
            hs = host_scope_sensitive.get(svc.host_id, False)
            sid = nid("svc", f"{svc.host_id}:{svc.port}/{svc.proto}")
            add_node(
                {
                    "id": sid,
                    "label": f"{svc.port}/{svc.proto}\n{svc.service_name or ''}".strip(),
                    "type": "service",
                    "in_scope": hin,
                    "sensitive": hs,
                    "service_id": svc.id,
                }
            )
            edges.append(
                {"from": host_ids.get(svc.host_id, ""), "to": sid, "type": "exposes"}
            )

        existing = {n["id"] for n in nodes}
        for host_id, fqdn_list in host_domains.items():
            host_node = host_ids.get(host_id)
            if not host_node:
                continue
            for fqdn in fqdn_list:
                sub_id = nid("sub", fqdn)
                if sub_id not in existing:
                    fqdn_ips = subdomain_ips.get(fqdn, [])
                    sub_in = domain_in_scope(
                        fqdn,
                        domains,
                        domain_all_subs,
                        domain_subs_if_ip,
                        fqdn_ips,
                        ips,
                        subnets,
                        excluded,
                    )
                    sub_sensitive = domain_in_scope(
                        fqdn,
                        s_domains,
                        s_domain_all_subs,
                        s_domain_subs_if_ip,
                        fqdn_ips,
                        s_ips,
                        s_subnets,
                        s_excluded,
                    )
                    add_node(
                        {
                            "id": sub_id,
                            "label": fqdn,
                            "type": "subdomain",
                            "in_scope": sub_in,
                            "sensitive": sub_sensitive,
                        }
                    )
                    existing.add(sub_id)
                edges.append({"from": sub_id, "to": host_node, "type": "resolves_to"})

        if only_in_scope:
            ids = {n["id"] for n in nodes}
            edges = [e for e in edges if e["from"] in ids and e["to"] in ids]
        return {"nodes": nodes, "edges": edges}

    @router.get("/graph", response_class=HTMLResponse)
    def graph_page(request: Request):
        return st.templates.TemplateResponse("graph.html", {"request": request})

    return router
