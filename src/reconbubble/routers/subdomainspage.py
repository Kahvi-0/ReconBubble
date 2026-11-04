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

    @router.get("/subdomains", response_class=HTMLResponse)
    def subdomains(request: Request):
        show_out = int(request.query_params.get("show_out", "0"))
        with st.db() as s:
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs, s_domain_subs_if_ip, s_excluded = (
                scope_sets(s, sensitive_only=True)
            )
            rows = (
                s.execute(
                    select(Subdomain).order_by(
                        Subdomain.root_domain.asc(), Subdomain.fqdn.asc()
                    )
                )
                .scalars()
                .all()
            )
            # Get all RDAP info
            rdap_info = {}
            for di in s.execute(select(DomainInfo)).scalars().all():
                rdap_info[di.domain] = {
                    "registrar": di.registrar,
                    "registrarEmail": di.registrar_email or "",
                    "registrarOrg": di.registrar_org or "",
                    "creationDate": di.creation_date or "",
                    "creation_date": di.creation_date or "",
                    "expirationDate": di.expiration_date or "",
                    "expiration_date": di.expiration_date or "",
                    "updatedDate": di.updated_date or "",
                    "nameServers": di.name_servers.split(", ")
                    if di.name_servers
                    else [],
                    "name_servers": di.name_servers or "",
                    "status": di.status or "",
                    "dnssec": di.dnssec or "",
                    "registrant": di.registrant or "",
                    "registrantEmail": di.registrant_email or "",
                    "adminContact": di.admin_contact or "",
                    "adminEmail": di.admin_email or "",
                    "techContact": di.tech_contact or "",
                    "techEmail": di.tech_email or "",
                    "error": di.rdap_error or "",
                }
            out = []
            all_ips_map = list_all_subdomain_ips(s)
            
            # Collect all IPs across subdomains for bulk service query
            all_sub_ips = set()
            for x in rows:
                ips_found = all_ips_map.get(x.fqdn, [])
                prowl_ips_list = (x.prowl_ips or "").split(",")
                prowl_ips_cleaned = [ip.strip() for ip in prowl_ips_list if ip.strip()]
                for ip in ips_found:
                    all_sub_ips.add(ip)
                for ip in prowl_ips_cleaned:
                    all_sub_ips.add(ip)

            ip_ports_map = get_open_web_ports_by_ip(s, all_sub_ips)

            root_domains = {}
            for x in rows:
                ips_found = all_ips_map.get(x.fqdn, [])
                prowl_ips_list = (x.prowl_ips or "").split(",")
                prowl_ips_cleaned = [ip.strip() for ip in prowl_ips_list if ip.strip()]
                all_ips = list(set(ips_found) | set(prowl_ips_cleaned))
                in_dom = domain_in_scope(
                    x.fqdn,
                    domains,
                    domain_all_subs,
                    domain_subs_if_ip,
                    ips_found,
                    ips,
                    subnets,
                    excluded,
                )
                sensitive_dom = domain_in_scope(
                    x.fqdn,
                    s_domains,
                    s_domain_all_subs,
                    s_domain_subs_if_ip,
                    ips_found,
                    s_ips,
                    s_subnets,
                    s_excluded,
                )
                sensitive_ip_set = {
                    ip for ip in all_ips if ip_in_scope(ip, s_ips, s_subnets, s_excluded)
                }
                in_scope_ip_set = {
                    ip for ip in all_ips if ip_in_scope(ip, ips, subnets, excluded)
                }
                in_scope = bool(in_dom or in_scope_ip_set)
                sensitive = bool(sensitive_dom or bool(sensitive_ip_set))
                # Get RDAP info for root domain
                rdap = rdap_info.get(x.root_domain, {}) if x.root_domain else {}
                # Get Prowler info for this subdomain
                prowl = {}
                if x.prowl_ips or x.prowl_registrar or x.prowl_netblocks:
                    prowl = {
                        "ips": x.prowl_ips,
                        "registrar": x.prowl_registrar,
                        "netblocks": x.prowl_netblocks,
                    }
                # Build ports map for this subdomain's IPs
                sub_ports: dict[str, list[int]] = {}
                for ip in all_ips:
                    if ip in ip_ports_map:
                        sub_ports[ip] = sorted(set(ip_ports_map[ip]))

                port_info: dict[int, dict[str, set[str]]] = {}
                for ip in all_ips:
                    for port in sub_ports.get(ip, []):
                        info = port_info.setdefault(port, {"ips": set(), "in_scope_ips": set()})
                        info["ips"].add(ip)
                        if ip in in_scope_ip_set:
                            info["in_scope_ips"].add(ip)
                port_chips = [
                    {
                        "label": f"{x.fqdn}:{port}",
                        "port": port,
                        "ips": sorted(info["ips"]),
                        "in_scope_ips": sorted(info["in_scope_ips"]),
                        "in_scope": bool(in_dom or info["in_scope_ips"]),
                    }
                    for port, info in sorted(port_info.items())
                ]

                out.append(
                    {
                        "fqdn": x.fqdn,
                        "root_domain": x.root_domain,
                        "ips": ips_found,
                        "in_scope": in_scope,
                        "sensitive": sensitive,
                        "sensitive_ips": sensitive_ip_set,
                        "in_scope_ips": in_scope_ip_set,
                        "rdap": rdap,
                        "prowl": prowl,
                        "scope_override": None,
                        "ports": sub_ports,
                        "port_chips": port_chips,
                        "complete": getattr(x, "complete", 0),
                        "inprogress": getattr(x, "inprogress", 0),
                        "waf": getattr(x, "waf", 0),
                    }
                )
                if x.root_domain and x.root_domain not in root_domains:
                    root_domains[x.root_domain] = rdap

            # Standalone hosts: all in-scope hosts with HTTP/HTTPS services,
            # including hosts that are also linked to subdomains
            all_web_ips_ports = get_open_web_ports_by_ip(s)

            # All in-scope IPs with HTTP/HTTPS ports
            standalone_seen: set[str] = set()
            for ip, ports in all_web_ips_ports.items():
                if ip in standalone_seen:
                    continue
                if not ip_in_scope(ip, ips, subnets, excluded):
                    continue
                standalone_seen.add(ip)
                is_sensitive_ip = ip_in_scope(ip, s_ips, s_subnets, s_excluded)
                out.append(
                    {
                        "fqdn": ip,
                        "root_domain": "_standalone_ips",
                        "ips": [ip],
                        "in_scope": True,
                        "sensitive": is_sensitive_ip,
                        "sensitive_ips": {ip} if is_sensitive_ip else set(),
                        "in_scope_ips": {ip},
                        "rdap": {},
                        "prowl": {},
                        "scope_override": None,
                        "ports": {ip: sorted(set(ports))},
                        "port_chips": [
                            {
                                "label": f"{ip}:{port}",
                                "port": port,
                                "ips": [ip],
                                "in_scope_ips": [ip],
                                "in_scope": True,
                            }
                            for port in sorted(set(ports))
                        ],
                        "standalone_host": True,
                        "complete": 0,
                        "inprogress": 0,
                        "waf": 0,
                    }
                )

            # Count URLs per host without loading every URL into the page.
            url_count_by_host: dict[str, int] = {}
            domain_count_rows = s.execute(
                select(WebUrl.domain, func.count(WebUrl.id)).group_by(WebUrl.domain)
            ).all()
            for domain_value, count in domain_count_rows:
                host = _web_url_host_from_domain(domain_value)
                if host:
                    url_count_by_host[host] = url_count_by_host.get(host, 0) + int(count)
            if any(not _web_url_host_from_domain(domain_value) for domain_value, _ in domain_count_rows):
                empty_domain_urls = s.execute(
                    select(WebUrl.url).where(WebUrl.domain == "")
                ).scalars().all()
                for url_value in empty_domain_urls:
                    host = _web_url_host_from_url(url_value)
                    if host:
                        url_count_by_host[host] = url_count_by_host.get(host, 0) + 1

        # Group by root domain, attaching matched URLs to each subdomain
        grouped = {}
        for r in out:
            rd = r["root_domain"] or "unknown"
            if rd not in grouped:
                grouped[rd] = {"subs": [], "rdap": root_domains.get(rd, {})}
            # Attach URL count matching this subdomain's FQDN
            r["url_count"] = url_count_by_host.get(
                _web_url_host_from_domain(r["fqdn"]), 0
            )
            grouped[rd]["subs"].append(r)

        # Ensure standalone IPs group exists and is sorted
        if "_standalone_ips" in grouped:
            grouped["_standalone_ips"]["subs"].sort(key=lambda x: x["fqdn"])

        out = out if show_out == 1 else [r for r in out if r.get("in_scope")]
        grouped_filtered = {}
        for rd, data in grouped.items():
            filtered = (
                data["subs"]
                if show_out == 1
                else [s for s in data["subs"] if s.get("in_scope")]
            )
            if filtered:
                filtered.sort(key=lambda x: (0 if x["fqdn"] == rd else 1, x["fqdn"]))
                if rd != "_standalone_ips" and not any(s["fqdn"] == rd for s in filtered):
                    root_sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == rd))
                    filtered.insert(0, {
                        "fqdn": rd, "root_domain": rd, "ips": [],
                        "in_scope": True, "sensitive": False,
                        "sensitive_ips": set(), "in_scope_ips": set(),
                        "rdap": {}, "prowl": {}, "scope_override": None,
                        "ports": {}, "port_chips": [], "url_count": 0,
                        "complete": root_sub.complete if root_sub else 0,
                        "inprogress": root_sub.inprogress if root_sub else 0,
                        "waf": root_sub.waf if root_sub else 0,
                    })
                grouped_filtered[rd] = {"subs": filtered, "rdap": data["rdap"]}

        probe_rows = s.execute(select(WebProtocolProbe)).scalars().all()
        probes_by_fqdn_port: dict[tuple[str, int], list[dict]] = {}
        for p in probe_rows:
            fq = (p.fqdn or "").strip().lower().rstrip(".")
            try:
                probe_port = int(p.port)
            except (TypeError, ValueError):
                continue
            probes_by_fqdn_port.setdefault((fq, probe_port), []).append(
                {
                    "scheme": p.scheme or "none",
                    "http_status": p.http_status or 0,
                    "https_status": p.https_status or 0,
                    "error": p.error or "",
                    "target_ip": p.target_ip or "",
                    "created_at": p.created_at.isoformat() if p.created_at else "",
                }
            )

        def _aggregate_probe_scheme(results: list[dict]) -> str:
            if not results:
                return ""
            schemes = {r.get("scheme", "none") for r in results}
            if "both" in schemes:
                return "both"
            if "https" in schemes:
                return "https"
            if "http" in schemes:
                return "http"
            return "none"

        for group in grouped_filtered.values():
            for sub in group.get("subs", []):
                sub_fqdn = (sub.get("fqdn") or "").strip().lower().rstrip(".")
                for chip in sub.get("port_chips", []):
                    try:
                        chip_port = int(chip.get("port") or 0)
                    except (TypeError, ValueError):
                        continue
                    results = probes_by_fqdn_port.get((sub_fqdn, chip_port), [])
                    chip["probe_results"] = sorted(
                        results, key=lambda r: r.get("target_ip") or ""
                    )
                    chip["probe_scheme"] = _aggregate_probe_scheme(results)
                    chip["probe_error"] = "; ".join(
                        r.get("error", "") for r in results if r.get("error")
                    )[:500]

        return st.templates.TemplateResponse(
            "subdomains.html",
            {"request": request, "grouped": grouped_filtered, "show_out": show_out, "excluded": excluded},
        )

    @router.get("/api/subdomains/{fqdn}/urls")
    def api_subdomain_urls(
        fqdn: str,
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ):
        host = _web_url_host_from_domain(fqdn)
        if not host:
            return {"ok": False, "error": "Invalid fqdn", "urls": [], "total": 0, "offset": offset, "limit": limit}

        def _serialize_url(u: WebUrl) -> dict:
            return {
                "id": u.id,
                "url": u.url,
                "domain": u.domain,
                "title": u.title or "",
                "status_code": u.status_code or 0,
            }

        with st.db() as s:
            domain_filter = (
                (WebUrl.domain == host)
                | (WebUrl.domain == host + ".")
                | (WebUrl.domain.like(_like_escape(host) + ":%", escape="\\"))
                | (WebUrl.domain.like(_like_escape(host) + ".:%", escape="\\"))
            )
            base_total = int(s.scalar(select(func.count(WebUrl.id)).where(domain_filter)) or 0)
            empty_domain_urls = (
                s.execute(select(WebUrl).where(WebUrl.domain == ""))
                .scalars()
                .all()
            )
            empty_urls = [
                _serialize_url(u)
                for u in empty_domain_urls
                if _web_url_host_from_url(u.url) == host
            ]
            empty_urls.sort(key=lambda item: item["url"])
            base_start = max(0, offset - len(empty_urls))
            base_fetch = limit + len(empty_urls)
            base_rows = (
                s.execute(
                    select(WebUrl)
                    .where(domain_filter)
                    .order_by(WebUrl.url.asc())
                    .offset(base_start)
                    .limit(base_fetch)
                )
                .scalars()
                .all()
            )
            base_urls = [_serialize_url(u) for u in base_rows]
            base_urls.sort(key=lambda item: item["url"])

        merged: list[dict] = []
        i = j = 0
        while i < len(empty_urls) and j < len(base_urls):
            if empty_urls[i]["url"] <= base_urls[j]["url"]:
                merged.append(empty_urls[i]); i += 1
            else:
                merged.append(base_urls[j]); j += 1
        merged.extend(empty_urls[i:])
        merged.extend(base_urls[j:])
        merged_start = offset - base_start
        page = merged[merged_start:merged_start + limit]
        total = base_total + len(empty_urls)
        return {
            "ok": True,
            "urls": page,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total,
        }

    return router
