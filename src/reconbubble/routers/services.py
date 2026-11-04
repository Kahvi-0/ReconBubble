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

    def _service_page_flags(request: Request, s):
        qs = request.query_params.get("hide_completed", "")
        if qs:
            hide_completed = int(qs)
        else:
            row = s.scalar(select(AppSettings).where(AppSettings.key == "services_hide_completed"))
            hide_completed = int(row.value) if row else 0
        qs = request.query_params.get("show_out_of_scope", "")
        if qs:
            show_oos = int(qs)
        else:
            row = s.scalar(select(AppSettings).where(AppSettings.key == "services_show_out_of_scope"))
            show_oos = int(row.value) if row else 0
        return hide_completed, show_oos

    def _build_service_summary(s, hide_completed: bool, show_oos: bool):
        ips, subnets, domains, _email_domains, domain_all_subs, _domain_subs_if_ip, excluded = scope_sets(s)
        hosts_by_id = {host.id: host for host in s.execute(select(Host)).scalars()}
        services = s.execute(select(Service).where(Service.state == "open")).scalars().all()
        findings_by_service = {}
        for f in s.execute(
            select(ServiceFinding).where(ServiceFinding.service_id.isnot(None))
        ).scalars().all():
            findings_by_service.setdefault(f.service_id, []).append(f)
        service_map = {}
        scope_cache = {}
        for svc in services:
            host = hosts_by_id.get(svc.host_id)
            if not host:
                continue
            if hide_completed and host.complete:
                continue
            if host.id not in scope_cache:
                scope_cache[host.id] = host_in_scope(
                    host.ip, host.hostname or "", ips, subnets, domains, domain_all_subs, excluded
                )
            host_in = scope_cache[host.id]
            if not (host_in or show_oos):
                continue
            key = f"{svc.port}/{svc.proto}"
            if key not in service_map:
                service_map[key] = {
                    "port": svc.port,
                    "proto": svc.proto,
                    "hosts": [],
                    "service_types": set(),
                    "products": set(),
                    "tracked_service_ids": set(),
                    "inspected_service_ids": set(),
                    "finding_sevs": [],
                }
            data = service_map[key]
            if host_in:
                data["hosts"].append(
                    {"id": host.id, "ip": host.ip, "hostname": host.hostname or ""}
                )
                data["tracked_service_ids"].add(svc.id)
                if int(svc.inspected or 0) == 1:
                    data["inspected_service_ids"].add(svc.id)
                data["finding_sevs"].extend(
                    f.severity for f in findings_by_service.get(svc.id, ())
                )
            if svc.service_name:
                data["service_types"].add(svc.service_name)
            if svc.product:
                data["products"].add(f"{svc.product} {svc.version}".strip())
        rows = []
        for data in service_map.values():
            if not data["hosts"]:
                continue
            tracked_count = len(data["tracked_service_ids"])
            inspected_count = len(data["inspected_service_ids"])
            finding_sevs = data["finding_sevs"]
            worst = (
                min(finding_sevs, key=lambda x: SEVERITY_RANK.get(x, 99))
                if finding_sevs
                else None
            )
            rows.append(
                {
                    "port": data["port"],
                    "proto": data["proto"],
                    "service_types": sorted(data["service_types"]),
                    "products": sorted(data["products"]),
                    "host_count": len(data["hosts"]),
                    "tracked_count": tracked_count,
                    "inspected_count": inspected_count,
                    "port_complete": bool(tracked_count) and data["inspected_service_ids"] == data["tracked_service_ids"],
                    "findings": {"count": len(finding_sevs), "worst": worst},
                }
            )
        rows.sort(key=lambda x: (x["port"], x["proto"]))
        return rows

    def _build_service_detail(s, hide_completed: bool, show_oos: bool, port: int, proto: str):
        ips, subnets, domains, _email_domains, domain_all_subs, _domain_subs_if_ip, excluded = scope_sets(s)
        hosts_by_id = {host.id: host for host in s.execute(select(Host)).scalars()}
        services = (
            s.execute(
                select(Service).where(
                    Service.state == "open",
                    Service.port == port,
                    Service.proto == proto,
                )
            )
            .scalars()
            .all()
        )
        key = f"{port}/{proto}"
        service_map = {}
        scope_cache = {}
        service_host_by_id = {}
        for svc in services:
            host = hosts_by_id.get(svc.host_id)
            if not host:
                continue
            if hide_completed and host.complete:
                continue
            if host.id not in scope_cache:
                scope_cache[host.id] = host_in_scope(
                    host.ip, host.hostname or "", ips, subnets, domains, domain_all_subs, excluded
                )
            host_in = scope_cache[host.id]
            if not (host_in or show_oos):
                continue
            if key not in service_map:
                service_map[key] = {
                    "port": svc.port,
                    "proto": svc.proto,
                    "hosts": [],
                    "service_types": set(),
                    "products": set(),
                    "host_outputs": {},
                    "tracked_service_ids": set(),
                    "inspected_service_ids": set(),
                }
            data = service_map[key]
            if host_in:
                data["hosts"].append(
                    {"id": host.id, "ip": host.ip, "hostname": host.hostname or ""}
                )
                data["tracked_service_ids"].add(svc.id)
                if int(svc.inspected or 0) == 1:
                    data["inspected_service_ids"].add(svc.id)
            if svc.service_name:
                data["service_types"].add(svc.service_name)
            if svc.product:
                data["products"].add(f"{svc.product} {svc.version}".strip())
            host_key = host.id
            if host_key not in data["host_outputs"]:
                data["host_outputs"][host_key] = {
                    "host": {"id": host.id, "ip": host.ip, "hostname": host.hostname or ""},
                    "outputs": set(),
                    "service_id": svc.id,
                    "service_name": svc.service_name or "",
                    "inspected": int(svc.inspected or 0),
                    "counted": bool(host_in),
                }
            else:
                data["host_outputs"][host_key].update(
                    {
                        "service_id": svc.id,
                        "service_name": svc.service_name or "",
                        "inspected": int(svc.inspected or 0),
                        "counted": bool(host_in),
                    }
                )
            service_host_by_id[svc.id] = (host.id, host.ip, host.hostname or "")
        if key not in service_map or not service_map[key]["hosts"]:
            return None
        data = service_map[key]
        evidence_service_ids = [ho["service_id"] for ho in data["host_outputs"].values()]
        if evidence_service_ids:
            evidence_rows = (
                s.execute(
                    select(ServiceEvidence).where(
                        ServiceEvidence.service_id.in_(evidence_service_ids)
                    )
                )
                .scalars()
                .all()
            )
            for e in evidence_rows:
                if not e.raw_output:
                    continue
                host_info = service_host_by_id.get(e.service_id)
                if not host_info:
                    continue
                host_id, host_ip, hostname = host_info
                cleaned = e.raw_output.replace(host_ip, "<IP>")
                if hostname:
                    cleaned = cleaned.replace(hostname, "<HOST>")
                data["host_outputs"][host_id]["outputs"].add(cleaned[:800])
        findings_by_svc = {}
        if service_host_by_id:
            for f in s.execute(
                select(ServiceFinding).where(
                    ServiceFinding.service_id.in_(list(service_host_by_id.keys()))
                )
            ).scalars().all():
                findings_by_svc.setdefault(f.service_id, []).append(f)
        output_rows = []
        for ho in data["host_outputs"].values():
            f_list = sorted(
                findings_by_svc.get(ho["service_id"], ()),
                key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.title),
            )
            output_rows.append(
                {
                    "host": ho["host"],
                    "outputs": list(ho["outputs"]),
                    "service_id": ho["service_id"],
                    "service_name": ho["service_name"],
                    "inspected": ho["inspected"],
                    "counted": ho["counted"],
                    "findings": [
                        {
                            "script": f.script_name,
                            "kind": f.kind,
                            "severity": f.severity,
                            "title": f.title,
                            "detail": f.detail,
                            "cves": f.cves,
                        }
                        for f in f_list
                    ],
                }
            )
        suggestions = []
        suggestion_command = ""
        try:
            cat = nsecatalog.get_catalog()
            primary_type = sorted(data["service_types"])[0] if data["service_types"] else ""
            suggested = cat.suggest(primary_type, data["port"], limit=8)
            for sc in suggested:
                desc = (sc.description or "").strip()
                suggestions.append(
                    {
                        "name": sc.name,
                        "description": desc.splitlines()[0][:200] if desc else "",
                        "categories": sorted(sc.categories),
                    }
                )
            if suggested:
                suggestion_command = nsecatalog.render_nmap_command(
                    suggested, data["port"], "<target>"
                )
        except Exception:
            pass
        tracked_count = len(data["tracked_service_ids"])
        inspected_count = len(data["inspected_service_ids"])
        return {
            "port": data["port"],
            "proto": data["proto"],
            "service_types": sorted(data["service_types"]),
            "products": sorted(data["products"]),
            "host_count": len(data["hosts"]),
            "hosts": data["hosts"],
            "host_outputs": output_rows,
            "tracked_count": tracked_count,
            "inspected_count": inspected_count,
            "port_complete": bool(tracked_count) and data["inspected_service_ids"] == data["tracked_service_ids"],
            "suggestions": suggestions,
            "suggestion_command": suggestion_command,
        }

    @router.get("/services", response_class=HTMLResponse)
    def services_page(request: Request):
        with st.db() as s:
            hide_completed, show_oos = _service_page_flags(request, s)
            rows = _build_service_summary(s, hide_completed, show_oos)

        return st.templates.TemplateResponse(
             "services.html", {"request": request, "rows": rows, "hide_completed": hide_completed, "show_oos": show_oos}
          )

    @router.get("/api/service-port/{port}/{proto}")
    def api_service_port(request: Request, port: int, proto: str):
        with st.db() as s:
            hide_completed, show_oos = _service_page_flags(request, s)
            detail = _build_service_detail(s, hide_completed, show_oos, port, proto)
        if not detail:
            return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
        return {"ok": True, **detail}

    @router.get("/profiling", response_class=HTMLResponse)
    def profiling_page(request: Request):
        return st.templates.TemplateResponse(
            "profiling.html", {"request": request}
        )

    return router
