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


def _is_web_service(svc: Service) -> bool:
    # Best-effort "serves HTTP(S)" check, using the same signals as
    # get_open_web_ports_by_ip: the confident web-port set, an http(s)
    # service name, or a known web-server product.
    if svc.port in _WEB_PORTS:
        return True
    if _WEB_SERVICE_NAME_RE.search(svc.service_name or ""):
        return True
    return _WEB_PRODUCT_RE.search(svc.product or "") is not None


def build(st: AppState, app) -> APIRouter:
    router = APIRouter()

    @router.get("/subdomains/export")
    def subdomains_export():
        with st.db() as s:
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            rows = s.execute(select(Subdomain)).scalars().all()
            all_sub_ips = list_all_subdomain_ips(s)
            all_web_ips_ports = get_open_web_ports_by_ip(s)
            entries: dict[tuple[str, int | None], set[str]] = {}
            covered_ip_ports: set[str] = set()

            def add_entry(
                host: str,
                port: int | None,
                entry_ips: set[str] | list[str] | None = None,
            ) -> None:
                normalized = (host or "").strip().lower().rstrip(".")
                if not normalized:
                    return
                entries.setdefault((normalized, port), set())
                for ip in entry_ips or []:
                    cleaned = (ip or "").strip()
                    if cleaned:
                        entries[(normalized, port)].add(cleaned)

            for x in rows:
                fqdn = (x.fqdn or "").strip().lower().rstrip(".")
                root_domain = (x.root_domain or "").strip().lower().rstrip(".")
                ips_found = list(set(all_sub_ips.get(fqdn, [])))
                prowl_ips_cleaned = [
                    ip.strip()
                    for ip in (x.prowl_ips or "").split(",")
                    if ip.strip()
                ]
                all_ips = list(set(ips_found) | set(prowl_ips_cleaned))
                in_dom = domain_in_scope(
                    fqdn,
                    domains,
                    domain_all_subs,
                    domain_subs_if_ip,
                    ips_found,
                    ips,
                    subnets,
                    excluded,
                )
                in_scope_ip_set = {
                    ip for ip in all_ips if ip_in_scope(ip, ips, subnets, excluded)
                }
                if not (in_dom or in_scope_ip_set):
                    continue
                bare_ips = set(all_ips) if in_dom else set(in_scope_ip_set)
                add_entry(fqdn, None, bare_ips)
                if root_domain:
                    root_ips = set(all_sub_ips.get(root_domain, []))
                    add_entry(root_domain, None, root_ips)
                eligible_ips = set(all_ips) if in_dom else set(in_scope_ip_set)
                for ip in eligible_ips:
                    for port in sorted(set(all_web_ips_ports.get(ip, []))):
                        add_entry(fqdn, port, {ip})
                        covered_ip_ports.add(f"{ip}:{port}")

            for ip in all_web_ips_ports:
                if not ip_in_scope(ip, ips, subnets, excluded):
                    continue
                for port in sorted(set(all_web_ips_ports[ip])):
                    if f"{ip}:{port}" not in covered_ip_ports:
                        add_entry(ip, port, {ip})

            explicit_tasks, default_tasks, _ = st._collect_export_probe_tasks(s, entries)
        st._run_export_probe_tasks(explicit_tasks, default_tasks)
        with st.db() as s:
            probes = st._load_web_probe_map(s)
        urls = set()
        for host, port in entries:
            if port is None:
                scheme = st._export_scheme_for_bare_host(host, probes)
            else:
                scheme = st._export_scheme_from_probe_results(probes.get((host, port), []))
            url = st._export_url_for_scheme(host, port, scheme)
            if url:
                urls.add(url)
        https_default_hosts = set()
        for url in urls:
            parsed = urlsplit(url)
            if parsed.scheme == "https" and parsed.port in (None, 443):
                https_default_hosts.add(parsed.hostname or "")
        final_urls = set()
        for url in urls:
            parsed = urlsplit(url)
            if (
                parsed.scheme == "http"
                and parsed.port in (None, 80)
                and (parsed.hostname or "") in https_default_hosts
            ):
                continue
            final_urls.add(url)
        txt = "\n".join(sorted(final_urls))
        return Response(
            content=txt,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=reconbubble-subdomains.txt"
            },
        )

    @router.post("/api/host/done")
    def api_host_done(host_id: int = Form(...), done: int = Form(...)):
        with st.db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.done = 1 if int(done) == 1 else 0
            s.commit()
        return {"ok": True}

    @router.post("/api/subdomain/done")
    def api_sub_done(fqdn: str = Form(...), done: int = Form(...)):
        fq = fqdn.strip().lower().rstrip(".")
        with st.db() as s:
            sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == fq))
            if not sub:
                return JSONResponse({"ok": False}, status_code=404)
            sub.done = 1 if int(done) == 1 else 0
            s.commit()
        return {"ok": True}

    @router.post("/api/subdomain/scope-override")
    def api_subdomain_scope_override(fqdn: str = Form(...)):
        fq = fqdn.strip().lower().rstrip(".")
        if not fq:
            return JSONResponse({"ok": False, "error": "Invalid FQDN"}, status_code=400)
        with st.db() as s:
            existing = s.scalar(select(ScopeExclusion).where(ScopeExclusion.fqdn == fq))
            if existing:
                s.delete(existing)
            else:
                s.add(ScopeExclusion(fqdn=fq))
            s.commit()
        return {"ok": True}

    @router.post("/api/subdomain/complete")
    def api_subdomain_complete(fqdn: str = Form(...), complete: int = Form(...), port: int | None = Form(None)):
        fq = fqdn.strip().lower().rstrip(".")
        with st.db() as s:
            sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == fq))
            if not sub:
                sub = Subdomain(fqdn=fq, root_domain=fq)
                s.add(sub)
            sub.complete = 1 if int(complete) == 1 else 0
            if sub.complete == 1:
                sub.inprogress = 0
            # Carry-over to the services page: when a port is provided (e.g. from
            # the screenshot view), mark the matching tracked web service(s)
            # inspected / un-inspected to mirror the complete state.
            if port:
                flag = 1 if sub.complete == 1 else 0
                candidate_ips: set[str] = set()
                shot = (
                    s.query(WebScreenshot)
                    .filter(WebScreenshot.fqdn == fq, WebScreenshot.port == int(port))
                    .order_by(WebScreenshot.created_at.desc(), WebScreenshot.id.desc())
                    .first()
                )
                if shot and shot.target_ip:
                    candidate_ips.add(shot.target_ip.strip().lower())
                for ip in list_all_subdomain_ips(s).get(fq, []) or []:
                    candidate_ips.add(ip)
                for ip in [p.strip() for p in (sub.prowl_ips or "").split(",") if p.strip()]:
                    candidate_ips.add(ip)
                for ip in candidate_ips:
                    host = s.scalar(select(Host).where(Host.ip == ip))
                    if not host:
                        continue
                    svc = s.scalar(
                        select(Service)
                        .where(
                            Service.host_id == host.id,
                            Service.port == int(port),
                            Service.proto == "tcp",
                            Service.state == "open",
                        )
                    )
                    if svc:
                        svc.inspected = flag
            s.commit()
        return {"ok": True}

    @router.post("/api/subdomain/inprogress")
    def api_subdomain_inprogress(fqdn: str = Form(...), inprogress: int = Form(...)):
        fq = fqdn.strip().lower().rstrip(".")
        with st.db() as s:
            sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == fq))
            if not sub:
                sub = Subdomain(fqdn=fq, root_domain=fq)
                s.add(sub)
            sub.inprogress = 1 if int(inprogress) == 1 else 0
            if sub.inprogress == 1:
                sub.complete = 0
            s.commit()
        return {"ok": True}

    @router.post("/api/subdomain/waf")
    def api_subdomain_waf(fqdn: str = Form(...), waf: int = Form(...)):
        fq = fqdn.strip().lower().rstrip(".")
        with st.db() as s:
            sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == fq))
            if not sub:
                sub = Subdomain(fqdn=fq, root_domain=fq)
                s.add(sub)
            sub.waf = 1 if int(waf) == 1 else 0
            s.commit()
        return {"ok": True}

    @router.post("/api/service/inspected")
    def api_service_inspected(service_id: int = Form(...), inspected: int = Form(...)):
        with st.db() as s:
            svc = s.scalar(select(Service).where(Service.id == service_id))
            if not svc:
                return JSONResponse({"ok": False}, status_code=404)
            svc.inspected = 1 if int(inspected) == 1 else 0
            # Reverse carry-over to the Web Apps page: when a web (http/https)
            # service is marked inspected, mark the subdomains served by that
            # host complete so the screenshot grid and subdomain table stay in
            # sync. Only the mark-complete direction syncs back: unmarking one
            # host:port must not clear subdomains that may have been completed
            # for other reasons on a shared (virtual-host) IP.
            if svc.inspected == 1 and svc.state == "open" and _is_web_service(svc):
                for fqdn in list_host_domains(s, svc.host_id):
                    sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))
                    if sub:
                        sub.complete = 1
                        sub.inprogress = 0
            s.commit()
        return {"ok": True}

    @router.post("/api/host/complete")
    def api_host_complete(host_id: int = Form(...), complete: int = Form(...)):
        with st.db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.complete = 1 if int(complete) == 1 else 0
            if h.complete == 1:
                h.inprogress = 0
            s.commit()
        return {"ok": True}

    @router.post("/api/host/inprogress")
    def api_host_inprogress(host_id: int = Form(...), inprogress: int = Form(...)):
        with st.db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.inprogress = 1 if int(inprogress) == 1 else 0
            s.commit()
        return {"ok": True}

    @router.post("/api/host/waf")
    def api_host_waf(host_id: int = Form(...), waf: int = Form(...)):
        with st.db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.waf = 1 if int(waf) == 1 else 0
            s.commit()
        return {"ok": True}

    @router.post("/api/settings")
    def api_settings_set(key: str = Form(...), value: str = Form("")):
        with st.db() as s:
            row = s.scalar(select(AppSettings).where(AppSettings.key == key))
            if row:
                row.value = value
            else:
                s.add(AppSettings(key=key, value=value))
            s.commit()
        return {"ok": True}

    @router.post("/api/host/tag")
    def api_host_tag(asset_id: int = Form(...), tag: str = Form("")):
        with st.db() as s:
            h = s.scalar(select(Host).where(Host.id == asset_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.tag = tag
            s.commit()
        return {"ok": True}

    @router.post("/api/host/delete")
    def api_host_delete(host_id: int = Form(...)):
        with st.db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False, "error": "Host not found"}, status_code=404)
            s.delete(h)
            s.commit()
        return {"ok": True}


    return router
