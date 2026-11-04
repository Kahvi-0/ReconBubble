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

    @router.get("/osint/registrars", response_class=HTMLResponse)
    def osint_registrars_page(request: Request):
        with st.db() as s:
            subs = s.execute(
                select(Subdomain)
                .order_by(Subdomain.root_domain, Subdomain.fqdn)
            ).scalars().all()

            # Get registrar overrides
            reg_overrides = s.execute(
                select(RegistrarInfo).order_by(RegistrarInfo.domain)
            ).scalars().all()

        # Group subdomains by root domain (only those with prowl data)
        grouped: dict[str, list[Subdomain]] = {}
        for sub in subs:
            if sub.prowl_ips or sub.prowl_registrar or sub.prowl_netblocks:
                grouped.setdefault(sub.root_domain, []).append(sub)

        # Also include domains from RegistrarInfo that aren't in grouped
        for ri in reg_overrides:
            if ri.domain not in grouped:
                grouped[ri.domain] = []

        # Build registrar/netblock/asn info per root domain + manual subdomain_ips
        root_info: dict[str, dict[str, str]] = {}
        manual_sub_ips: dict[str, str] = {}
        for root, sub_list in grouped.items():
            # Start with prowl data
            registrar = next((s.prowl_registrar for s in sub_list if s.prowl_registrar), "")
            netblocks = next((s.prowl_netblocks for s in sub_list if s.prowl_netblocks), "")
            asn = ""

            # Override with manual RegistrarInfo if exists
            for ri in reg_overrides:
                if ri.domain == root:
                    registrar = ri.registrar or registrar
                    netblocks = ri.netblocks or netblocks
                    asn = ri.asn or asn
                    if ri.subdomain_ips:
                        manual_sub_ips[root] = ri.subdomain_ips
                    break

            root_info[root] = {
                "registrar": registrar,
                "netblocks": netblocks,
                "asn": asn,
            }

        return st.templates.TemplateResponse(
            "osint_registrars.html",
            {
                "request": request,
                "grouped": dict(sorted(grouped.items())),
                "root_info": root_info,
                "manual_sub_ips": manual_sub_ips,
            },
        )

    @router.get("/api/registrar")
    def api_registrar_list(domain: str | None = Query(None)):
        with st.db() as s:
            if domain:
                # Return merged data for specific domain
                ri = s.execute(select(RegistrarInfo).where(RegistrarInfo.domain == domain.lower().strip())).scalars().first()
                subs = s.execute(select(Subdomain).where(Subdomain.root_domain == domain.lower().strip()).order_by(Subdomain.fqdn)).scalars().all()
                prowl_reg = next((sb.prowl_registrar for sb in subs if sb.prowl_registrar), "")
                prowl_nb = next((sb.prowl_netblocks for sb in subs if sb.prowl_netblocks), "")
                subdomain_list = [{"fqdn": sb.fqdn, "ips": sb.prowl_ips} for sb in subs if sb.prowl_ips or sb.fqdn]
                manual_sub_ips = ""
                if ri:
                    manual_sub_ips = ri.subdomain_ips or ""
                else:
                    # Build subdomain list from Prowler data for initial textarea
                    for sb in subs:
                        ips = sb.prowl_ips if sb.prowl_ips else ""
                        manual_sub_ips += f"{sb.fqdn} {ips}\n" if ips else f"{sb.fqdn}\n"
                if ri:
                    return {
                        "ok": True,
                        "item": {
                            "id": ri.id,
                            "domain": ri.domain,
                            "asn": ri.asn,
                            "registrar": ri.registrar,
                            "netblocks": ri.netblocks,
                        },
                        "subdomains": subdomain_list,
                        "subdomain_ips": manual_sub_ips.rstrip('\n'),
                    }
                else:
                    return {
                        "ok": True,
                        "item": {
                            "id": None,
                            "domain": domain.lower().strip(),
                            "asn": "",
                            "registrar": prowl_reg,
                            "netblocks": prowl_nb,
                        },
                        "subdomains": subdomain_list,
                        "subdomain_ips": manual_sub_ips.rstrip('\n'),
                    }
            else:
                items = s.execute(select(RegistrarInfo)).scalars().all()
                return {
                    "ok": True,
                    "items": [
                        {
                            "id": i.id,
                            "domain": i.domain,
                            "asn": i.asn,
                            "registrar": i.registrar,
                            "netblocks": i.netblocks,
                            "subdomain_ips": i.subdomain_ips,
                        }
                        for i in items
                    ],
                }

    @router.get("/api/registrar/copy")
    def api_registrar_copy(domain: str = Query(...)):
        domain = domain.lower().strip()
        with st.db() as s:
            ri = s.execute(select(RegistrarInfo).where(RegistrarInfo.domain == domain)).scalars().first()
            subs = s.execute(select(Subdomain).where(Subdomain.root_domain == domain).order_by(Subdomain.fqdn)).scalars().all()
            prowl_reg = next((sb.prowl_registrar for sb in subs if sb.prowl_registrar), "")
            prowl_nb = next((sb.prowl_netblocks for sb in subs if sb.prowl_netblocks), "")
            prowl_asn = ""

            registrar = (ri.registrar if ri else "") or prowl_reg
            netblocks = (ri.netblocks if ri else "") or prowl_nb
            asn = (ri.asn if ri else "") or prowl_asn
            manual_sub_ips = ri.subdomain_ips if ri else ""

        html = f"<ul><li>{domain}<ul>"
        html += f"<li>Registrar: {registrar}</li>"
        if asn:
            html += f"<li>ASN: {asn}</li>"
        if netblocks:
            for nb in netblocks.split(","):
                nb = nb.strip()
                if nb:
                    html += f"<li>Network: {nb}</li>"
        sub_lines = []
        if manual_sub_ips:
            for line in manual_sub_ips.strip().split("\n"):
                parts = line.strip().split()
                if parts:
                    fqdn = parts[0]
                    ips = parts[1:]
                    sub_lines.append(f"<li>{fqdn} : {', '.join(ips)}</li>")
        else:
            for sb in subs:
                if sb.prowl_ips:
                    ips = [ip.strip() for ip in sb.prowl_ips.split(",") if ip.strip()]
                    sub_lines.append(f"<li>{sb.fqdn} : {', '.join(ips)}</li>")
        if sub_lines:
            html += f"<li>Subdomains<ul>{''.join(sub_lines)}</ul></li>"
        html += "</ul></li></ul>"

        # Plain text fallback
        lines = [f"• {domain}"]
        lines.append(f"  • Registrar: {registrar}")
        if asn:
            lines.append(f"  • ASN: {asn}")
        if netblocks:
            for nb in netblocks.split(","):
                nb = nb.strip()
                if nb:
                    lines.append(f"  • Network: {nb}")
        plain_subs = []
        if manual_sub_ips:
            for line in manual_sub_ips.strip().split("\n"):
                parts = line.strip().split()
                if parts:
                    fqdn = parts[0]
                    ips = parts[1:]
                    plain_subs.append(f"    • {fqdn} : {', '.join(ips)}")
        else:
            for sb in subs:
                if sb.prowl_ips:
                    ips = [ip.strip() for ip in sb.prowl_ips.split(",") if ip.strip()]
                    plain_subs.append(f"    • {sb.fqdn} : {', '.join(ips)}")
        if plain_subs:
            lines.append(f"  • Subdomains")
            lines.extend(plain_subs)
        text = "\n".join(lines) + "\n"

        return {"text": text, "html": html}

    @router.post("/api/registrar/create")
    def api_registrar_create(
        domain: str = Form(""),
        asn: str = Form(""),
        registrar: str = Form(""),
        registrar_email: str = Form(""),
        registrar_org: str = Form(""),
        netblocks: str = Form(""),
        subdomain_ips: str = Form(""),
        creation_date: str = Form(""),
        expiration_date: str = Form(""),
        notes: str = Form(""),
        has_existing: str = Form("0"),
    ):
        domain = domain.lower().strip()
        with st.db() as s:
            if has_existing == "0":
                existing = s.execute(select(RegistrarInfo).where(RegistrarInfo.domain == domain)).scalars().first()
                if existing:
                    return {"ok": False, "error": "Domain already exists."}
                ri = RegistrarInfo(
                    domain=domain,
                    asn=asn,
                    registrar=registrar,
                    registrar_email=registrar_email,
                    registrar_org=registrar_org,
                    netblocks=netblocks,
                    subdomain_ips=subdomain_ips,
                    creation_date=creation_date,
                    expiration_date=expiration_date,
                    notes=notes,
                )
                s.add(ri)
            else:
                ri = s.execute(select(RegistrarInfo).where(RegistrarInfo.domain == domain)).scalars().first()
                if ri:
                    ri.asn = asn
                    ri.registrar = registrar
                    ri.registrar_email = registrar_email
                    ri.registrar_org = registrar_org
                    ri.netblocks = netblocks
                    ri.subdomain_ips = subdomain_ips
                    ri.creation_date = creation_date
                    ri.expiration_date = expiration_date
                    ri.notes = notes
            s.commit()
        return {"ok": True}

    @router.post("/api/registrar/update")
    def api_registrar_update(
        registrar_id: int = Form(...),
        domain: str = Form(""),
        asn: str = Form(""),
        registrar: str = Form(""),
        registrar_email: str = Form(""),
        registrar_org: str = Form(""),
        netblocks: str = Form(""),
        subdomain_ips: str = Form(""),
        creation_date: str = Form(""),
        expiration_date: str = Form(""),
        notes: str = Form(""),
    ):
        with st.db() as s:
            ri = s.get(RegistrarInfo, registrar_id)
            if not ri:
                return {"ok": False, "error": "Not found."}
            if domain:
                ri.domain = domain.lower().strip()
            ri.asn = asn
            ri.registrar = registrar
            ri.registrar_email = registrar_email
            ri.registrar_org = registrar_org
            ri.netblocks = netblocks
            ri.subdomain_ips = subdomain_ips
            ri.creation_date = creation_date
            ri.expiration_date = expiration_date
            ri.notes = notes
            s.commit()
        return {"ok": True}

    @router.post("/api/registrar/delete")
    def api_registrar_delete(registrar_id: int = Form(...)):
        with st.db() as s:
            ri = s.get(RegistrarInfo, registrar_id)
            if not ri:
                return {"ok": False, "error": "Not found."}
            s.delete(ri)
            s.commit()
        return {"ok": True}

    return router
