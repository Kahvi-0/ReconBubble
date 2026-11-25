from __future__ import annotations
from pathlib import Path
import asyncio, base64, ipaddress, json, os, re, shlex, socket, ssl, sys, tempfile, uuid
import html as html_lib
from urllib.parse import quote_plus, parse_qsl, urlencode, urlsplit
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import APIRouter, Request, UploadFile, File, Form, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from markupsafe import Markup

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
    RegistrarExclusion,
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
    def api_registrar_delete(
        registrar_id: int | None = Form(None),
        domain: str = Form(""),
    ):
        with st.db() as s:
            deleted = False
            if registrar_id is not None:
                ri = s.get(RegistrarInfo, registrar_id)
                if ri:
                    s.delete(ri)
                    deleted = True
            if domain:
                root = domain.lower().strip()
                ri = s.execute(
                    select(RegistrarInfo).where(RegistrarInfo.domain == root)
                ).scalars().first()
                if ri:
                    s.delete(ri)
                    deleted = True
                # Hide the root from the registrar views instead of wiping
                # Prowler data — subdomain/IP info stays available on the
                # subdomains page. Re-shown from the OSINT hub.
                has_prowl = s.execute(
                    select(func.count(Subdomain.id)).where(
                        Subdomain.root_domain == root,
                        or_(
                            Subdomain.prowl_ips != "",
                            Subdomain.prowl_registrar != "",
                            Subdomain.prowl_netblocks != "",
                        ),
                    )
                ).scalar() or 0
                if has_prowl:
                    if not s.execute(
                        select(RegistrarExclusion).where(
                            RegistrarExclusion.domain == root
                        )
                    ).scalars().first():
                        s.add(RegistrarExclusion(domain=root))
                    deleted = True
            if not deleted:
                return {"ok": False, "error": "Not found."}
            s.commit()
        return {"ok": True}

    @router.post("/api/registrar/unhide")
    def api_registrar_unhide(domain: str = Form("")):
        root = (domain or "").lower().strip()
        if not root:
            return {"ok": False, "error": "Missing domain."}
        with st.db() as s:
            e = s.execute(
                select(RegistrarExclusion).where(RegistrarExclusion.domain == root)
            ).scalars().first()
            if not e:
                return {"ok": False, "error": "Not hidden."}
            s.delete(e)
            s.commit()
        return {"ok": True}

    @router.get("/osint/tools", response_class=HTMLResponse)
    def osint_tools_page(request: Request):
        # Tool cards (Prowler today, more OSINT tools later). Tool status and
        # run queue are fetched client-side from /api/tools and
        # /api/tools/jobs/active, same as the subdomains-discovery page.
        return st.templates.TemplateResponse(
            "osint_tools.html",
            {"request": request},
        )

    # ------------------------------------------------------------------
    # OSINT Hub prototypes — three alternative single-page layouts for
    # viewing all OSINT categories at once (v1 tiles + modal popout,
    # v2 dossier accordion, v3 unified feed). All share this read-only
    # data prep and the slim "Run a tool" strip.
    # ------------------------------------------------------------------

    def _hub_mime_short(mime: str) -> str:
        m = (mime or "").lower()
        if "spreadsheetml" in m:
            return "xlsx"
        if "wordprocessingml" in m:
            return "docx"
        if "presentationml" in m:
            return "pptx"
        if "msword" in m:
            return "doc"
        if m.startswith("application/pdf"):
            return "pdf"
        if m.startswith("image/"):
            return "image"
        if m.startswith("text/"):
            return "text"
        return m.split("/")[0] if m else "file"

    def _hub_size_human(n) -> str:
        try:
            n = float(n or 0)
        except (TypeError, ValueError):
            n = 0
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024.0
        return f"{n:.0f} B"

    def _osint_hub_context(st) -> dict:
        from ..models import DnsZoneTransfer, SmtpScan, DocExtractedName, DocExtractedSoftware

        def _fmt(dt):
            return dt.strftime("%Y-%m-%d %H:%M") if dt else ""

        def _b64_json(obj) -> str:
            # Per-row sidebar payload, URL-safe base64-encoded so it is
            # trivially safe inside an HTML attribute (no quote/escaping
            # issues, no </script> breakout). Decoded client-side.
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            return base64.urlsafe_b64encode(raw).decode("ascii")

        cats: list[dict] = []

        with st.db() as s:
            # --- Social Media -------------------------------------------------
            socials = s.execute(
                select(SocialMedia).order_by(
                    SocialMedia.platform.asc(), SocialMedia.handle.asc()
                )
            ).scalars().all()
            social_rows = []
            for r in socials:
                if r.artifact_id:
                    img_cell = Markup(
                        '<img class="hub-thumb" src="/api/artifacts/{aid}/thumb" '
                        'data-full="/api/artifacts/{aid}" alt="" title="View screenshot" />'
                    ).format(aid=r.artifact_id)
                else:
                    img_cell = Markup("—")
                social_rows.append([
                    img_cell,
                    r.platform,
                    r.handle,
                    r.url or "—",
                    r.display_name or "—",
                    (r.notes or "")[:120] or "—",
                    _fmt(r.created_at),
                ])
            # Full per-row payload for the hub sidebar (row click). Kept in
            # parallel with social_rows so the template can index by row.
            social_metas = [
                {
                    "id": r.id,
                    "platform": r.platform,
                    "handle": r.handle or "",
                    "url": r.url or "",
                    "display_name": r.display_name or "",
                    "bio": r.bio or "",
                    "notes": r.notes or "",
                    "artifact_id": r.artifact_id,
                    "added": _fmt(r.created_at),
                }
                for r in socials
            ]
            cats.append({
                "key": "social",
                "label": "Social Media",
                "count": len(socials),
                "last": _fmt(max((r.created_at for r in socials), default=None)),
                "preview": [
                    {"primary": r.handle or r.url or r.platform, "secondary": r.platform}
                    for r in socials[:5]
                ],
                "table": {
                    "head": ["Image", "Platform", "Handle", "URL", "Display", "Notes", "Added"],
                    "rows": social_rows,
                    "row_metas": [_b64_json(m) for m in social_metas],
                },
                "feed": [
                    {
                        "primary": r.handle or r.url or r.platform,
                        "secondary": r.platform,
                        "added": _fmt(r.created_at),
                        "detail": [
                            ["Platform", r.platform],
                            ["URL", r.url or "—"],
                            ["Display name", r.display_name or "—"],
                            ["Notes", (r.notes or "")[:400] or "—"],
                        ],
                    }
                    for r in socials
                ],
            })

            # --- Documents & Exif ---------------------------------------------
            docs = s.execute(
                select(Document).order_by(Document.created_at.desc())
            ).scalars().all()
            doc_titles = {r.id: r.title for r in docs}
            name_objs = s.execute(
                select(DocExtractedName).order_by(DocExtractedName.name.asc())
            ).scalars().all()
            sw_objs = s.execute(
                select(DocExtractedSoftware).order_by(
                    DocExtractedSoftware.software.asc()
                )
            ).scalars().all()
            names_by_doc: dict[int, list[str]] = {}
            for n in name_objs:
                names_by_doc.setdefault(n.document_id, []).append(f"{n.meta_field}: {n.name}")
            sw_by_doc: dict[int, list[str]] = {}
            for w in sw_objs:
                sw_by_doc.setdefault(w.document_id, []).append(f"{w.meta_field}: {w.software}")
            doc_rows = []
            doc_feed = []
            for r in docs:
                names = "; ".join(names_by_doc.get(r.id, [])) or "—"
                sw = "; ".join(sw_by_doc.get(r.id, [])) or "—"
                doc_rows.append([
                    r.title,
                    _hub_mime_short(r.mime),
                    _hub_size_human(r.size_bytes),
                    _fmt(r.created_at),
                    names,
                    sw,
                ])
                doc_feed.append({
                    "primary": r.title,
                    "secondary": f"{_hub_mime_short(r.mime)} · {_hub_size_human(r.size_bytes)}",
                    "added": _fmt(r.created_at),
                    "detail": [
                        ["Type", r.mime or "—"],
                        ["Size", _hub_size_human(r.size_bytes)],
                        ["Extracted names", names],
                        ["Software", sw],
                    ],
                })
            cats.append({
                "key": "docs",
                "label": "Documents & Exif",
                "count": len(docs),
                "last": _fmt(docs[0].created_at) if docs else "",
                "preview": [
                    {"primary": r.title, "secondary": _hub_mime_short(r.mime)}
                    for r in docs[:5]
                ],
                "table": {
                    "head": ["Title", "Type", "Size", "Added", "Extracted names", "Software"],
                    "rows": doc_rows,
                    "row_ids": [r.id for r in docs],
                },
                "subtables": [
                    {
                        "label": "Extracted Names",
                        "count": len(name_objs),
                        "head": ["Name", "Field", "Source document"],
                        "fields": sorted({n.meta_field for n in name_objs if n.meta_field}),
                        "rows": [
                            [n.name, n.meta_field, doc_titles.get(n.document_id, "—")]
                            for n in name_objs
                        ],
                    },
                    {
                        "label": "Extracted Software",
                        "count": len(sw_objs),
                        "head": ["Software", "Field", "Source document"],
                        "fields": sorted({w.meta_field for w in sw_objs if w.meta_field}),
                        "rows": [
                            [w.software, w.meta_field, doc_titles.get(w.document_id, "—")]
                            for w in sw_objs
                        ],
                    },
                ],
                "feed": doc_feed,
            })

            # --- DNS zone transfers --------------------------------------------
            dns_rows_db = s.execute(
                select(DnsZoneTransfer).order_by(
                    DnsZoneTransfer.domain.asc(), DnsZoneTransfer.nameserver.asc()
                )
            ).scalars().all()
            dns_by_domain: dict[str, list] = {}
            for r in dns_rows_db:
                dns_by_domain.setdefault(r.domain or "unknown", []).append(r)
            dns_table_rows = []
            dns_metas = []
            dns_feed = []
            for domain, recs in sorted(dns_by_domain.items()):
                ok = any(x.status == "SUCCESS" for x in recs)
                dns_table_rows.append([
                    domain,
                    ", ".join(x.nameserver for x in recs),
                    "SUCCESS" if ok else "blocked",
                ])
                # Per-domain payload for the hub sidebar (row click).
                dns_metas.append({
                    "domain": domain,
                    "records": [[x.nameserver, x.status] for x in recs],
                })
                dns_feed.append({
                    "primary": domain,
                    "secondary": f"{len(recs)} nameserver(s)" + (" — transfer OK" if ok else ""),
                    "added": _fmt(max(x.created_at for x in recs)),
                    "detail": [["Zone transfer", "SUCCESS" if ok else "blocked"]]
                    + [[x.nameserver, x.status] for x in recs],
                })
            cats.append({
                "key": "dns",
                "label": "DNS",
                "count": len(dns_by_domain),
                "last": _fmt(max((r.created_at for r in dns_rows_db), default=None)),
                "preview": [
                    {"primary": d, "secondary": f"{len(recs)} nameserver(s)"}
                    for d, recs in sorted(dns_by_domain.items())[:5]
                ],
                "table": {
                    "head": ["Domain", "Nameservers", "Status"],
                    "rows": dns_table_rows,
                    "row_metas": [_b64_json(m) for m in dns_metas],
                },
                "feed": dns_feed,
            })

            # --- SMTP -----------------------------------------------------------
            smtps = s.execute(
                select(SmtpScan).order_by(SmtpScan.mx_host.asc())
            ).scalars().all()
            smtp_table_rows = []
            smtp_feed = []
            for r in smtps:
                smtp_table_rows.append([
                    r.mx_host, r.vrfy or "—", r.expn or "—", r.rcpt or "—", _fmt(r.created_at),
                ])
                smtp_feed.append({
                    "primary": r.mx_host,
                    "secondary": f"VRFY {r.vrfy or '—'} · EXPN {r.expn or '—'}",
                    "added": _fmt(r.created_at),
                    "detail": [
                        ["VRFY", r.vrfy or "—"],
                        ["EXPN", r.expn or "—"],
                        ["RCPT", r.rcpt or "—"],
                    ],
                })
            cats.append({
                "key": "smtp",
                "label": "SMTP",
                "count": len(smtps),
                "last": _fmt(max((r.created_at for r in smtps), default=None)),
                "preview": [
                    {"primary": r.mx_host, "secondary": r.vrfy or "no VRFY data"}
                    for r in smtps[:5]
                ],
                "table": {
                    "head": ["MX Host", "VRFY", "EXPN", "RCPT", "Added"],
                    "rows": smtp_table_rows,
                },
                "feed": smtp_feed,
            })

            # --- Registrars (prowl data on subdomains + manual overrides) -------
            subs = s.execute(
                select(Subdomain).order_by(Subdomain.root_domain.asc(), Subdomain.fqdn.asc())
            ).scalars().all()
            reg_overrides = s.execute(
                select(RegistrarInfo).order_by(RegistrarInfo.domain)
            ).scalars().all()
            reg: dict[str, dict] = {}
            for sub in subs:
                if not (sub.prowl_ips or sub.prowl_registrar or sub.prowl_netblocks):
                    continue
                g = reg.setdefault(sub.root_domain, {
                    "registrar": "", "netblocks": "", "asn": "",
                    "creation_date": "", "expiration_date": "", "subs": 0,
                })
                g["subs"] += 1
                g["registrar"] = g["registrar"] or (sub.prowl_registrar or "")
                g["netblocks"] = g["netblocks"] or (sub.prowl_netblocks or "")
            for ri in reg_overrides:
                g = reg.setdefault(ri.domain, {
                    "registrar": "", "netblocks": "", "asn": "",
                    "creation_date": "", "expiration_date": "", "subs": 0,
                })
                g["registrar"] = ri.registrar or g["registrar"]
                g["netblocks"] = ri.netblocks or g["netblocks"]
                g["asn"] = ri.asn or ""
                g["creation_date"] = ri.creation_date or ""
                g["expiration_date"] = ri.expiration_date or ""
            hidden_roots = {
                e.domain
                for e in s.execute(select(RegistrarExclusion)).scalars().all()
            }
            effective_hidden = hidden_roots - {ri.domain for ri in reg_overrides}
            if effective_hidden:
                reg = {k: v for k, v in reg.items() if k not in effective_hidden}
            reg_table_rows = []
            reg_ids = []
            reg_feed = []
            for domain in sorted(reg):
                g = reg[domain]
                reg_ids.append(domain)
                reg_table_rows.append([
                    domain,
                    g["registrar"] or "—",
                    g["asn"] or "—",
                    g["netblocks"] or "—",
                    g["creation_date"] or "—",
                    g["expiration_date"] or "—",
                    g["subs"],
                ])
                reg_feed.append({
                    "primary": domain,
                    "secondary": g["registrar"] or "registrar unknown",
                    "added": "",
                    "detail": [
                        ["Registrar", g["registrar"] or "—"],
                        ["ASN", g["asn"] or "—"],
                        ["Netblocks", g["netblocks"] or "—"],
                        ["Created", g["creation_date"] or "—"],
                        ["Expires", g["expiration_date"] or "—"],
                        ["Subs with data", g["subs"]],
                    ],
                })
            cats.append({
                "key": "registrars",
                "label": "Registrars",
                "count": len(reg),
                "last": _fmt(max((ri.created_at for ri in reg_overrides), default=None)),
                "preview": [
                    {"primary": d, "secondary": reg[d]["registrar"] or "registrar unknown"}
                    for d in sorted(reg)[:5]
                ],
                "table": {
                    "head": ["Domain", "Registrar", "ASN", "Netblocks", "Created", "Expires", "Subs"],
                    "rows": reg_table_rows,
                    "row_ids": reg_ids,
                },
                "feed": reg_feed,
            })

        return {
            "categories": cats,
            "total": sum(c["count"] for c in cats),
            "hidden_registrars": sorted(effective_hidden),
        }

    @router.get("/osint/hub", response_class=HTMLResponse)
    def osint_hub(request: Request):
        """OSINT hub: single dossier-accordion page unifying all OSINT categories."""
        hub = _osint_hub_context(st)
        return st.templates.TemplateResponse(
            "osint_hub.html",
            {"request": request, "hub": hub},
        )

    return router
