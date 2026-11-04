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

    @router.get("/assets", response_class=HTMLResponse)
    def assets(request: Request):
        show_out = int(request.query_params.get("show_out", "0"))
        hide_completed = int(request.query_params.get("hide_completed", "0"))
        hide_zero_services = int(request.query_params.get("hide_zero_services", "0"))
        tag_filter = request.query_params.get("tag_filter", "").strip().lower()
        row_limit_raw = (request.query_params.get("row_limit", "0") or "0").strip()
        try:
            row_limit = max(0, int(row_limit_raw))
        except ValueError:
            row_limit = 0

        page_raw = (request.query_params.get("page", "1") or "1").strip()
        try:
            page = max(1, int(page_raw))
        except ValueError:
            page = 1
        page_size = 200 if row_limit == 0 else 0

        def subnet_sort_key(net):
            return (net.version, int(net.network_address), net.prefixlen)

        with st.db() as s:
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs, s_domain_subs_if_ip, s_excluded = (
                scope_sets(s, sensitive_only=True)
            )
            scope_is_empty = not bool(ips or subnets or domains)
            total_hosts = s.execute(select(func.count(Host.id))).scalar() or 0

            q = select(
                Host.id,
                Host.ip,
                Host.hostname,
                Host.done,
                Host.complete,
                Host.inprogress,
                Host.waf,
                Host.tag,
                func.count(Service.id).label("svc_count"),
            ).outerjoin(Service, Service.host_id == Host.id).group_by(Host.id).order_by(func.count(Service.id).desc(), Host.ip.asc())
            rows = s.execute(q).all()
            all_host_domains = list_all_host_domains(s)
            domains_by_host = {r.id: all_host_domains.get(r.id, []) for r in rows}
            all_ips = {r.id: r.ip for r in rows}
        data = []
        for r in rows:
            ip_in = ip_in_scope(r.ip, ips, subnets, excluded)
            ip_sensitive = ip_in_scope(r.ip, s_ips, s_subnets, s_excluded)
            host_domains = domains_by_host.get(r.id, [])
            hostname_domain = _hostname_as_domain(r.hostname)
            if hostname_domain and hostname_domain not in host_domains:
                host_domains = sorted([*host_domains, hostname_domain])
            # Check scope for each individual domain
            domain_list = []
            any_domain_in = False
            any_domain_sensitive = False
            for d in host_domains:
                d_in = domain_in_scope(
                    d, domains, domain_all_subs, domain_subs_if_ip, [r.ip], ips, subnets, excluded
                )
                d_sensitive = domain_in_scope(
                    d,
                    s_domains,
                    s_domain_all_subs,
                    s_domain_subs_if_ip,
                    [r.ip],
                    s_ips,
                    s_subnets,
                    s_excluded,
                )
                if d_in:
                    any_domain_in = True
                if d_sensitive:
                    any_domain_sensitive = True
                domain_list.append(
                    {"fqdn": d, "in_scope": d_in, "sensitive": d_sensitive}
                )
            data.append(
                {
                    "id": r.id,
                    "ip": r.ip,
                    "hostname": r.hostname,
                    "done": getattr(r, "done", 0),
                    "complete": getattr(r, "complete", 0),
                    "inprogress": getattr(r, "inprogress", 0),
                    "waf": getattr(r, "waf", 0),
                    "tag": getattr(r, "tag", ""),
                    "svc_count": r.svc_count,
                    "ip_in_scope": ip_in,
                    "ip_sensitive": ip_sensitive,
                    "domain_in_scope": any_domain_in,
                    "in_scope": ip_in or any_domain_in,
                    "sensitive": ip_sensitive or any_domain_sensitive,
                    "domains": domain_list,
                }
            )

        compromised_ids = st._topology_compromised_ids()
        compromised_asset_ids = compromised_ids.get("asset_ids", set()) if compromised_ids else set()

        # Build asset_id -> topology_node_id mapping for row-level topo buttons
        topology_asset_node_ids: dict[str, str] = {}
        with st.db() as s:
            topo_row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "topology_map", Note.object_id == 0)
                    .order_by(Note.updated_at.desc(), Note.id.desc())
                )
                .scalars()
                .first()
            )
            if topo_row and (topo_row.body or "").strip():
                try:
                    topo_data = json.loads(topo_row.body)
                    for n in (topo_data.get("nodes") or []):
                        aid = n.get("linked_asset_id")
                        if aid:
                            topology_asset_node_ids[str(aid)] = n.get("id", "")
                except Exception:
                    pass

        available_tags = sorted(
            {
                str(d.get("tag") or "").strip().lower()
                for d in data
                if str(d.get("tag") or "").strip()
            }
        )
        in_scope_data = [d for d in data if d.get("in_scope")]
        filtered_data = data if show_out == 1 else in_scope_data
        if hide_completed == 1:
            filtered_data = [d for d in filtered_data if int(d.get("complete", 0)) != 1]
        if hide_zero_services == 1:
            filtered_data = [d for d in filtered_data if int(d.get("svc_count", 0)) > 0]
        if tag_filter:
            filtered_data = [
                d
                for d in filtered_data
                if str(d.get("tag") or "").strip().lower() == tag_filter
            ]
        filtered_total = len(filtered_data)
        if row_limit == 0:
            page_count = max(1, (filtered_total + page_size - 1) // page_size)
            page = min(page, page_count)
            offset = (page - 1) * page_size
            page_rows = filtered_data[offset : offset + page_size]
        else:
            page_count = 1
            page = 1
            page_rows = filtered_data[:row_limit]

        sorted_subnets = sorted(subnets, key=subnet_sort_key)
        subnet_stats: dict[str, int] = {str(net): 0 for net in sorted_subnets}
        inferred_stats: dict[str, int] = {}

        def infer_network(ip_obj):
            if ip_obj.version == 4:
                return ipaddress.ip_network(f"{ip_obj}/24", strict=False)
            return ipaddress.ip_network(f"{ip_obj}/64", strict=False)

        def classify_subnet_label(ip_str: str, allow_infer: bool):
            try:
                ip_obj = ipaddress.ip_address(ip_str or "")
            except ValueError:
                return None
            matches = [n for n in sorted_subnets if ip_obj in n]
            if matches:
                best = max(matches, key=lambda n: n.prefixlen)
                return str(best)
            if allow_infer:
                inferred = infer_network(ip_obj)
                prefix_name = "Inferred /24" if ip_obj.version == 4 else "Inferred /64"
                return f"{prefix_name}: {inferred}"
            return None

        # Build subnet stats from ALL hosts, not just the current page
        all_in_scope_ips = []
        for hid, hip in all_ips.items():
            if ip_in_scope(hip, ips, subnets, excluded):
                all_in_scope_ips.append(hip)
        for ip_str in all_in_scope_ips:
            label = classify_subnet_label(ip_str, allow_infer=True)
            if not label:
                continue
            if label in subnet_stats:
                subnet_stats[label] = subnet_stats.get(label, 0) + 1
            else:
                inferred_stats[label] = inferred_stats.get(label, 0) + 1

        grouped: dict[str, list[dict]] = {}
        for row in page_rows:
            group_name = "Unscoped / Other"
            label = classify_subnet_label(row.get("ip", ""), allow_infer=True)
            if label:
                group_name = label
            elif row.get("in_scope"):
                group_name = "Scoped IPs (No Subnet)"

            grouped.setdefault(group_name, []).append(row)

        ordered_group_names = [str(n) for n in sorted_subnets if str(n) in grouped]
        inferred_group_names = sorted(
            [name for name in grouped if name.startswith("Inferred /")],
            key=lambda name: subnet_sort_key(
                ipaddress.ip_network(name.split(": ", 1)[1], strict=False)
            ),
        )
        ordered_group_names.extend(inferred_group_names)
        if "Scoped IPs (No Subnet)" in grouped:
            ordered_group_names.append("Scoped IPs (No Subnet)")
        if "Unscoped / Other" in grouped:
            ordered_group_names.append("Unscoped / Other")

        grouped_ordered = {name: grouped[name] for name in ordered_group_names}

        subnet_stats_list = [{"subnet": k, "count": v} for k, v in subnet_stats.items()]
        for k in sorted(
            inferred_stats.keys(),
            key=lambda name: subnet_sort_key(
                ipaddress.ip_network(name.split(": ", 1)[1], strict=False)
            ),
        ):
            subnet_stats_list.append({"subnet": k, "count": inferred_stats[k]})

        shown_count = sum(len(v) for v in grouped_ordered.values())

        def page_url(p: int) -> str:
            params = [
                (k, v)
                for k, v in parse_qsl(request.url.query, keep_blank_values=True)
                if k != "page"
            ]
            p = max(1, int(p))
            if p > 1:
                params.append(("page", str(p)))
            return ("?" + urlencode(params)) if params else ""

        return st.templates.TemplateResponse(
            "assets.html",
            {
                "request": request,
                "grouped": grouped_ordered,
                "show_out": show_out,
                "hide_completed": hide_completed,
                "hide_zero_services": hide_zero_services,
                "tag_filter": tag_filter,
                "available_tags": available_tags,
                "row_limit": row_limit,
                "shown_count": shown_count,
                "total_count": filtered_total,
                "page_count": page_count,
                "page_url": page_url,
                "subnet_stats": subnet_stats_list,
                "in_scope_total": len(all_in_scope_ips),
                "scope_is_empty": scope_is_empty,
                "compromised_asset_ids": compromised_asset_ids,
                "topology_asset_node_ids": topology_asset_node_ids,
                "page": page,
                "page_size": page_size,
                "total_hosts": total_hosts,
            },
        )

    @router.post("/api/host/create")
    def api_host_create(
        ip: str = Form(...), hostname: str = Form(""), tag: str = Form(""), domains_raw: str = Form("")
    ):
        ip = ip.strip()
        hostname = (hostname or "").strip()
        tag = (tag or "").strip()
        domains = [
            ln.strip().lower().rstrip(".")
            for ln in (domains_raw or "").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        hostname_domain = _hostname_as_domain(hostname)
        if hostname_domain and hostname_domain not in domains:
            domains.append(hostname_domain)
        with st.db() as s:
            # Check for duplicate IP
            existing = s.scalar(select(Host).where(Host.ip == ip))
            if existing:
                return {"ok": False, "error": f"IP {ip} already exists as an asset."}

            try:
                host = Host(ip=ip, hostname=hostname, os_guess="")
                s.add(host)
                s.flush()
                host.tag = tag
                for d in domains:
                    if DOMAIN_RE.match(d):
                        link_host_domain(s, host.id, d, commit=False)
                s.commit()
            except Exception as e:
                s.rollback()
                return {"ok": False, "error": str(e)}
        return {"ok": True}

    # Sidebar APIs

    @router.post("/api/note/add")
    def api_note_add(
        object_type: str = Form(...),
        object_id: int = Form(...),
        severity: str = Form("info"),
        tags: str = Form(""),
        body: str = Form(...),
    ):
        object_type = (object_type or "").strip().lower()
        severity = (severity or "info").strip().lower()
        tags = (tags or "").strip()
        body = (body or "").strip()
        if not body:
            return JSONResponse({"ok": False, "error": "empty body"}, status_code=400)
        if severity not in ("info", "low", "med", "medium", "high", "critical"):
            severity = "info"
        if severity == "medium":
            severity = "med"
        with st.db() as s:
            n = Note(
                object_type=object_type[:32],
                object_id=int(object_id),
                severity=severity[:16],
                tags=tags[:255],
                body=body,
            )
            s.add(n)
            s.commit()
            return {"ok": True, "id": n.id}

    @router.post("/api/note/delete")
    def api_note_delete(note_id: int = Form(...)):
        with st.db() as s:
            n = s.scalar(select(Note).where(Note.id == note_id))
            if not n:
                return JSONResponse({"ok": False}, status_code=404)
            s.delete(n)
            s.commit()
        return {"ok": True}

    @router.get("/api/global-notes")
    def api_global_notes_get():
        with st.db() as s:
            row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "global_panel", Note.object_id == 0)
                    .order_by(Note.updated_at.desc(), Note.id.desc())
                )
                .scalars()
                .first()
            )
        if not row:
            return {"ok": True, "note": "", "updated_at": ""}
        return {
            "ok": True,
            "note": row.body or "",
            "updated_at": row.updated_at.isoformat() if row.updated_at else "",
        }

    @router.post("/api/global-notes")
    def api_global_notes_save(note: str = Form("")):
        note = note or ""
        with st.db() as s:
            row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "global_panel", Note.object_id == 0)
                    .order_by(Note.updated_at.desc(), Note.id.desc())
                )
                .scalars()
                .first()
            )
            if row:
                row.body = note
                row.updated_at = datetime.utcnow()
            else:
                row = Note(
                    object_type="global_panel",
                    object_id=0,
                    severity="info",
                    tags="global",
                    body=note,
                )
                s.add(row)
            s.commit()
        return {"ok": True}

    @router.get("/api/global-notes-table")
    def api_global_notes_table_get():
        with st.db() as s:
            rows = (
                s.execute(
                    select(GlobalNote).order_by(GlobalNote.order_index.asc())
                )
                .scalars()
                .all()
            )
        return {
            "ok": True,
            "rows": [
                {
                    "id": r.id,
                    "title": r.title or "",
                    "body": r.body or "",
                    "order_index": r.order_index,
                }
                for r in rows
            ],
        }

    @router.post("/api/global-notes-table")
    def api_global_notes_table_create(
        title: str = Form(""),
        body: str = Form(""),
    ):
        with st.db() as s:
            max_idx = (
                s.execute(
                    select(func.max(GlobalNote.order_index))
                )
                .scalar()
                or -1
            )
            row = GlobalNote(
                title=title,
                body=body,
                order_index=max_idx + 1,
            )
            s.add(row)
            s.commit()
            rid = row.id
        return {"ok": True, "id": rid}

    @router.patch("/api/global-notes-table/{note_id}")
    def api_global_notes_table_update(
        note_id: int,
        title: str = Form(""),
        body: str = Form(""),
    ):
        with st.db() as s:
            row = s.scalar(select(GlobalNote).where(GlobalNote.id == note_id))
            if row:
                row.title = title
                row.body = body
                s.commit()
        return {"ok": True}

    @router.delete("/api/global-notes-table/{note_id}")
    def api_global_notes_table_delete(note_id: int):
        with st.db() as s:
            row = s.scalar(select(GlobalNote).where(GlobalNote.id == note_id))
            if row:
                s.delete(row)
                s.commit()
        return {"ok": True}

    @router.get("/api/timeline")
    def api_timeline_get():
        with st.db() as s:
            days = (
                s.execute(
                    select(TimelineDay).order_by(TimelineDay.day_date.asc())
                )
                .scalars()
                .all()
            )
            result = []
            for day in days:
                entries = (
                    s.execute(
                        select(TimelineEntry)
                        .where(TimelineEntry.day_id == day.id)
                        .order_by(TimelineEntry.order_index.asc())
                    )
                    .scalars()
                    .all()
                )
                result.append({
                    "id": day.id,
                    "day_date": day.day_date,
                    "entries": [
                        {
                            "id": e.id,
                            "content": e.content,
                            "order_index": e.order_index,
                        }
                        for e in entries
                    ],
                })
        return {"days": result}

    @router.post("/api/timeline/day")
    def api_timeline_day_create(day_date: str = Form("")):
        with st.db() as s:
            max_idx = s.scalar(select(func.max(TimelineDay.id))) or 0
            day = TimelineDay(day_date=day_date[:10] if day_date else "")
            s.add(day)
            s.commit()
            day_id = day.id
        return {"ok": True, "id": day_id}

    @router.patch("/api/timeline/day/{day_id}")
    def api_timeline_day_update(day_id: int, day_date: str = Form("")):
        with st.db() as s:
            day = s.scalar(select(TimelineDay).where(TimelineDay.id == day_id))
            if day:
                day.day_date = day_date[:10] if day_date else ""
                s.commit()
        return {"ok": True}

    @router.delete("/api/timeline/day/{day_id}")
    def api_timeline_day_delete(day_id: int):
        with st.db() as s:
            day = s.scalar(select(TimelineDay).where(TimelineDay.id == day_id))
            if day:
                s.delete(day)
                s.commit()
        return {"ok": True}

    @router.post("/api/timeline/entry")
    def api_timeline_entry_create(
        day_id: str = Form(""),
        content: str = Form(""),
    ):
        with st.db() as s:
            did = int(day_id) if day_id else 0
            max_idx = s.scalar(
                select(func.max(TimelineEntry.order_index)).where(TimelineEntry.day_id == did)
            )
            idx = (max_idx or -1) + 1
            entry = TimelineEntry(day_id=did, content=content[:10000], order_index=idx)
            s.add(entry)
            s.commit()
            entry_id = entry.id
            return {"ok": True, "id": entry_id, "order_index": idx, "content": entry.content}
        return {"ok": False}

    @router.patch("/api/timeline/entry/{entry_id}")
    def api_timeline_entry_update(entry_id: int, content: str = Form("")):
        with st.db() as s:
            entry = s.scalar(select(TimelineEntry).where(TimelineEntry.id == entry_id))
            if entry:
                entry.content = content[:10000] if content else ""
                s.commit()
        return {"ok": True}

    @router.delete("/api/timeline/entry/{entry_id}")
    def api_timeline_entry_delete(entry_id: int):
        with st.db() as s:
            entry = s.scalar(select(TimelineEntry).where(TimelineEntry.id == entry_id))
            if entry:
                s.delete(entry)
                s.commit()
        return {"ok": True}

    @router.get("/api/host/{host_id}")
    def api_host(host_id: int):
        with st.db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host:
                return JSONResponse({"ok": False}, status_code=404)

            services = (
                s.execute(
                    select(Service)
                    .where(Service.host_id == host_id)
                    .order_by(Service.port.asc())
                )
                .scalars()
                .all()
            )
            domains = list_host_domains(s, host_id)

            notes = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "host", Note.object_id == host_id)
                    .order_by(Note.created_at.desc())
                )
                .scalars()
                .all()
            )

        # Highest severity (for UI tint)
        sev_rank = {"info": 1, "low": 2, "med": 3, "high": 4}
        highest_severity = None
        for n in notes:
            sv = (n.severity or "info").lower()
            if highest_severity is None or sev_rank.get(sv, 0) > sev_rank.get(
                highest_severity, 0
            ):
                highest_severity = sv
        return {
            "ok": True,
            "highest_severity": highest_severity,
                "host": {
                    "id": host.id,
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "os_guess": host.os_guess,
                    "tag": host.tag,
                },
            "domains": domains,
            "services": [
                {
                    "id": sv.id,
                    "port": sv.port,
                    "proto": sv.proto,
                    "state": sv.state,
                    "service_name": sv.service_name,
                    "inspected": int(sv.inspected or 0),
                    "product": sv.product,
                    "version": sv.version,
                }
                for sv in services
            ],
            "notes": [
                {
                    "id": n.id,
                    "created_at": n.created_at.isoformat() if n.created_at else "",
                    "severity": n.severity,
                    "tags": n.tags,
                    "body": n.body,
                }
                for n in notes
            ],
        }

    @router.get("/api/hosts/list")
    def api_hosts_list():
        with st.db() as s:
            hosts = s.execute(select(Host).order_by(Host.ip.asc())).scalars().all()
        compromised_ids = st._topology_compromised_ids()
        compromised_asset_ids = compromised_ids.get("asset_ids", set()) if compromised_ids else set()
        return {
            "ok": True,
            "hosts": [
                {
                    "id": h.id,
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "os_guess": h.os_guess,
                    "compromised": str(h.id) in compromised_asset_ids,
                }
                for h in hosts
            ],
        }

    @router.get("/api/hosts/{host_id}")
    def api_host_detail(host_id: int):
        with st.db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host:
                return JSONResponse({"ok": False, "error": "Host not found"}, status_code=404)
            
            services = s.execute(
                select(Service).where(Service.host_id == host.id)
            ).scalars().all()

            host_findings = s.execute(
                select(ServiceFinding).where(
                    ServiceFinding.host_id == host.id,
                    ServiceFinding.service_id.is_(None),
                )
            ).scalars().all()

            return {
                "ok": True,
                "host": {
                    "id": host.id,
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "os": host.os_guess,
                    "status": "active",
                    "services": [
                        {
                            "id": svc.id,
                            "port": svc.port,
                            "protocol": svc.proto,
                            "service": svc.service_name,
                            "version": svc.version,
                        }
                        for svc in services
                    ],
                    "findings": [
                        {
                            "script": f.script_name,
                            "kind": f.kind,
                            "severity": f.severity,
                            "title": f.title,
                            "detail": f.detail,
                            "cves": f.cves,
                        }
                        for f in sorted(
                            host_findings,
                            key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.title),
                        )
                    ],
                    "tags": [t.strip() for t in host.tag.split(",") if t.strip()],
                },
            }

    @router.post("/api/host/tag/delete")
    def api_host_tag_delete(host_id: int = Form(...), tag: str = Form(...)):
        with st.db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host or not host.tag:
                return JSONResponse({"ok": False}, status_code=404)
            
            tags = [t.strip() for t in host.tag.split(",") if t.strip()]
            if tag in tags:
                tags.remove(tag)
                host.tag = ",".join(tags)
                s.commit()
                return {"ok": True}
            return JSONResponse({"ok": False, "error": "Tag not found"}, status_code=404)

    @router.post("/api/host/update")
    def api_host_update(
        host_id: int = Form(...),
        ip: str = Form(...),
        hostname: str = Form(""),
        os_guess: str = Form(""),
        tag: str = Form(""),
        domains_raw: str = Form(""),
    ):
        ip = ip.strip()
        hostname = (hostname or "").strip()
        os_guess = (os_guess or "").strip()
        tag = (tag or "").strip()
        domains = [
            ln.strip().lower().rstrip(".")
            for ln in (domains_raw or "").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        hostname_domain = _hostname_as_domain(hostname)
        if hostname_domain and hostname_domain not in domains:
            domains.append(hostname_domain)
        with st.db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host:
                return JSONResponse({"ok": False, "error": "Host not found"}, status_code=404)

            try:
                # Check for duplicate IP on another host
                if ip != host.ip:
                    clash = s.scalar(select(Host).where(Host.ip == ip, Host.id != host_id))
                    if clash:
                        return {"ok": False, "error": f"IP {ip} already belongs to another host."}

                host.ip = ip
                host.hostname = hostname
                host.os_guess = os_guess
                host.tag = tag

                existing_domains = list_host_domains(s, host.id)
                # Remove domains no longer in the list
                for d in existing_domains:
                    if d not in domains:
                        s.execute(
                            text(
                                "DELETE FROM host_subdomains WHERE host_id = :hid AND subdomain_id = (SELECT id FROM subdomains WHERE fqdn = :fq)"
                            ),
                            {"hid": host.id, "fq": d},
                        )
                # Add new domains
                for d in domains:
                    if DOMAIN_RE.match(d):
                        link_host_domain(s, host.id, d, commit=False)

                s.commit()
            except Exception as e:
                s.rollback()
                return {"ok": False, "error": f"Failed to save host: {e}"}

        return {"ok": True}

    @router.get("/api/service/{service_id}")
    def api_service(service_id: int):
        with st.db() as s:
            svc = s.scalar(select(Service).where(Service.id == service_id))
            if not svc:
                return JSONResponse({"ok": False}, status_code=404)
            host = s.scalar(select(Host).where(Host.id == svc.host_id))
            from sqlalchemy.orm import joinedload

            evidence = (
                s.execute(
                    select(ServiceEvidence)
                    .options(joinedload(ServiceEvidence.artifact))
                    .where(ServiceEvidence.service_id == service_id)
                    .order_by(ServiceEvidence.created_at.desc())
                )
                .scalars()
                .all()
            )
        return {
            "ok": True,
            "host": {"id": host.id, "ip": host.ip, "hostname": host.hostname}
            if host
            else None,
            "service": {
                "id": svc.id,
                "port": svc.port,
                "proto": svc.proto,
                "state": svc.state,
                "service_name": svc.service_name,
                "product": svc.product,
                "version": svc.version,
                "extra_info": svc.extra_info,
            },
            "evidence": [
                {
                    "id": ev.id,
                    "created_at": str(ev.created_at),
                    "raw_output": ev.raw_output,
                    "source": ev.artifact.filename if ev.artifact else "",
                }
                for ev in evidence
            ],
        }

    @router.post("/api/service/create")
    def api_service_create(
        host_id: int = Form(...),
        port: int = Form(...),
        proto: str = Form("tcp"),
        state: str = Form("open"),
        service_name: str = Form(""),
        product: str = Form(""),
        version: str = Form(""),
        extra_info: str = Form(""),
        raw_output: str = Form(""),
    ):
        proto = (proto or "tcp").strip().lower()[:8]
        state = (state or "open").strip().lower()[:16]
        service_name = (service_name or "").strip()
        product = (product or "").strip()
        version = (version or "").strip()
        extra_info = (extra_info or "").strip()
        raw_output = (raw_output or "").strip()

        if port <= 0 or port > 65535:
            return JSONResponse(
                {"ok": False, "error": "Port must be 1-65535"}, status_code=400
            )

        with st.db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host:
                return JSONResponse(
                    {"ok": False, "error": "Host not found"}, status_code=404
                )

            svc = s.scalar(
                select(Service).where(
                    Service.host_id == host_id,
                    Service.port == port,
                    Service.proto == proto,
                )
            )

            if not svc:
                svc = Service(
                    host_id=host_id,
                    port=port,
                    proto=proto,
                    state=state or "open",
                    service_name=service_name,
                    product=product,
                    version=version,
                    extra_info=extra_info,
                )
                s.add(svc)
                s.flush()
            else:
                svc.state = state or svc.state
                svc.service_name = service_name or svc.service_name
                svc.product = product or svc.product
                svc.version = version or svc.version
                svc.extra_info = extra_info or svc.extra_info

            if raw_output:
                manual_dir = st.ws.uploads_dir / "manual_evidence"
                manual_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
                ev_path = manual_dir / f"service-{host_id}-{port}-{proto}-{stamp}.txt"
                ev_path.write_text(raw_output, encoding="utf-8", errors="replace")
                art = upsert_artifact(s, "service-evidence", ev_path)
                s.add(
                    ServiceEvidence(
                        service_id=svc.id,
                        artifact_id=art.id,
                        raw_output=raw_output,
                    )
                )

            s.commit()
            return {"ok": True, "service_id": svc.id}

    @router.post("/api/service/update")
    def api_service_update(
        service_id: int = Form(...),
        port: int = Form(...),
        proto: str = Form("tcp"),
        state: str = Form("open"),
        service_name: str = Form(""),
        product: str = Form(""),
        version: str = Form(""),
        extra_info: str = Form(""),
        raw_output: str = Form(""),
    ):
        proto = (proto or "tcp").strip().lower()[:8]
        state = (state or "open").strip().lower()[:16]
        service_name = (service_name or "").strip()
        product = (product or "").strip()
        version = (version or "").strip()
        extra_info = (extra_info or "").strip()
        raw_output = (raw_output or "").strip()

        if port <= 0 or port > 65535:
            return JSONResponse(
                {"ok": False, "error": "Port must be 1-65535"}, status_code=400
            )

        with st.db() as s:
            svc = s.scalar(select(Service).where(Service.id == service_id))
            if not svc:
                return JSONResponse(
                    {"ok": False, "error": "Service not found"}, status_code=404
                )

            clash = s.scalar(
                select(Service).where(
                    Service.host_id == svc.host_id,
                    Service.port == port,
                    Service.proto == proto,
                    Service.id != svc.id,
                )
            )
            if clash:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": "Another service already exists for this host+port+proto",
                    },
                    status_code=400,
                )

            svc.port = port
            svc.proto = proto
            svc.state = state
            svc.service_name = service_name
            svc.product = product
            svc.version = version
            svc.extra_info = extra_info

            if raw_output:
                manual_dir = st.ws.uploads_dir / "manual_evidence"
                manual_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
                ev_path = (
                    manual_dir / f"service-{svc.host_id}-{port}-{proto}-{stamp}.txt"
                )
                ev_path.write_text(raw_output, encoding="utf-8", errors="replace")
                art = upsert_artifact(s, "service-evidence", ev_path)
                s.add(
                    ServiceEvidence(
                        service_id=svc.id,
                        artifact_id=art.id,
                        raw_output=raw_output,
                    )
                )

            s.commit()
            return {"ok": True, "service_id": svc.id}

    @router.get("/service/{service_id}", response_class=HTMLResponse)
    def service_page(request: Request, service_id: int):
        with st.db() as s:
            svc = s.scalar(select(Service).where(Service.id == service_id))
            if not svc:
                return HTMLResponse("Service not found", status_code=404)
            host = s.scalar(select(Host).where(Host.id == svc.host_id))
            from sqlalchemy.orm import joinedload

            evidence = (
                s.execute(
                    select(ServiceEvidence)
                    .options(joinedload(ServiceEvidence.artifact))
                    .where(ServiceEvidence.service_id == service_id)
                    .order_by(ServiceEvidence.created_at.desc())
                )
                .scalars()
                .all()
            )
            notes = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "service", Note.object_id == service_id)
                    .order_by(Note.created_at.desc())
                )
                .scalars()
                .all()
            )
        return st.templates.TemplateResponse(
            "service_detail.html",
            {
                "request": request,
                "host": host,
                "svc": svc,
                "evidence": [
                    {
                        "created_at": str(e.created_at),
                        "raw_output": e.raw_output,
                        "source": e.artifact.filename if e.artifact else "",
                    }
                    for e in evidence
                ],
                "notes": [
                    {
                        "created_at": str(n.created_at),
                        "severity": n.severity,
                        "tags": n.tags,
                        "body": n.body,
                    }
                    for n in notes
                ],
            },
        )

    return router
