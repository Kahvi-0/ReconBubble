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

    @router.get("/topology", response_class=HTMLResponse)
    def topology_page(request: Request):
        return st.templates.TemplateResponse("topology.html", {"request": request})

    @router.get("/api/topology")
    def api_topology_get():
        with st.db() as s:
            row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "topology_map", Note.object_id == 0)
                    .order_by(Note.updated_at.desc(), Note.id.desc())
                )
                .scalars()
                .first()
            )
        data = {"nodes": [], "edges": []}
        if row and (row.body or "").strip():
            try:
                raw = json.loads(row.body)
                if isinstance(raw.get("nodes"), list):
                    data["nodes"] = raw.get("nodes")
                if isinstance(raw.get("edges"), list):
                    data["edges"] = raw.get("edges")
            except Exception:
                pass
        return {"ok": True, "map": data}

    @router.post("/api/topology")
    async def api_topology_save(request: Request):
        body = await request.json()
        nodes = body.get("nodes") if isinstance(body.get("nodes"), list) else []
        edges = body.get("edges") if isinstance(body.get("edges"), list) else []
        payload = json.dumps({"nodes": nodes, "edges": edges})

        with st.db() as s:
            row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "topology_map", Note.object_id == 0)
                    .order_by(Note.updated_at.desc(), Note.id.desc())
                )
                .scalars()
                .first()
            )

            current_name_nodes = {}
            for n in nodes:
                if n.get("type") == "user":
                    linked_name_id = str(n.get("linked_name_id") or "").strip()
                    if linked_name_id:
                        current_name_nodes[linked_name_id] = str(n.get("id") or "")

            if current_name_nodes:
                linked_ids = [int(k) for k in current_name_nodes if str(k).isdigit()]
                if linked_ids:
                    for ni in s.execute(
                        select(NameItem).where(NameItem.id.in_(linked_ids))
                    ).scalars().all():
                        expected = current_name_nodes.get(str(ni.id), "")
                        if (ni.topology_node_id or "") != expected:
                            ni.topology_node_id = expected

            for ni in s.execute(
                select(NameItem).where(NameItem.topology_node_id != "")
            ).scalars().all():
                if str(ni.id) not in current_name_nodes:
                    ni.topology_node_id = ""

            _update_compromised_cache(s, nodes)

            if row:
                row.body = payload
                row.updated_at = datetime.utcnow()
            else:
                s.add(
                    Note(
                        object_type="topology_map",
                        object_id=0,
                        severity="info",
                        tags="topology",
                        body=payload,
                    )
                )
            s.commit()
        return {"ok": True}

    def _topology_compromised_ids():
        """Read cached compromised IDs from topology."""
        result = {"asset_ids": set(), "name_ids": set()}
        with st.db() as s:
            row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "topology_compromised", Note.object_id == 0)
                    .order_by(Note.id.desc())
                )
                .scalars()
                .first()
            )
            if row and row.body:
                try:
                    data = json.loads(row.body)
                    result["asset_ids"] = {str(a) for a in data.get("asset_ids", [])}
                    result["name_ids"] = {str(n) for n in data.get("name_ids", [])}
                except Exception:
                    pass
        return result

    def _update_compromised_cache(s, nodes):
        """Rebuild the compromised ID cache from node list."""
        c_asset = set()
        c_name = set()
        for n in (nodes or []):
            if n.get("compromised"):
                ntype = (n.get("type") or "").lower()
                aid = n.get("linked_asset_id")
                if aid and ntype in ("computer", "domain"):
                    c_asset.add(str(aid))
                nid = n.get("linked_name_id")
                if nid:
                    c_name.add(str(nid))
        comp_payload = json.dumps({"asset_ids": list(c_asset), "name_ids": list(c_name)})
        comp_row = (
            s.execute(
                select(Note)
                .where(Note.object_type == "topology_compromised", Note.object_id == 0)
                .order_by(Note.id.desc())
            )
            .scalars()
            .first()
        )
        if comp_row:
            comp_row.body = comp_payload
            comp_row.updated_at = datetime.utcnow()
        else:
            s.add(
                Note(
                    object_type="topology_compromised",
                    object_id=0,
                    severity="info",
                    tags="topology",
                    body=comp_payload,
                )
            )

    @router.post("/api/topology/add-node")
    async def api_topology_add_node(request: Request):
        body = await request.json()
        asset_id = body.get("asset_id")
        hostname = body.get("hostname", "unknown")
        ip = body.get("ip", "")

        # Load current topology
        with st.db() as s:
            row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "topology_map", Note.object_id == 0)
                    .order_by(Note.updated_at.desc(), Note.id.desc())
                )
                .scalars()
                .first()
            )
            data = {"nodes": [], "edges": []}
            if row and (row.body or "").strip():
                try:
                    raw = json.loads(row.body)
                    if isinstance(raw.get("nodes"), list):
                        data["nodes"] = raw.get("nodes")
                    if isinstance(raw.get("edges"), list):
                        data["edges"] = raw.get("edges")
                except Exception:
                    pass

            # Generate unique node ID
            import time
            node_id = f"n_asset_{asset_id}_{int(time.time())}"

            # Check if node for this asset already exists
            existing = [n for n in data["nodes"] if n.get("linked_asset_id") == asset_id]
            if existing:
                return {"ok": False, "error": "Node for this asset already exists in topology"}

            new_node = {
                "id": node_id,
                "label": f"{hostname} ({ip})" if hostname != "unknown" else ip,
                "type": "computer",
                "color": "#4a90d9",
                "notes": "",
                "compromised": False,
                "linked_asset_id": asset_id,
                "x": 400,
                "y": 300,
            }
            data["nodes"].append(new_node)

            _update_compromised_cache(s, data["nodes"])
            payload = json.dumps(data)
            if row:
                row.body = payload
                row.updated_at = datetime.utcnow()
            else:
                s.add(
                    Note(
                        object_type="topology_map",
                        object_id=0,
                        severity="info",
                        tags="topology",
                        body=payload,
                    )
                )
            s.commit()

        return {"ok": True, "node": new_node}

    @router.post("/api/topology/add-domain")
    async def api_topology_add_domain(request: Request):
        body = await request.json()
        domain = body.get("domain", "").strip()
        asn = body.get("asn", "").strip()
        registrar = body.get("registrar", "").strip()
        netblocks = body.get("netblocks", "").strip()
        subdomain_ips = body.get("subdomain_ips", "").strip()
        if not domain:
            return {"ok": False, "error": "Domain is required"}

        with st.db() as s:
            row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "topology_map", Note.object_id == 0)
                    .order_by(Note.updated_at.desc(), Note.id.desc())
                )
                .scalars()
                .first()
            )
            data = {"nodes": [], "edges": []}
            if row and (row.body or "").strip():
                try:
                    raw = json.loads(row.body)
                    if isinstance(raw.get("nodes"), list):
                        data["nodes"] = raw.get("nodes")
                    if isinstance(raw.get("edges"), list):
                        data["edges"] = raw.get("edges")
                except Exception:
                    pass

            existing = [n for n in data["nodes"] if n.get("label") == domain and n.get("type") == "domain"]
            if existing:
                return {"ok": False, "error": f"Domain node \"{domain}\" already exists in topology"}

            import time
            node_id = f"n_domain_{domain.replace('.', '_')}_{int(time.time())}"

            new_node = {
                "id": node_id,
                "label": domain,
                "type": "domain",
                "color": "#16a34a",
                "notes": "",
                "asn": asn,
                "registrar": registrar,
                "netblocks": netblocks,
                "subdomain_ips": subdomain_ips,
                "compromised": False,
                "linked_asset_id": "",
                "x": 200 + hash(domain) % 600,
                "y": 200 + hash(domain) % 400,
            }
            data["nodes"].append(new_node)

            _update_compromised_cache(s, data["nodes"])
            payload = json.dumps(data)
            if row:
                row.body = payload
                row.updated_at = datetime.utcnow()
            else:
                s.add(
                    Note(
                        object_type="topology_map",
                        object_id=0,
                        severity="info",
                        tags="topology",
                        body=payload,
                    )
                )
            s.commit()

        return {"ok": True, "node": new_node}

    @router.post("/api/topology/add-user")
    async def api_topology_add_user(request: Request):
        body = await request.json()
        label = body.get("label", "").strip()
        email = body.get("email", "").strip()
        phone = body.get("phone", "").strip()
        name_id = body.get("name_id")
        if not label:
            return {"ok": False, "error": "Label is required"}

        with st.db() as s:
            row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "topology_map", Note.object_id == 0)
                    .order_by(Note.updated_at.desc(), Note.id.desc())
                )
                .scalars()
                .first()
            )
            data = {"nodes": [], "edges": []}
            if row and (row.body or "").strip():
                try:
                    raw = json.loads(row.body)
                    if isinstance(raw.get("nodes"), list):
                        data["nodes"] = raw.get("nodes")
                    if isinstance(raw.get("edges"), list):
                        data["edges"] = raw.get("edges")
                except Exception:
                    pass

            # Resolve name_id: use provided id, or auto-match by first/last name
            resolved_name_id = str(name_id) if name_id else ""
            if not resolved_name_id:
                parts = label.strip().split()
                if len(parts) >= 2:
                    fn, ln = parts[0], parts[-1]
                    candidate = s.execute(
                        select(NameItem)
                        .where(
                            NameItem.first_name.ilike(fn),
                            NameItem.last_name.ilike(ln),
                            NameItem.topology_node_id == "",
                        )
                        .limit(1)
                    ).scalars().first()
                    if candidate:
                        resolved_name_id = str(candidate.id)
                elif len(parts) == 1:
                    candidate = s.execute(
                        select(NameItem)
                        .where(
                            NameItem.first_name.ilike(parts[0]),
                            NameItem.topology_node_id == "",
                        )
                        .limit(1)
                    ).scalars().first()
                    if candidate:
                        resolved_name_id = str(candidate.id)

            # Check existing node by linked_name_id (avoids duplicate name conflicts)
            if resolved_name_id:
                existing = [n for n in data["nodes"] if str(n.get("linked_name_id")) == resolved_name_id and n.get("type") == "user"]
                if existing:
                    return {"ok": True, "node": existing[0]}

            import time
            node_id = f"n_user_{label.replace(' ', '_')}_{int(time.time())}"

            new_node = {
                "id": node_id,
                "label": label,
                "type": "user",
                "color": "#f59e0b",
                "notes": "",
                "first_name": label.split()[0] if label.split() else "",
                "last_name": label.split()[-1] if label.split() else "",
                "email": email,
                "phone": phone,
                "compromised": False,
                "linked_asset_id": "",
                "linked_name_id": resolved_name_id or "",
                "x": 200 + hash(label) % 600,
                "y": 200 + hash(label) % 400,
            }
            data["nodes"].append(new_node)

            _update_compromised_cache(s, data["nodes"])
            payload = json.dumps(data)
            if row:
                row.body = payload
                row.updated_at = datetime.utcnow()
            else:
                s.add(
                    Note(
                        object_type="topology_map",
                        object_id=0,
                        severity="info",
                        tags="topology",
                        body=payload,
                    )
                )

            if resolved_name_id:
                ni = s.scalar(select(NameItem).where(NameItem.id == resolved_name_id))
                if ni:
                    ni.topology_node_id = node_id

            s.commit()

        return {"ok": True, "node": new_node}

    st._topology_compromised_ids = _topology_compromised_ids
    return router
