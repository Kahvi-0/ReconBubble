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

    @router.post("/api/users/create")
    def api_user_create(
        username: str = Form(...), source: str = Form(""), notes: str = Form("")
    ):
        username = username.strip()
        if not username:
            return JSONResponse(
                {"ok": False, "error": "Username is required"}, status_code=400
            )
        with st.db() as s:
            if not s.scalar(select(ValidUser).where(ValidUser.username == username)):
                s.add(
                    ValidUser(
                        username=username, source=source.strip(), notes=notes.strip()
                    )
                )
                s.commit()
        return {"ok": True}

    @router.post("/api/creds/create")
    def api_cred_create(
        username: str = Form(...),
        password: str = Form(""),
        service: str = Form(""),
        url: str = Form(""),
        notes: str = Form(""),
    ):
        username = username.strip()
        if not username:
            return JSONResponse(
                {"ok": False, "error": "Username is required"}, status_code=400
            )
        with st.db() as s:
            s.add(
                Credential(
                    username=username,
                    password=password,
                    service=service,
                    url=url.strip(),
                    notes=notes.strip(),
                )
            )
            s.commit()
        return {"ok": True}

    @router.post("/api/creds/update")
    def api_cred_update(
        cred_id: int = Form(...),
        username: str = Form(...),
        password: str = Form(""),
        service: str = Form(""),
        url: str = Form(""),
        notes: str = Form(""),
    ):
        username = username.strip()
        if not username:
            return JSONResponse(
                {"ok": False, "error": "Username is required"}, status_code=400
            )
        with st.db() as s:
            cred = s.scalar(select(Credential).where(Credential.id == cred_id))
            if not cred:
                return JSONResponse({"ok": False, "error": "Credential not found"}, status_code=404)
            cred.username = username
            cred.password = password
            cred.service = service
            cred.url = url.strip()
            cred.notes = notes.strip()
            s.commit()
        return {"ok": True}

    @router.post("/api/creds/delete")
    def api_cred_delete(cred_id: int = Form(...)):
        with st.db() as s:
            cred = s.scalar(select(Credential).where(Credential.id == cred_id))
            if not cred:
                return JSONResponse({"ok": False, "error": "Credential not found"}, status_code=404)
            s.delete(cred)
            s.commit()
        return {"ok": True}

    @router.get("/users", response_class=HTMLResponse)
    def users_page(request: Request):
        topology_name_node_ids: dict[str, str] = {}
        with st.db() as s:
            names = (
                s.execute(
                    select(NameItem).order_by(NameItem.last_name.asc(), NameItem.first_name.asc())
                )
                .scalars()
                .all()
            )
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
                        if n.get("type") == "user":
                            nid = str(n.get("linked_name_id") or "").strip()
                            if nid:
                                topology_name_node_ids[nid] = str(n.get("id") or "")
                except Exception:
                    pass
        compromised_ids = st._topology_compromised_ids()
        compromised_name_ids = compromised_ids.get("name_ids", set()) if compromised_ids else set()
        return st.templates.TemplateResponse(
            "users.html",
            {
                "request": request,
                "names": names,
                "compromised_name_ids": compromised_name_ids,
                "topology_name_node_ids": topology_name_node_ids,
            },
        )

    @router.get("/api/names/list")
    def api_names_list():
        with st.db() as s:
            names = list(
                s.execute(
                    select(NameItem).order_by(NameItem.last_name.asc(), NameItem.first_name.asc())
                )
                .scalars()
                .all()
            )
        compromised_ids = st._topology_compromised_ids()
        compromised_name_ids = compromised_ids.get("name_ids", set()) if compromised_ids else set()
        return {
            "names": [
                {
                    "id": n.id,
                    "first_name": n.first_name,
                    "middle_name": n.middle_name,
                    "last_name": n.last_name,
                    "email": n.email,
                    "phone": n.phone,
                    "ad_username": n.ad_username,
                    "domain": n.domain,
                    "has_password": bool(n.password and n.password.strip()),
                    "ntlm_hash": n.ntlm_hash,
                    "ntlm_v1": n.ntlm_v1,
                    "ntlm_v2": n.ntlm_v2,
                    "dcc2": n.dcc2,
                    "kerberos_asrep": n.kerberos_asrep,
                    "kerberos_tgs": n.kerberos_tgs,
                    "kerberos_key_aes128": n.kerberos_key_aes128,
                    "kerberos_key_aes256": n.kerberos_key_aes256,
                    "password_plaintext": n.password_plaintext or 0,
                    "ntlm_hash_cracked": n.ntlm_hash_cracked or 0,
                    "ntlm_v1_cracked": n.ntlm_v1_cracked or 0,
                    "ntlm_v2_cracked": n.ntlm_v2_cracked or 0,
                    "dcc2_cracked": n.dcc2_cracked or 0,
                    "kerberos_asrep_cracked": n.kerberos_asrep_cracked or 0,
                    "kerberos_tgs_cracked": n.kerberos_tgs_cracked or 0,
                    "kerberos_key_aes128_cracked": n.kerberos_key_aes128_cracked or 0,
                    "kerberos_key_aes256_cracked": n.kerberos_key_aes256_cracked or 0,
                    "tags": n.tags,
                    "topology_node_id": n.topology_node_id,
                    "compromised": str(n.id) in compromised_name_ids or bool((n.password or "").strip() or (n.ntlm_hash or "").strip()),
                }
                for n in names
            ]
        }

    @router.post("/api/names/create")
    def api_name_create(
        first_name: str = Form(""),
        middle_name: str = Form(""),
        last_name: str = Form(""),
        email: str = Form(""),
        phone: str = Form(""),
        ad_username: str = Form(""),
        domain: str = Form(""),
        application: str = Form(""),
        password: str = Form(""),
        ntlm_hash: str = Form(""),
        ntlm_v1: str = Form(""),
        ntlm_v2: str = Form(""),
        dcc2: str = Form(""),
        kerberos_asrep: str = Form(""),
        kerberos_tgs: str = Form(""),
        kerberos_key_aes128: str = Form(""),
        kerberos_key_aes256: str = Form(""),
        tags: str = Form(""),
    ):
        with st.db() as s:
            s.add(
                NameItem(
                    first_name=first_name.strip(),
                    middle_name=middle_name.strip(),
                    last_name=last_name.strip(),
                    email=email.strip(),
                    phone=phone.strip(),
                    ad_username=ad_username.strip(),
                    domain=domain.strip(),
                    application=application.strip(),
                    password=password.strip(),
                    ntlm_hash=ntlm_hash.strip(),
                    ntlm_v1=ntlm_v1.strip(),
                    ntlm_v2=ntlm_v2.strip(),
                    dcc2=dcc2.strip(),
                    kerberos_asrep=kerberos_asrep.strip(),
                    kerberos_tgs=kerberos_tgs.strip(),
                    kerberos_key_aes128=kerberos_key_aes128.strip(),
                    kerberos_key_aes256=kerberos_key_aes256.strip(),
                    tags=tags,
                )
            )
            s.commit()
        return {"ok": True}

    @router.post("/api/names/update")
    def api_name_update(
        name_id: int = Form(...),
        first_name: str = Form(""),
        middle_name: str = Form(""),
        last_name: str = Form(""),
        email: str = Form(""),
        phone: str = Form(""),
        ad_username: str = Form(""),
        domain: str = Form(""),
        application: str = Form(""),
        password: str = Form(""),
        ntlm_hash: str = Form(""),
        ntlm_v1: str = Form(""),
        ntlm_v2: str = Form(""),
        dcc2: str = Form(""),
        kerberos_asrep: str = Form(""),
        kerberos_tgs: str = Form(""),
        kerberos_key_aes128: str = Form(""),
        kerberos_key_aes256: str = Form(""),
        password_plaintext: str = Form(""),
        ntlm_hash_cracked: str = Form(""),
        ntlm_v1_cracked: str = Form(""),
        ntlm_v2_cracked: str = Form(""),
        dcc2_cracked: str = Form(""),
        kerberos_asrep_cracked: str = Form(""),
        kerberos_tgs_cracked: str = Form(""),
        kerberos_key_aes128_cracked: str = Form(""),
        kerberos_key_aes256_cracked: str = Form(""),
        tags: str = Form(""),
    ):
        with st.db() as s:
            name = s.scalar(select(NameItem).where(NameItem.id == name_id))
            if not name:
                return JSONResponse({"ok": False, "error": "Name not found"}, status_code=404)
            name.first_name = first_name
            name.middle_name = middle_name.strip()
            name.last_name = last_name
            name.email = email.strip()
            name.phone = phone.strip()
            name.ad_username = ad_username.strip()
            name.domain = domain.strip()
            name.application = application.strip()
            name.password = password.strip()
            name.ntlm_hash = ntlm_hash.strip()
            name.ntlm_v1 = ntlm_v1.strip()
            name.ntlm_v2 = ntlm_v2.strip()
            name.dcc2 = dcc2.strip()
            name.kerberos_asrep = kerberos_asrep.strip()
            name.kerberos_tgs = kerberos_tgs.strip()
            name.kerberos_key_aes128 = kerberos_key_aes128.strip()
            name.kerberos_key_aes256 = kerberos_key_aes256.strip()
            name.password_plaintext = 1 if password_plaintext else 0
            name.ntlm_hash_cracked = 1 if ntlm_hash_cracked else 0
            name.ntlm_v1_cracked = 1 if ntlm_v1_cracked else 0
            name.ntlm_v2_cracked = 1 if ntlm_v2_cracked else 0
            name.dcc2_cracked = 1 if dcc2_cracked else 0
            name.kerberos_asrep_cracked = 1 if kerberos_asrep_cracked else 0
            name.kerberos_tgs_cracked = 1 if kerberos_tgs_cracked else 0
            name.kerberos_key_aes128_cracked = 1 if kerberos_key_aes128_cracked else 0
            name.kerberos_key_aes256_cracked = 1 if kerberos_key_aes256_cracked else 0
            name.tags = tags.strip()
            s.commit()
        return {"ok": True}

    @router.post("/api/names/update-domain")
    def api_name_update_domain(name_id: int = Form(...), domain: str = Form("")):
        with st.db() as s:
            name = s.scalar(select(NameItem).where(NameItem.id == name_id))
            if not name:
                return JSONResponse({"ok": False, "error": "Name not found"}, status_code=404)
            name.domain = domain.strip()
            s.commit()
        return {"ok": True}

    @router.post("/api/names/delete")
    def api_name_delete(name_id: int = Form(...)):
        with st.db() as s:
            name = s.scalar(select(NameItem).where(NameItem.id == name_id))
            if not name:
                return JSONResponse({"ok": False, "error": "Name not found"}, status_code=404)
            s.execute(
                SmbShare.__table__.update()
                .where(SmbShare.user_id == name_id)
                .values(user_id=None)
            )
            s.delete(name)
            s.commit()
        return {"ok": True}

    @router.get("/api/domain-correlations")
    def api_domain_correlations_get():
        from reconbubble.models import DomainCorrelation
        with st.db() as s:
            corrs = s.scalars(select(DomainCorrelation).order_by(DomainCorrelation.primary_domain)).all()
            result = {}
            for c in corrs:
                if c.primary_domain not in result:
                    result[c.primary_domain] = {"primary": c.primary_domain, "aliases": c.aliases.split(",") if c.aliases else []}
            return result

    @router.post("/api/domain-correlations/save")
    async def api_domain_correlations_save(request: Request):
        from reconbubble.models import DomainCorrelation
        data = await request.json()
        if not data:
            return JSONResponse({"ok": False, "error": "No data"}, status_code=400)
        with st.db() as s:
            s.execute(DomainCorrelation.__table__.delete())
            for primary, info in data.items():
                aliases = ",".join(info.get("aliases", []))
                s.add(DomainCorrelation(primary_domain=primary, aliases=aliases))
            s.commit()
        return {"ok": True}

    # Social Media
    return router
