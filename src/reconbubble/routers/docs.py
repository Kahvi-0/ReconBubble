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

    @router.get("/docs", response_class=HTMLResponse)
    def docs(request: Request):
        from ..parsers import DOC_NAME_FIELDS, DOC_SOFTWARE_FIELDS
        with st.db() as s:
            rows = (
                s.execute(select(Document).order_by(Document.created_at.desc()))
                .scalars()
                .all()
            )
        return st.templates.TemplateResponse(
            "docs.html", {"request": request, "rows": rows, "name_fields": sorted(DOC_NAME_FIELDS), "software_fields": sorted(DOC_SOFTWARE_FIELDS)}
        )

    @router.get("/api/doc/names")
    def api_doc_names(field: str = ""):
        from ..models import DocExtractedName
        from ..parsers import DOC_NAME_FIELDS
        with st.db() as s:
            q = select(DocExtractedName)
            if field and field.lower() in {f.lower() for f in DOC_NAME_FIELDS}:
                q = q.where(DocExtractedName.meta_field == field)
            q = q.order_by(DocExtractedName.name.asc())
            rows = s.execute(q).scalars().all()
        return [
            {
                "id": r.id,
                "name": r.name,
                "meta_field": r.meta_field,
                "document_id": r.document_id,
                "source_file": r.source_file,
            }
            for r in rows
        ]

    @router.post("/api/doc/extract-software")
    def api_doc_extract_software(fields: str = ""):
        from ..models import DocExtractedSoftware
        from ..parsers import DOC_SOFTWARE_FIELDS, extract_doc_software
        with st.db() as s:
            s.query(DocExtractedSoftware).delete()
            s.commit()
            field_set = {f.strip() for f in fields.split(",") if f.strip()}
            if not field_set:
                field_set = DOC_SOFTWARE_FIELDS
            count = extract_doc_software(s, field_set)
        return {"ok": True, "count": count}

    @router.get("/api/doc/software")
    def api_doc_software(field: str = ""):
        from ..models import DocExtractedSoftware
        from ..parsers import DOC_SOFTWARE_FIELDS
        with st.db() as s:
            q = select(DocExtractedSoftware)
            if field and field.lower() in {f.lower() for f in DOC_SOFTWARE_FIELDS}:
                q = q.where(DocExtractedSoftware.meta_field == field)
            q = q.order_by(DocExtractedSoftware.software.asc())
            rows = s.execute(q).scalars().all()
        return [
            {
                "id": r.id,
                "software": r.software,
                "meta_field": r.meta_field,
                "document_id": r.document_id,
                "source_file": r.source_file,
            }
            for r in rows
        ]

    @router.get("/api/doc/{doc_id}")
    def api_doc(doc_id: int):
        with st.db() as s:
            d = s.scalar(select(Document).where(Document.id == doc_id))
            if not d:
                return JSONResponse({"error": "not found"}, status_code=404)
            return {
                "id": d.id,
                "title": d.title,
                "mime": d.mime,
                "artifact_id": d.artifact_id,
            }

    @router.get("/api/doc/{doc_id}/text")
    def api_doc_text(doc_id: int):
        with st.db() as s:
            d = s.scalar(select(Document).where(Document.id == doc_id))
            if not d:
                return JSONResponse({"error": "not found"}, status_code=404)
            art = (
                s.scalar(select(Artifact).where(Artifact.id == d.artifact_id))
                if d.artifact_id
                else None
            )
            if not art or not art.stored_path:
                return JSONResponse({"error": "artifact not found"}, status_code=404)

        path = Path(art.stored_path)
        if not path.is_absolute():
            path = st.ws.uploads_dir / path
        if not path.exists() or not path.is_file():
            return JSONResponse({"error": "file not found"}, status_code=404)

        suffix = path.suffix.lower()
        try:
            if suffix == ".docx":
                import docx

                dfile = docx.Document(str(path))
                parts = [p.text for p in dfile.paragraphs if (p.text or "").strip()]
                text_body = "\n".join(parts)
            elif suffix in (".txt", ".log", ".csv", ".json", ".md"):
                text_body = path.read_text(encoding="utf-8", errors="replace")
            else:
                return JSONResponse(
                    {"error": "text preview not supported for this file type"},
                    status_code=400,
                )
        except Exception as e:
            return JSONResponse({"error": f"preview error: {e}"}, status_code=500)

        return {"ok": True, "text": text_body[:500000]}

    @router.get("/doc/{doc_id}", response_class=HTMLResponse)
    def doc_detail(doc_id: int, request: Request):
        with st.db() as s:
            d = s.scalar(select(Document).where(Document.id == doc_id))
            art = (
                s.scalar(select(Artifact).where(Artifact.id == d.artifact_id))
                if d
                else None
            )
        meta = json.loads(d.meta_json) if d else {}
        return st.templates.TemplateResponse(
            "doc_detail.html",
            {"request": request, "doc": d, "artifact": art, "meta": meta},
        )

    @router.post("/api/doc/delete")
    def api_doc_delete(doc_id: int = Form(...)):
        file_to_delete: Path | None = None
        with st.db() as s:
            d = s.scalar(select(Document).where(Document.id == doc_id))
            if not d:
                return RedirectResponse(url="/docs", status_code=303)

            artifact_id = d.artifact_id

            note_rows = (
                s.execute(
                    select(Note).where(
                        Note.object_type == "document", Note.object_id == doc_id
                    )
                )
                .scalars()
                .all()
            )
            for n in note_rows:
                s.delete(n)

            s.delete(d)
            s.flush()

            if artifact_id:
                remaining = (
                    s.scalar(
                        select(func.count(Document.id)).where(
                            Document.artifact_id == artifact_id
                        )
                    )
                    or 0
                )
                if remaining == 0:
                    art = s.scalar(select(Artifact).where(Artifact.id == artifact_id))
                    if art:
                        file_to_delete = Path(art.stored_path or "")
                        s.delete(art)

            s.commit()

        if file_to_delete:
            try:
                if file_to_delete.exists() and file_to_delete.is_file():
                    file_to_delete.unlink()
            except Exception:
                pass

        return RedirectResponse(url="/docs", status_code=303)

    @router.post("/api/doc/extract-names")
    def api_doc_extract_names(fields: str = Form("")):
        from ..parsers import DOC_NAME_FIELDS, extract_doc_names
        target = set(f.strip() for f in fields.split(",") if f.strip()) if fields else None
        with st.db() as s:
            count = extract_doc_names(s, target)
        return {"ok": True, "count": count}

    # Graph API

    return router
