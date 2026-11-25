from __future__ import annotations
from pathlib import Path
import asyncio, json, ipaddress, os, re, shlex, socket, ssl, sys, tempfile, uuid
import html as html_lib
from urllib.parse import quote_plus, parse_qsl, urlencode, urlsplit
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import APIRouter, Request, UploadFile, File, Form, Query, Response
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse, StreamingResponse

from sqlalchemy import select, func, text, or_
from sqlalchemy.orm import Session

from .. import netproxy
from .. import nsecatalog
from .. import smbbrowse
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

    @router.get("/api/doc/{doc_id}/detail")
    def api_doc_detail(doc_id: int):
        with st.db() as s:
            d = s.scalar(select(Document).where(Document.id == doc_id))
            if not d:
                return JSONResponse({"error": "not found"}, status_code=404)
            art = (
                s.scalar(select(Artifact).where(Artifact.id == d.artifact_id))
                if d.artifact_id
                else None
            )
            notes = (
                s.execute(
                    select(Note)
                    .where(
                        Note.object_type == "document",
                        Note.object_id == doc_id,
                    )
                    .order_by(Note.created_at.desc())
                )
                .scalars()
                .all()
            )
        meta = json.loads(d.meta_json) if d.meta_json else {}
        return {
            "id": d.id,
            "title": d.title or "",
            "mime": d.mime or "",
            "size_bytes": d.size_bytes,
            "sha256": d.sha256 or "",
            "created_at": d.created_at.strftime("%Y-%m-%d %H:%M") if d.created_at else "",
            "artifact_id": d.artifact_id,
            "stored_path": art.stored_path if art else "",
            "meta": meta,
            "notes": [
                {
                    "created_at": n.created_at.strftime("%Y-%m-%d %H:%M") if n.created_at else "",
                    "severity": n.severity or "",
                    "tags": n.tags or "",
                    "body": n.body or "",
                }
                for n in notes
            ],
        }

    # Image extension -> media type, mirroring /api/smb/preview so doc
    # previews and SMB share previews render identically.
    _DOC_IMAGE_MEDIA = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "webp": "image/webp",
        "bmp": "image/bmp",
        "ico": "image/x-icon",
        "svg": "image/svg+xml",
    }

    @router.get("/api/doc/{doc_id}/preview")
    def api_doc_preview(doc_id: int):
        """Stream a stored document for inline preview.

        Uses the same contract as ``/api/smb/preview``: ``X-Preview-Kind`` /
        ``X-Preview-Cache`` / ``X-Preview-Note`` headers with the bytes
        sniffed as text/image/pdf/binary, and legacy .doc files rendered to
        PDF with headless LibreOffice when it is installed (the converted
        PDF is cached in the workspace preview cache, same as the SMB share
        preview).  Without LibreOffice the response carries
        ``X-Preview-Note: needs-libreoffice`` so the pane can offer the
        install command.
        """
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
        try:
            size = path.stat().st_size
        except OSError:
            return JSONResponse({"error": "file not found"}, status_code=404)

        cache_dir = st.ws.preview_cache_dir
        ext = path.suffix.lower().lstrip(".")

        if ext == "doc" and smbbrowse.find_soffice() is None:
            # No converter: nothing to stream, just the install prompt.
            return Response(
                b"",
                media_type="application/octet-stream",
                headers={
                    "X-Preview-Kind": "binary",
                    "X-Preview-Cache": "miss",
                    "X-Preview-Note": "needs-libreoffice",
                    "Cache-Control": "no-store",
                },
            )

        if ext == "doc" and 0 < size <= smbbrowse.PREVIEW_MAX_BYTES:
            if cache_dir is not None:
                cached_pdf = smbbrowse.doc2pdf_cache_hit_doc(cache_dir, doc_id, size)
                if cached_pdf is not None:
                    return Response(
                        cached_pdf,
                        media_type="application/pdf",
                        headers={
                            "X-Preview-Kind": "pdf",
                            "X-Preview-Cache": "hit",
                            "Cache-Control": "no-store",
                        },
                    )
            try:
                doc_bytes = path.read_bytes()
            except OSError:
                return JSONResponse({"error": "could not read file"}, status_code=500)
            try:
                # tmp_root keeps the per-call working copy (source + profile)
                # inside the workspace cache dir: zero footprint outside.
                pdf = smbbrowse.convert_to_pdf(doc_bytes, path.name, tmp_root=cache_dir)
            except smbbrowse.DocToPdfError as exc:
                return Response(
                    doc_bytes,
                    media_type="application/octet-stream",
                    headers={
                        "X-Preview-Kind": "binary",
                        "X-Preview-Cache": "miss",
                        "X-Preview-Note": (
                            "needs-libreoffice" if exc.reason == "missing"
                            else "conversion-failed"
                        ),
                        "Cache-Control": "no-store",
                    },
                )
            if cache_dir is not None:
                smbbrowse.doc2pdf_cache_write_doc(cache_dir, doc_id, size, pdf)
            return Response(
                pdf,
                media_type="application/pdf",
                headers={
                    "X-Preview-Kind": "pdf",
                    "X-Preview-Cache": "miss",
                    "Cache-Control": "no-store",
                },
            )

        with path.open("rb") as fh:
            sample = fh.read(smbbrowse.SNIFF_SIZE)
        kind = smbbrowse.sniff_kind(sample, size or None)
        if kind == "text":
            media = "text/plain; charset=utf-8"
        elif kind == "image":
            media = _DOC_IMAGE_MEDIA.get(ext, "image/octet-stream")
        elif kind == "pdf":
            media = "application/pdf"
        else:
            media = "application/octet-stream"

        def stream():
            with path.open("rb") as fh:
                while True:
                    chunk = fh.read(64 * 1024)
                    if not chunk:
                        break
                    yield chunk

        return StreamingResponse(
            stream(),
            media_type=media,
            headers={
                "X-Preview-Kind": kind,
                "X-Preview-Cache": "miss",
                "Cache-Control": "no-store",
            },
        )

    @router.post("/api/doc/delete")
    def api_doc_delete(doc_id: int = Form(...)):
        file_to_delete: Path | None = None
        with st.db() as s:
            d = s.scalar(select(Document).where(Document.id == doc_id))
            if not d:
                return RedirectResponse(url="/osint/hub", status_code=303)

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

        return RedirectResponse(url="/osint/hub", status_code=303)

    # Graph API

    return router
