from __future__ import annotations
from pathlib import Path
import asyncio, json, ipaddress, os, re, shlex, socket, ssl, sys, tempfile, uuid
import html as html_lib
from urllib.parse import quote_plus, parse_qsl, urlencode, urlsplit
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import FastAPI, Request, UploadFile, File, Form, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from sqlalchemy import select, func, text, or_
from sqlalchemy.orm import Session

from .db import make_engine, make_session, Base, migrate_sqlite
from .workspace import Workspace
from . import netproxy
from . import nsecatalog
from .nse import SEVERITY_RANK
from .models import (
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
from .parsers import (
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
from .tools import (
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

from .state import AppState
from .helpers import _hostname_as_domain
from .routers import (
    dashboard,
    scope,
    upload,
    assets,
    subdomain_api,
    screenshots,
    webprobe,
    tools,
    servicekeys,
    jobs,
    toolspage,
    checklist,
    smb,
    osint,
    topology,
    subdomainspage,
    docs,
    cloud,
    profiling,
    services,
    graph,
    status,
    passwordspray,
    users,
    social,
    artifacts,
    urls,
    rdap,
    dnspages,
)

def _backfill_host_hostname_subdomains(session: Session) -> int:
    rows = session.execute(
        select(Host.id, Host.hostname).where(
            Host.hostname.isnot(None), Host.hostname != ""
        )
    ).all()
    count = 0
    for idx, (host_id, hostname) in enumerate(rows, 1):
        fqdn = _hostname_as_domain(hostname)
        if not fqdn:
            continue
        try:
            parser_link_host_domain(session, host_id, fqdn, commit=False)
            count += 1
        except Exception as e:
            session.rollback()
            print(f"[Backfill] Error linking host {host_id} to {fqdn}: {e}")
            continue
        if idx % 500 == 0:
            session.commit()
    if count % 500 != 0:
        session.commit()
    return count

def create_app(
    db_path: Path, workspace_root: Path | None = None, project_name: str = ""
) -> FastAPI:
    ws = Workspace.from_db(db_path, workspace_root)
    try:
        netproxy.mirror_env()
    except netproxy.ProxyConfigError as e:
        # stderr: line-buffered, so the warning survives log redirection and
        # signals a misconfiguration the user should notice (stdout prints are
        # block-buffered and can be lost if the process is killed).
        print(
            f"[Startup] {netproxy.ENV_VAR} misconfigured ({e}); continuing without a proxy.",
            file=sys.stderr,
        )
        os.environ.pop(netproxy.ENV_VAR, None)
    engine = make_engine(ws.db_path)
    Base.metadata.create_all(engine)
    migrate_sqlite(engine)
    SessionLocal = make_session(engine)

    with SessionLocal() as s:
        linked = _backfill_host_hostname_subdomains(s)
        if linked:
            print(f"[Startup] Linked {linked} host hostname(s) to subdomains")

    app = FastAPI(title="ReconBubble", docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def add_cache_headers(request: Request, call_next):
        response = await call_next(request)
        if request.method == "GET":
            if request.url.path.startswith("/api/"):
                response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            elif request.url.path.startswith("/static/"):
                response.headers.setdefault("Cache-Control", "public, max-age=86400")
            elif response.headers.get("content-type", "").startswith("text/html"):
                response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            else:
                response.headers["Cache-Control"] = "private, max-age=300, must-revalidate"
        return response

    app.mount(
        "/static",
        StaticFiles(directory=Path(__file__).parent / "static"),
        name="static",
    )
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
    templates.env.globals["project_name"] = (project_name or "").strip()

    def _scope_is_empty() -> bool:
        with SessionLocal() as s:
            count = (
                s.scalar(
                    select(func.count(ScopeItem.id)).where(ScopeItem.in_scope == 1)
                )
                or 0
            )
        return count == 0

    # Starlette/FastAPI changed TemplateResponse call style across versions.
    # Support both:
    #   templates.TemplateResponse("name.html", {"request": request, ...})
    # and
    #   templates.TemplateResponse(request, "name.html", {...})
    _template_response_orig = templates.TemplateResponse

    def _template_response_compat(*args, **kwargs):
        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            template_name = args[0]
            context = args[1]
            context.setdefault("scope_is_empty", _scope_is_empty())
            request = context.get("request")
            if request is not None:
                try:
                    return _template_response_orig(
                        request, template_name, context, *args[2:], **kwargs
                    )
                except Exception:
                    # Fall back to legacy call style below.
                    pass
        return _template_response_orig(*args, **kwargs)

    templates.TemplateResponse = _template_response_compat

    def db() -> Session:
        return SessionLocal()


    st = AppState(app=app, ws=ws, templates=templates,
                 SessionLocal=SessionLocal, project_name=project_name)

    app.state.screenshot_jobs = {}
    app.state.screenshot_queue = asyncio.Queue()
    app.state.screenshot_queue_ids = []
    app.state.screenshot_worker_task = None
    app.state.active_screenshot_job_id = None
    app.state.web_probe_jobs = {}
    app.state.active_web_probe_job_id = None
    app.state.web_probe_lock = asyncio.Lock()
    app.state.tool_jobs = {}
    app.state.tool_active_task = None
    app.state.tool_queue = asyncio.Queue()
    app.state.tool_queue_ids = []
    app.state.tool_worker_task = None
    app.state.active_tool_job_id = None
    app.state.tools_registry = build_tools(ws.bin_dir)
    app.state.process_providers = []

    app.include_router(dashboard.build(st, app))
    app.include_router(scope.build(st, app))
    app.include_router(upload.build(st, app))
    app.include_router(assets.build(st, app))
    app.include_router(subdomain_api.build(st, app))
    app.include_router(screenshots.build(st, app))
    app.include_router(webprobe.build(st, app))
    app.include_router(tools.build(st, app))
    app.include_router(servicekeys.build(st, app))
    app.include_router(jobs.build(st, app))
    app.include_router(toolspage.build(st, app))
    app.include_router(checklist.build(st, app))
    app.include_router(smb.build(st, app))
    app.include_router(osint.build(st, app))
    app.include_router(topology.build(st, app))
    app.include_router(subdomainspage.build(st, app))
    app.include_router(docs.build(st, app))
    app.include_router(cloud.build(st, app))
    app.include_router(profiling.build(st, app))
    app.include_router(services.build(st, app))
    app.include_router(graph.build(st, app))
    app.include_router(status.build(st, app))
    app.include_router(passwordspray.build(st, app))
    app.include_router(users.build(st, app))
    app.include_router(social.build(st, app))
    app.include_router(artifacts.build(st, app))
    app.include_router(urls.build(st, app))
    app.include_router(rdap.build(st, app))
    app.include_router(dnspages.build(st, app))

    return app
