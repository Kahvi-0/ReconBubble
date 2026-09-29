from __future__ import annotations
from pathlib import Path
import os, subprocess, sys, tempfile
import typer, uvicorn

from .workspace import Workspace
from .db import make_engine, make_session, Base, migrate_sqlite
from .parsers import upsert_artifact, import_nmap_xml, import_subdomains, import_emails, import_document
from . import nsecatalog
from .nse import reanalyze_artifact
from .models import Artifact
from .webapp import create_app
from . import netproxy

app = typer.Typer(
    add_completion=False,
    help="ReconBubble - local-only recon/OSINT workspace",
    epilog=(
        "Environment variables:\n"
        "  RECONBUBBLE_PROXY - socks5://user:pass@host:port - route all outbound traffic\n"
        "    (screenshots, web probes, whois/RDAP, external tools) through a SOCKS5 proxy.\n"
        "    Same as --proxy on run. No auth needed? Use socks5://host:port.\n"
        "  RECONBUBBLE_BROWSER_DIR - explicit Playwright browser directory (server mode)\n"
        "  RECONBUBBLE_CHROMIUM_EXECUTABLE - system Chromium to use instead of Playwright's\n"
        "  RECONBUBBLE_DB / RECONBUBBLE_PROJECT - storage + project (server mode)\n"
        "  PLAYWRIGHT_BROWSERS_PATH - browser location used by Playwright"
    ),
)

def _browser_install_env(target: Path) -> dict:
    env = os.environ.copy()
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(target)
    return env

def _run_playwright_install(target: Path, with_deps: bool = False) -> int:
    cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
    if with_deps:
        cmd.append("--with-deps")
    typer.echo("Running: " + " ".join(cmd))
    typer.echo(f"Browser path: {target}")
    result = subprocess.run(cmd, env=_browser_install_env(target))
    return result.returncode

def _playwright_chromium_path(target: Path) -> str | None:
    old = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(target)
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            return p.chromium.executable_path
    except Exception:
        return None
    finally:
        if old is None:
            os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)
        else:
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = old

def _ensure_browser_installed(target: Path, with_deps: bool = False) -> None:
    if os.environ.get("RECONBUBBLE_CHROMIUM_EXECUTABLE", "").strip():
        typer.echo("RECONBUBBLE_CHROMIUM_EXECUTABLE is set; skipping Playwright browser install.")
        return
    executable_path = _playwright_chromium_path(target)
    if executable_path and Path(executable_path).exists():
        return
    code = _run_playwright_install(target, with_deps)
    if code != 0:
        raise typer.Exit(code)

@app.callback()
def main(
    ctx: typer.Context,
    database: Path = typer.Option(..., "--database", "-d", help="Path to SQLite database file"),
    workspace: Path | None = typer.Option(None, "--workspace", help="Optional workspace root (defaults to db directory)"),
    project: str = typer.Option("", "--project", help="Optional project name shown in UI"),
):
    ctx.ensure_object(dict)
    ctx.obj["database"] = database
    ctx.obj["workspace"] = workspace
    ctx.obj["project"] = project

@app.command()
def init(ctx: typer.Context):
    cfg = ctx.obj
    ws = Workspace.from_db(cfg["database"], cfg["workspace"])
    engine = make_engine(ws.db_path)
    Base.metadata.create_all(engine)
    migrate_sqlite(engine)
    typer.echo(f"Initialized DB: {ws.db_path}")
    typer.echo(f"Workspace: {ws.root}")
    typer.echo(f"Uploads:   {ws.uploads_dir}")

import_app = typer.Typer(add_completion=False, help="Import artifacts into the workspace")
app.add_typer(import_app, name="import")

@import_app.command("nmap")
def import_nmap(ctx: typer.Context, path: Path):
    cfg = ctx.obj
    ws = Workspace.from_db(cfg["database"], cfg["workspace"])
    engine = make_engine(ws.db_path); Base.metadata.create_all(engine); migrate_sqlite(engine)
    SessionLocal = make_session(engine)
    stored = ws.store_upload(path, prefix="nmap")
    with SessionLocal() as s:
        art = upsert_artifact(s, "nmap_xml", stored)
        stats = import_nmap_xml(s, art, stored)
    typer.echo(f"Imported Nmap XML -> {stats}")

@import_app.command("subdomains")
def import_subs(ctx: typer.Context, path: Path):
    cfg = ctx.obj
    ws = Workspace.from_db(cfg["database"], cfg["workspace"])
    engine = make_engine(ws.db_path); Base.metadata.create_all(engine); migrate_sqlite(engine)
    SessionLocal = make_session(engine)
    stored = ws.store_upload(path, prefix="subdomains")
    with SessionLocal() as s:
        art = upsert_artifact(s, "subdomains", stored)
        n = import_subdomains(s, art, stored)
    typer.echo(f"Imported {n} subdomains")

@import_app.command("emails")
def import_emails_cmd(ctx: typer.Context, path: Path):
    cfg = ctx.obj
    ws = Workspace.from_db(cfg["database"], cfg["workspace"])
    engine = make_engine(ws.db_path); Base.metadata.create_all(engine); migrate_sqlite(engine)
    SessionLocal = make_session(engine)
    stored = ws.store_upload(path, prefix="emails")
    with SessionLocal() as s:
        art = upsert_artifact(s, "emails", stored)
        n = import_emails(s, art, stored)
    typer.echo(f"Imported {n} emails")

@import_app.command("docs")
def import_docs(ctx: typer.Context, path: Path):
    cfg = ctx.obj
    ws = Workspace.from_db(cfg["database"], cfg["workspace"])
    engine = make_engine(ws.db_path); Base.metadata.create_all(engine); migrate_sqlite(engine)
    SessionLocal = make_session(engine)
    paths = [p for p in path.rglob("*") if p.is_file()] if path.is_dir() else [path]
    total = 0
    with SessionLocal() as s:
        for p in paths:
            stored = ws.store_upload(p, prefix="doc")
            art = upsert_artifact(s, "doc", stored)
            total += import_document(s, art, stored)
    typer.echo(f"Imported {total} document(s)")

nse_app = typer.Typer(add_completion=False, help="NSE script catalog and finding analysis (local, no nmap needed)")
app.add_typer(nse_app, name="nse")

@nse_app.command("list")
def nse_list(
    ctx: typer.Context,
    category: str = typer.Option("", "--category", "-c", help="Only show scripts with this category (vuln, safe, default, intrusive, ...)"),
    limit: int = typer.Option(0, "--limit", "-n", help="Max number of scripts to show (0 = all)"),
):
    cat = nsecatalog.get_catalog()
    if not cat.scripts:
        typer.echo("NSE catalog not available (set RECONBUBBLE_NSE_DIR or install nmap scripts).")
        raise typer.Exit(1)
    names = sorted(cat.scripts)
    if category:
        c = category.lower()
        names = [n for n in names if c in cat.scripts[n].categories]
    shown = names[:limit] if limit > 0 else names
    for n in shown:
        sc = cat.scripts[n]
        desc = (sc.description or "").strip().splitlines()
        first = desc[0][:72] if desc else ""
        typer.echo(f"{n}\t{','.join(sorted(sc.categories))}\t{first}")
    typer.echo(f"{len(shown)} of {len(names)} script(s)")

@nse_app.command("show")
def nse_show(ctx: typer.Context, script: str):
    cat = nsecatalog.get_catalog()
    sc = cat.scripts.get(script)
    if sc is None:
        typer.echo(f"Script not found in catalog: {script}")
        raise typer.Exit(1)
    typer.echo(f"Name:        {sc.name}")
    typer.echo(f"Categories:  {', '.join(sorted(sc.categories))}")
    if sc.ports:
        typer.echo(f"Ports:       {sorted(sc.ports)}")
    if sc.services:
        typer.echo(f"Services:    {', '.join(sorted(sc.services))}")
    if sc.cves:
        typer.echo(f"References:  {', '.join(sc.cves)}")
    desc = (sc.description or "").strip()
    if desc:
        typer.echo("")
        typer.echo(desc)
    if sc.usage:
        typer.echo("")
        typer.echo(sc.usage.strip())

@nse_app.command("reanalyze")
def nse_reanalyze(ctx: typer.Context):
    """Re-derive NSE script results and findings from stored nmap_xml artifacts.

    Backfills projects imported before NSE analysis existed, or re-applies
    derivation after catalog/heuristic changes.
    """
    from sqlalchemy import select
    cfg = ctx.obj
    ws = Workspace.from_db(cfg["database"], cfg["workspace"])
    engine = make_engine(ws.db_path); Base.metadata.create_all(engine); migrate_sqlite(engine)
    SessionLocal = make_session(engine)
    with SessionLocal() as s:
        arts = s.execute(
            select(Artifact).where(Artifact.type == "nmap_xml").order_by(Artifact.id)
        ).scalars().all()
        if not arts:
            typer.echo("No nmap_xml artifacts to reanalyze.")
            return
        total = 0
        for art in arts:
            n = reanalyze_artifact(s, art, art.stored_path)
            total += n
            typer.echo(f"artifact {art.id} ({art.filename}): {n} script result(s)")
        s.commit()
    typer.echo(f"Reanalyzed {len(arts)} artifact(s); {total} script result(s) stored.")

@app.command()
def install_browser(
    ctx: typer.Context,
    browser_dir: Path | None = typer.Option(None, "--browser-dir", help="Explicit Playwright browser directory"),
    with_deps: bool = typer.Option(False, "--with-deps", help="Also install system dependencies for Chromium"),
):
    cfg = ctx.obj
    ws = Workspace.from_db(cfg["database"], cfg["workspace"])
    if browser_dir:
        target = browser_dir.expanduser().resolve()
    else:
        env_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
        target = Path(env_path).expanduser().resolve() if env_path else ws.browser_dir
    target.mkdir(parents=True, exist_ok=True)
    code = _run_playwright_install(target, with_deps)
    raise typer.Exit(code)

@app.command()
def run(
    ctx: typer.Context,
    port: int = typer.Option(5000, "--port", "-p"),
    bind: str = typer.Option("127.0.0.1", "--bind", help="Bind address (default localhost only)"),
    listen_all: bool = typer.Option(False, "--listen-all", help="Listen on all interfaces (0.0.0.0) instead of localhost only"),
    proxy: str = typer.Option("", "--proxy", help="Route outbound traffic (screenshots, web probes, whois/RDAP, external tools) through a SOCKS5 proxy, e.g. socks5://user:pass@127.0.0.1:1080"),
    browser_dir: Path | None = typer.Option(None, "--browser-dir", help="Explicit Playwright browser directory"),
    ephemeral_browser: bool = typer.Option(False, "--ephemeral-browser", help="Use a temporary Playwright browser directory for this run"),
    ram_browser: bool = typer.Option(False, "--ram-browser", help="Use a temporary RAM-backed Playwright browser directory when /dev/shm is available"),
    install_browser: bool = typer.Option(False, "--install-browser", help="Install Playwright Chromium before starting if it is missing"),
    with_deps: bool = typer.Option(False, "--with-deps", help="Pass --with-deps to Playwright when installing Chromium"),
):
    if listen_all:
        bind = "0.0.0.0"
    if bind == "0.0.0.0" and not listen_all:
        typer.echo("Refusing to bind to 0.0.0.0 (non-local). Use --listen-all to listen on all interfaces or --bind 127.0.0.1 for local-only.")
        raise typer.Exit(code=2)
    if proxy:
        try:
            netproxy.parse_proxy_url(proxy)
        except netproxy.ProxyConfigError as e:
            typer.echo(f"Invalid --proxy value: {e}")
            raise typer.Exit(code=2)
        os.environ[netproxy.ENV_VAR] = proxy
        typer.echo(f"Proxy: {netproxy.describe()}")
    if browser_dir and (ephemeral_browser or ram_browser):
        typer.echo("Use either --browser-dir or --ephemeral-browser/--ram-browser, not both.")
        raise typer.Exit(code=2)
    cfg = ctx.obj
    ws = Workspace.from_db(cfg["database"], cfg["workspace"])
    existing_env_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()

    temp_dir = None
    if browser_dir:
        target = browser_dir.expanduser().resolve()
    elif ephemeral_browser or ram_browser:
        tmp_parent = Path("/dev/shm") if ram_browser and Path("/dev/shm").exists() else None
        temp_dir = tempfile.TemporaryDirectory(prefix="reconbubble-playwright-", dir=str(tmp_parent) if tmp_parent else None)
        target = Path(temp_dir.name)
    elif existing_env_path:
        target = Path(existing_env_path).expanduser().resolve()
    else:
        target = ws.browser_dir
    target.mkdir(parents=True, exist_ok=True)
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(target)

    mode = "ram" if ram_browser else "ephemeral" if ephemeral_browser else "custom" if browser_dir or existing_env_path else "workspace"
    os.environ["RECONBUBBLE_BROWSER_MODE"] = "ephemeral" if ephemeral_browser or ram_browser else "custom" if browser_dir or existing_env_path else "workspace"
    typer.echo(f"Screenshot browser mode: {mode}")
    typer.echo(f"Screenshot browser path: {target}")

    try:
        if install_browser:
            _ensure_browser_installed(target, with_deps)
        uvicorn.run(create_app(ws.db_path, ws.root, cfg.get("project", "")), host=bind, port=port, log_level="warning")
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()
