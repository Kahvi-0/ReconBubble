from __future__ import annotations
from pathlib import Path
import os, subprocess, sys, tempfile
import typer, uvicorn

from .workspace import Workspace
from .db import make_engine, make_session, Base, migrate_sqlite
from .parsers import upsert_artifact, import_nmap_xml, import_subdomains, import_emails, import_document
from .webapp import create_app

app = typer.Typer(add_completion=False, help="ReconBubble - local-only recon/OSINT workspace")

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
