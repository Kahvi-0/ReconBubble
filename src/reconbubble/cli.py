from __future__ import annotations
from pathlib import Path
import typer, uvicorn

from .workspace import Workspace
from .db import make_engine, make_session, Base, migrate_sqlite
from .parsers import upsert_artifact, import_nmap_xml, import_subdomains, import_emails, import_document
from .webapp import create_app

app = typer.Typer(add_completion=False, help="ReconBubble - local-only recon/OSINT workspace")

@app.callback()
def main(
    ctx: typer.Context,
    database: Path = typer.Option(..., "--database", "-d", help="Path to SQLite database file"),
    workspace: Path | None = typer.Option(None, "--workspace", help="Optional workspace root (defaults to db directory)"),
):
    ctx.ensure_object(dict)
    ctx.obj["database"] = database
    ctx.obj["workspace"] = workspace

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
def run(
    ctx: typer.Context,
    port: int = typer.Option(5000, "--port", "-p"),
    bind: str = typer.Option("127.0.0.1", "--bind", help="Bind address (default localhost only)"),
):
    if bind == "0.0.0.0":
        typer.echo("Refusing to bind to 0.0.0.0 (non-local). Use --bind 127.0.0.1 for local-only.")
        raise typer.Exit(code=2)
    cfg = ctx.obj
    ws = Workspace.from_db(cfg["database"], cfg["workspace"])
    uvicorn.run(create_app(ws.db_path, ws.root), host=bind, port=port, log_level="warning")
