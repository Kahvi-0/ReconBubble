from __future__ import annotations
from pathlib import Path
import json, ipaddress, re, socket
from datetime import datetime

from fastapi import FastAPI, Request, UploadFile, File, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from sqlalchemy import select, func, text
from sqlalchemy.orm import Session

from .db import make_engine, make_session, Base, migrate_sqlite
from .workspace import Workspace
from .models import Host, Service, Subdomain, Email, Artifact, ServiceEvidence, Document, Note, ScopeItem, CloudItem, ValidUser, Credential, SocialMedia, WebUrl, DomainInfo
from .parsers import upsert_artifact, import_nmap_xml, import_subdomains, import_emails, import_document, upsert_host, import_valid_users, import_credentials, import_web_urls, import_prowl_phase1, import_zone_transfers, import_smtp

DOMAIN_RE = re.compile(r"(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.?$")

def create_app(db_path: Path, workspace_root: Path | None = None) -> FastAPI:
    ws = Workspace.from_db(db_path, workspace_root)
    engine = make_engine(ws.db_path)
    Base.metadata.create_all(engine)
    migrate_sqlite(engine)
    SessionLocal = make_session(engine)

    app = FastAPI(title="ReconBubble", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

    def db() -> Session:
        return SessionLocal()

    # ---- Scope helpers ----
    def scope_sets(s: Session):
        items = s.execute(select(ScopeItem).where(ScopeItem.in_scope == 1)).scalars().all()
        ips, subnets, domains, email_domains, domain_all_subs = set(), [], set(), set(), set()
        for it in items:
            v = (it.value or "").strip().lower().strip(".")
            if not v:
                continue
            if it.kind == "ip":
                ips.add(v)
            elif it.kind == "subnet":
                try:
                    subnets.append(ipaddress.ip_network(v, strict=False))
                except Exception:
                    pass
            elif it.kind == "domain":
                domains.add(v)
                if getattr(it, "apply_all_subdomains", 0) == 1:
                    domain_all_subs.add(v)
            elif it.kind == "email_domain":
                email_domains.add(v)
        return ips, subnets, domains, email_domains, domain_all_subs

    def ip_in_scope(ip: str, ips: set[str], subnets: list) -> bool:
        ip = (ip or "").strip()
        if not ip:
            return False
        if ip in ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        return any(addr in net for net in subnets)

    def domain_in_scope(fqdn: str, domains: set[str], domain_all_subs: set[str]) -> bool:
        f = (fqdn or "").strip().lower().strip(".")
        if not f:
            return False
        if f in domains:
            return True
        return any(f.endswith("." + d) for d in domain_all_subs)

    def email_in_scope(email: str, email_domains: set[str]) -> bool:
        e = (email or "").strip().lower()
        if "@" not in e:
            return False
        dom = e.split("@", 1)[1].strip().strip(".")
        if dom in email_domains:
            return True
        return any(dom.endswith("." + d) for d in email_domains)

    # ---- Host <-> Subdomain linking ----
    def list_host_domains(s: Session, host_id: int) -> list[str]:
        rows = s.execute(text(
            "SELECT subdomains.fqdn FROM host_subdomains "
            "JOIN subdomains ON subdomains.id = host_subdomains.subdomain_id "
            "WHERE host_subdomains.host_id = :hid ORDER BY subdomains.fqdn ASC"
        ), {"hid": host_id}).fetchall()
        return [r[0] for r in rows]

    def _split_lines(txt: str) -> list[str]:
        return [l.strip() for l in (txt or "").splitlines() if l.strip()]

    def list_subdomain_ips(s: Session, fqdn: str) -> list[str]:
        rows = s.execute(text(
            "SELECT hosts.ip FROM host_subdomains "
            "JOIN subdomains ON subdomains.id = host_subdomains.subdomain_id "
            "JOIN hosts ON hosts.id = host_subdomains.host_id "
            "WHERE subdomains.fqdn = :fq ORDER BY hosts.ip ASC"
        ), {"fq": fqdn}).fetchall()
        return [r[0] for r in rows]

    def list_subdomain_hosts(s: Session, fqdn: str) -> list[dict]:
        rows = s.execute(text(
            "SELECT hosts.id, hosts.ip, hosts.hostname FROM host_subdomains "
            "JOIN subdomains ON subdomains.id = host_subdomains.subdomain_id "
            "JOIN hosts ON hosts.id = host_subdomains.host_id "
            "WHERE subdomains.fqdn = :fq ORDER BY hosts.ip ASC"
        ), {"fq": fqdn}).fetchall()
        return [{"id": r[0], "ip": r[1], "hostname": r[2] or ""} for r in rows]

    def link_host_domain(s: Session, host_id: int, fqdn: str) -> None:
        fqdn = fqdn.strip().lower().rstrip(".")
        if not fqdn or not DOMAIN_RE.match(fqdn):
            return
        sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))
        if not sub:
            sub = Subdomain(fqdn=fqdn, root_domain=".".join(fqdn.split(".")[-2:]))
            s.add(sub); s.commit(); s.refresh(sub)
        s.execute(text(
            "INSERT OR IGNORE INTO host_subdomains(host_id, subdomain_id, created_at) "
            "VALUES (:hid, :sid, :ts)"
        ), {"hid": host_id, "sid": sub.id, "ts": datetime.utcnow().isoformat()})
        s.commit()

    def resolve_ips(fqdn: str) -> list[str]:
        fqdn = fqdn.strip().rstrip(".")
        out = set()
        try:
            for fam in (socket.AF_INET, socket.AF_INET6):
                try:
                    infos = socket.getaddrinfo(fqdn, None, family=fam, type=socket.SOCK_STREAM)
                except Exception:
                    continue
                for info in infos:
                    ip = info[4][0]
                    if ip:
                        out.add(ip)
        except Exception:
            pass
        return sorted(out)

    # ---- Pages ----
    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        with db() as s:
            stats = {
                "hosts": s.scalar(select(func.count(Host.id))) or 0,
                "services": s.scalar(select(func.count(Service.id))) or 0,
                "subdomains": s.scalar(select(func.count(Subdomain.id))) or 0,
                "emails": s.scalar(select(func.count(Email.id))) or 0,
                "docs": s.scalar(select(func.count(Document.id))) or 0,
                "notes": s.scalar(select(func.count(Note.id))) or 0,
            }
        return templates.TemplateResponse("home.html", {"request": request, "stats": stats})

    # Scope
    @app.get("/scope", response_class=HTMLResponse)
    def scope_page(request: Request):
        with db() as s:
            domains = (
                s.execute(
                    select(ScopeItem)
                    .where(ScopeItem.kind == "domain")
                    .order_by(ScopeItem.value.asc())
                )
                .scalars()
                .all()
            )
            ip_items = (
                s.execute(
                    select(ScopeItem)
                    .where(ScopeItem.kind.in_(["ip", "subnet"]))
                    .order_by(ScopeItem.kind.asc(), ScopeItem.value.asc())
                )
                .scalars()
                .all()
            )
            email_items = (
                s.execute(
                    select(ScopeItem)
                    .where(ScopeItem.kind == "email_domain")
                    .order_by(ScopeItem.value.asc())
                )
                .scalars()
                .all()
            )

        return templates.TemplateResponse(
            "scope.html",
            {
                "request": request,
                "domains": domains,
                "ip_items": ip_items,
                "email_items": email_items,
            },
        )

    @app.post("/scope/add")
    def scope_add(kind: str = Form(...), value: str = Form(""), values_raw: str = Form(""),
                  note: str = Form(""), apply_all_subdomains: int = Form(0)):
        items: list[str] = []
        if values_raw and values_raw.strip():
            items = [ln.strip() for ln in values_raw.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        elif value and value.strip():
            items = [value.strip()]
        if not items:
            return RedirectResponse(url="/scope", status_code=303)

        with db() as s:
            for v in items:
                v2 = v.strip()
                if kind == "ip_or_subnet":
                    actual_kind = "subnet" if "/" in v2 else "ip"
                else:
                    actual_kind = kind

                it = ScopeItem(
                    kind=actual_kind,
                    value=v2,
                    note=(note or "").strip(),
                    in_scope=1,
                    apply_all_subdomains=1 if (actual_kind == "domain" and apply_all_subdomains == 1) else 0,
                )
                s.add(it)
                try:
                    s.commit()
                except Exception:
                    s.rollback()
        return RedirectResponse(url="/scope", status_code=303)

    @app.post("/scope/toggle")
    def scope_toggle(item_id: int = Form(...)):
        with db() as s:
            it = s.scalar(select(ScopeItem).where(ScopeItem.id == item_id))
            if it:
                it.in_scope = 0 if it.in_scope == 1 else 1
                s.commit()
        return RedirectResponse(url="/scope", status_code=303)

    @app.post("/scope/delete")
    def scope_delete(item_id: int = Form(...)):
        with db() as s:
            it = s.scalar(select(ScopeItem).where(ScopeItem.id == item_id))
            if it:
                s.delete(it); s.commit()
        return RedirectResponse(url="/scope", status_code=303)

    # Upload
    @app.get("/upload", response_class=HTMLResponse)
    def upload_page(request: Request):
        return templates.TemplateResponse("upload.html", {"request": request})
    @app.post("/upload")
    async def upload(
        request: Request,
        kind: str = Form(...),
        file: UploadFile | None = File(None),
        raw_text: str = Form(""),
        raw_filename: str = Form(""),
    ):
        """Handle uploads (file or raw paste) and import into DB."""
        stored: str | None = None
        try:
            if raw_text and raw_text.strip():
                default = {
                    "nmap_xml": "pasted_scan.xml",
                    "subdomains": "pasted_subdomains.txt",
                    "scope": "pasted_scope.txt",
                    "emails": "pasted_emails.txt",
                    "doc": "pasted_document.bin",
                    "users": "pasted_users.txt",
                    "creds": "pasted_creds.txt",
                    "urls": "pasted_urls.txt",
                }.get(kind, "pasted.txt")
                fname = raw_filename.strip() if raw_filename and raw_filename.strip() else default
                stored = ws.store_text(raw_text, fname, prefix=kind)
            elif file is not None and file.filename:
                tmp = ws.uploads_dir / f"tmp_{file.filename}"
                tmp.write_bytes(await file.read())
                stored = ws.store_upload(tmp, prefix=kind)
                tmp.unlink(missing_ok=True)
            else:
                return templates.TemplateResponse(
                    "upload.html",
                    {"request": request, "workspace": ws, "error": "No file uploaded and no raw text provided."},
                    status_code=400,
                )

            with db() as s:
                art = upsert_artifact(s, kind, Path(stored))
                if kind == "nmap_xml":
                    import_nmap_xml(s, art, Path(stored))
                elif kind == "subdomains":
                    import_subdomains(s, art, Path(stored))
                    # resolve subdomain IPs and link to hosts
                    fqdn_list = s.execute(select(Subdomain.fqdn)).scalars().all()
                    for fqdn in fqdn_list:
                        for ip in resolve_ips(fqdn):
                            try:
                                h = upsert_host(s, ip, "", "")
                            except Exception:
                                continue
                            link_host_domain(s, h.id, fqdn)
                elif kind == "scope":
                    import_scope(s, art, Path(stored))
                elif kind == "emails":
                    import_emails(s, art, Path(stored))
                elif kind == "doc":
                    import_document(s, art, Path(stored))
                elif kind == "users":
                    import_valid_users(s, art, Path(stored))
                elif kind == "creds":
                    import_credentials(s, art, Path(stored))
                elif kind == "urls":
                    import_web_urls(s, art, Path(stored))
                elif kind == "prowl_phase1":
                    import_prowl_phase1(s, art, Path(stored))
                elif kind == "zone_transfers":
                    import_zone_transfers(s, art, Path(stored))
                elif kind == "smtp":
                    import_smtp(s, art, Path(stored))

            return RedirectResponse(url="/", status_code=303)

        except ValueError as e:
            return templates.TemplateResponse(
                "upload.html",
                {"request": request, "workspace": ws, "error": str(e)},
                status_code=400,
            )
        except Exception as e:
            return templates.TemplateResponse(
                "upload.html",
                {"request": request, "workspace": ws, "error": f"Upload failed: {e}"},
                status_code=500,
            )

    # Assets
    @app.get("/assets", response_class=HTMLResponse)
    def assets(request: Request):
        show_out = int(request.query_params.get('show_out', '0'))
        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            rows = s.execute(
                select(Host.id, Host.ip, Host.hostname, Host.done, Host.complete, Host.waf, func.count(Service.id).label("svc_count"))
                .outerjoin(Service, Service.host_id == Host.id)
                .group_by(Host.id)
                .order_by(func.count(Service.id).desc(), Host.ip.asc())
            ).all()
            domains_by_host = {r.id: list_host_domains(s, r.id) for r in rows}
        data = []
        for r in rows:
            ip_in = ip_in_scope(r.ip, ips, subnets)
            host_domains = domains_by_host.get(r.id, [])
            # Check scope for each individual domain
            domain_list = []
            any_domain_in = False
            for d in host_domains:
                d_in = domain_in_scope(d, domains, domain_all_subs)
                if d_in:
                    any_domain_in = True
                domain_list.append({"fqdn": d, "in_scope": d_in})
            data.append({
                "id": r.id,
                "ip": r.ip,
                "hostname": r.hostname,
                "done": getattr(r, "done", 0),
                "complete": getattr(r, "complete", 0),
                "waf": getattr(r, "waf", 0),
                "svc_count": r.svc_count,
                "ip_in_scope": ip_in,
                "domain_in_scope": any_domain_in,
                "in_scope": ip_in or any_domain_in,
                "domains": domain_list,
            })
        data = data if show_out == 1 else [d for d in data if d.get("in_scope")]
        return templates.TemplateResponse("assets.html", {"request": request, "rows": data, "show_out": show_out})

    @app.post("/api/host/create")
    def api_host_create(ip: str = Form(...), hostname: str = Form(""), domains_raw: str = Form("")):
        ip = ip.strip()
        hostname = (hostname or "").strip()
        domains = [ln.strip().lower().rstrip(".") for ln in (domains_raw or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
        with db() as s:
            try:
                host = upsert_host(s, ip, hostname, "")
            except Exception as e:
                return {"ok": False, "error": str(e)}
            for d in domains:
                if DOMAIN_RE.match(d):
                    link_host_domain(s, host.id, d)
        return {"ok": True}

    # Sidebar APIs

    @app.post("/api/note/add")
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
        with db() as s:
            n = Note(object_type=object_type[:32], object_id=int(object_id), severity=severity[:16], tags=tags[:255], body=body)
            s.add(n)
            s.commit()
            return {"ok": True, "id": n.id}

    @app.post("/api/note/delete")
    def api_note_delete(note_id: int = Form(...)):
        with db() as s:
            n = s.scalar(select(Note).where(Note.id == note_id))
            if not n:
                return JSONResponse({"ok": False}, status_code=404)
            s.delete(n)
            s.commit()
        return {"ok": True}


    @app.get("/api/host/{host_id}")
    def api_host(host_id: int):
        with db() as s:
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
            if highest_severity is None or sev_rank.get(sv, 0) > sev_rank.get(highest_severity, 0):
                highest_severity = sv
    
        return {
            "ok": True,
            "highest_severity": highest_severity,
            "host": {"id": host.id, "ip": host.ip, "hostname": host.hostname, "os_guess": host.os_guess},
            "domains": domains,
            "services": [
                {
                    "id": sv.id,
                    "port": sv.port,
                    "proto": sv.proto,
                    "state": sv.state,
                    "service_name": sv.service_name,
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

    @app.post("/api/host/update")
    def api_host_update(host_id: int = Form(...), ip: str = Form(...), hostname: str = Form(""),
                        os_guess: str = Form(""), domains_raw: str = Form("")):
        ip = ip.strip()
        hostname = (hostname or "").strip()
        os_guess = (os_guess or "").strip()
        domains = [ln.strip().lower().rstrip(".") for ln in (domains_raw or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
        with db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host:
                return JSONResponse({"ok": False}, status_code=404)
            host.ip = ip
            host.hostname = hostname
            host.os_guess = os_guess
            try:
                s.commit()
            except Exception:
                s.rollback()
                return {"ok": False, "error": "IP already exists (or invalid update)."}
            for d in domains:
                if DOMAIN_RE.match(d):
                    link_host_domain(s, host.id, d)
        return {"ok": True}

    @app.get("/api/service/{service_id}")
    def api_service(service_id: int):
        with db() as s:
            svc = s.scalar(select(Service).where(Service.id == service_id))
            if not svc:
                return JSONResponse({"ok": False}, status_code=404)
            host = s.scalar(select(Host).where(Host.id == svc.host_id))
            evidence = s.execute(select(ServiceEvidence).where(ServiceEvidence.service_id==service_id).order_by(ServiceEvidence.created_at.desc())).scalars().all()
        return {
            "ok": True,
            "host": {"id": host.id, "ip": host.ip, "hostname": host.hostname} if host else None,
            "service": {"id": svc.id, "port": svc.port, "proto": svc.proto, "state": svc.state, "service_name": svc.service_name,
                        "product": svc.product, "version": svc.version, "extra_info": svc.extra_info},
            "evidence": [{"created_at": str(ev.created_at), "raw_output": ev.raw_output} for ev in evidence],
        }

    @app.get("/api/subdomain")
    def api_subdomain(fqdn: str = Query(...)):
        fq = fqdn.strip().lower().rstrip(".")
        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            ips_found = list_subdomain_ips(s, fq)
            in_dom = domain_in_scope(fq, domains, domain_all_subs)
            in_ip = any(ip_in_scope(ip, ips, subnets) for ip in ips_found)
            hosts = list_subdomain_hosts(s, fq)
        return {"ok": True, "fqdn": fq, "ips": ips_found, "in_scope": bool(in_dom or in_ip), "hosts": hosts}

    # Lists
    @app.get("/subdomains", response_class=HTMLResponse)
    def subdomains(request: Request):
        show_out = int(request.query_params.get('show_out', '0'))
        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            rows = s.execute(select(Subdomain).order_by(Subdomain.root_domain.asc(), Subdomain.fqdn.asc())).scalars().all()
            # Get all RDAP info
            rdap_info = {}
            for di in s.execute(select(DomainInfo)).scalars().all():
                rdap_info[di.domain] = {"registrar": di.registrar, "creation_date": di.creation_date, "expiration_date": di.expiration_date, "name_servers": di.name_servers, "status": di.status, "error": di.rdap_error}
            out = []
            root_domains = {}
            for x in rows:
                ips_found = list_subdomain_ips(s, x.fqdn)
                in_dom = domain_in_scope(x.fqdn, domains, domain_all_subs)
                in_ip = any(ip_in_scope(ip, ips, subnets) for ip in ips_found)
                in_scope = bool(in_dom or in_ip)
                # Get RDAP info for root domain
                rdap = rdap_info.get(x.root_domain, {}) if x.root_domain else {}
                # Get Prowler info for this subdomain
                prowl = {}
                if x.prowl_ips or x.prowl_registrar or x.prowl_netblocks:
                    prowl = {
                        "ips": x.prowl_ips,
                        "registrar": x.prowl_registrar,
                        "netblocks": x.prowl_netblocks,
                    }
                out.append({"fqdn": x.fqdn, "root_domain": x.root_domain, "ips": ips_found, "in_scope": in_scope, "rdap": rdap, "prowl": prowl})
                if x.root_domain and x.root_domain not in root_domains:
                    root_domains[x.root_domain] = rdap
        
        # Group by root domain
        grouped = {}
        for r in out:
            rd = r["root_domain"] or "unknown"
            if rd not in grouped:
                grouped[rd] = {"subs": [], "rdap": root_domains.get(rd, {})}
            grouped[rd]["subs"].append(r)
        
        out = out if show_out == 1 else [r for r in out if r.get("in_scope")]
        grouped_filtered = {}
        for rd, data in grouped.items():
            filtered = data["subs"] if show_out == 1 else [s for s in data["subs"] if s.get("in_scope")]
            if filtered:
                grouped_filtered[rd] = {"subs": filtered, "rdap": data["rdap"]}
        
        return templates.TemplateResponse("subdomains.html", {"request": request, "grouped": grouped_filtered, "show_out": show_out})

    @app.get("/emails", response_class=HTMLResponse)
    def emails(request: Request):
        with db() as s:
            _, _, _, email_domains, _ = scope_sets(s)
            rows = s.execute(select(Email).order_by(Email.domain.asc(), Email.email.asc())).scalars().all()
        out = [{"email": x.email, "domain": x.domain, "in_scope": email_in_scope(x.email, email_domains)} for x in rows]
        return templates.TemplateResponse("emails.html", {"request": request, "rows": out})

    @app.get("/docs", response_class=HTMLResponse)
    def docs(request: Request):
        with db() as s:
            rows = s.execute(select(Document).order_by(Document.created_at.desc())).scalars().all()
        return templates.TemplateResponse("docs.html", {"request": request, "rows": rows})

    @app.get("/doc/{doc_id}", response_class=HTMLResponse)
    def doc_detail(doc_id: int, request: Request):
        with db() as s:
            d = s.scalar(select(Document).where(Document.id==doc_id))
            art = s.scalar(select(Artifact).where(Artifact.id==d.artifact_id)) if d else None
        meta = json.loads(d.meta_json) if d else {}
        return templates.TemplateResponse("doc_detail.html", {"request": request, "doc": d, "artifact": art, "meta": meta})

    # Graph API
    
    @app.get("/cloud", response_class=HTMLResponse)
    def cloud(request: Request):
        with db() as s:
            rows = s.execute(select(CloudItem).order_by(CloudItem.created_at.desc())).scalars().all()
            out = []
            for r in rows:
                data = {}
                try:
                    data = json.loads(r.data_json) if r.data_json else {}
                except Exception:
                    data = {}
                out.append({
                    "id": r.id,
                    "provider": r.provider,
                    "name": r.name,
                    "notes": r.notes or "",
                    "data": data,
                    "created_at": r.created_at,
                })
        return templates.TemplateResponse("cloud.html", {"request": request, "rows": out})

    @app.post("/api/cloud/create")
    def api_cloud_create(
        provider: str = Form(...),
        name: str = Form(""),
        notes: str = Form(""),
        tenant_id: str = Form(""),
        account_id: str = Form(""),
        primary_domain: str = Form(""),
        regions: str = Form(""),
        subscriptions: str = Form(""),
        buckets: str = Form(""),
        projects: str = Form(""),
        app_ids: str = Form(""),
    ):
        provider = (provider or "").strip()
        name = (name or "").strip()
        notes = notes or ""
        data = {}
        # Provider-specific fields (best-effort defaults)
        if provider.lower() in ("aws",):
            data = {
                "account_id": account_id.strip(),
                "regions": _split_lines(regions),
                "buckets": _split_lines(buckets),
            }
        elif provider.lower() in ("azure",):
            data = {
                "tenant_id": tenant_id.strip(),
                "subscriptions": _split_lines(subscriptions),
                "regions": _split_lines(regions),
            }
        elif provider.lower() in ("digital ocean", "digitalocean", "do"):
            data = {
                "projects": _split_lines(projects),
                "spaces": _split_lines(buckets),
                "regions": _split_lines(regions),
            }
            provider = "Digital Ocean"
        elif provider.lower() in ("o365", "office365", "office 365"):
            data = {
                "tenant_id": tenant_id.strip(),
                "primary_domain": primary_domain.strip(),
                "email_domains": _split_lines(subscriptions),
            }
            provider = "O365"
        else:  # Microsoft (generic)
            data = {
                "tenant_id": tenant_id.strip(),
                "primary_domain": primary_domain.strip(),
                "app_ids": _split_lines(app_ids),
                "domains": _split_lines(subscriptions),
            }
            provider = "Microsoft"

        with db() as s:
            item = CloudItem(provider=provider[:64], name=name[:255], notes=notes, data_json=json.dumps(data, ensure_ascii=False))
            s.add(item)
            s.commit()
            return {"ok": True, "id": item.id}

    @app.get("/api/cloud/{cloud_id}")
    def api_cloud_get(cloud_id: int):
        with db() as s:
            item = s.scalar(select(CloudItem).where(CloudItem.id == cloud_id))
            if not item:
                return JSONResponse({"ok": False}, status_code=404)
            try:
                data = json.loads(item.data_json) if item.data_json else {}
            except Exception:
                data = {}
            return {
                "ok": True,
                "id": item.id,
                "provider": item.provider,
                "name": item.name,
                "notes": item.notes or "",
                "data": data,
                "created_at": item.created_at.isoformat() if item.created_at else "",
            }

    @app.post("/api/cloud/update")
    def api_cloud_update(
        cloud_id: int = Form(...),
        provider: str = Form(...),
        name: str = Form(""),
        notes: str = Form(""),
        tenant_id: str = Form(""),
        account_id: str = Form(""),
        primary_domain: str = Form(""),
        regions: str = Form(""),
        subscriptions: str = Form(""),
        buckets: str = Form(""),
        projects: str = Form(""),
        app_ids: str = Form(""),
    ):
        with db() as s:
            item = s.scalar(select(CloudItem).where(CloudItem.id == cloud_id))
            if not item:
                return JSONResponse({"ok": False}, status_code=404)

            provider = (provider or "").strip()
            name = (name or "").strip()
            notes = notes or ""

            data = {}
            if provider.lower() in ("aws",):
                data = {"account_id": account_id.strip(), "regions": _split_lines(regions), "buckets": _split_lines(buckets)}
                provider = "AWS"
            elif provider.lower() in ("azure",):
                data = {"tenant_id": tenant_id.strip(), "subscriptions": _split_lines(subscriptions), "regions": _split_lines(regions)}
                provider = "Azure"
            elif provider.lower() in ("digital ocean", "digitalocean", "do"):
                data = {"projects": _split_lines(projects), "spaces": _split_lines(buckets), "regions": _split_lines(regions)}
                provider = "Digital Ocean"
            elif provider.lower() in ("o365", "office365", "office 365"):
                data = {"tenant_id": tenant_id.strip(), "primary_domain": primary_domain.strip(), "email_domains": _split_lines(subscriptions)}
                provider = "O365"
            else:
                data = {"tenant_id": tenant_id.strip(), "primary_domain": primary_domain.strip(), "app_ids": _split_lines(app_ids), "domains": _split_lines(subscriptions)}
                provider = "Microsoft"

            item.provider = provider[:64]
            item.name = name[:255]
            item.notes = notes
            item.data_json = json.dumps(data, ensure_ascii=False)
            s.commit()
        return {"ok": True}

    @app.post("/api/cloud/delete")
    def api_cloud_delete(cloud_id: int = Form(...)):
        with db() as s:
            item = s.scalar(select(CloudItem).where(CloudItem.id == cloud_id))
            if not item:
                return JSONResponse({"ok": False}, status_code=404)
            s.delete(item)
            s.commit()
        return {"ok": True}

    @app.get("/api/graph")
    def api_graph(only_in_scope: bool = Query(False)):
        nodes, edges = [], []
        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            subs = s.execute(select(Subdomain)).scalars().all()
            hosts = s.execute(select(Host)).scalars().all()
            svcs = s.execute(select(Service)).scalars().all()
            host_domains = {h.id: list_host_domains(s, h.id) for h in hosts}

        def nid(prefix: str, key: str) -> str:
            return f"{prefix}:{key}"

        def add_node(n: dict):
            if only_in_scope and not n.get("in_scope", False):
                return
            nodes.append(n)

        domain_nodes = {}
        for sub in subs:
            rd = (sub.root_domain or "").strip(".").lower()
            fq = sub.fqdn
            sub_in = domain_in_scope(fq, domains, domain_all_subs)
            dom_in = domain_in_scope(rd, domains, domain_all_subs) if rd else False
            if rd and rd not in domain_nodes:
                did = nid("domain", rd)
                domain_nodes[rd] = did
                add_node({"id": did, "label": rd, "type": "domain", "in_scope": dom_in})
            sid = nid("sub", fq)
            add_node({"id": sid, "label": fq, "type": "subdomain", "in_scope": sub_in})
            if rd:
                edges.append({"from": domain_nodes[rd], "to": sid, "type": "has"})

        host_ids = {}
        host_scope = {}
        for h in hosts:
            hid = nid("host", h.ip)
            host_ids[h.id] = hid
            hin = ip_in_scope(h.ip, ips, subnets)
            host_scope[h.id] = hin
            label = h.ip + (("\n" + h.hostname) if h.hostname else "")
            add_node({"id": hid, "label": label, "type": "host", "in_scope": hin, "host_id": h.id})

        for svc in svcs:
            hin = host_scope.get(svc.host_id, False)
            sid = nid("svc", f"{svc.host_id}:{svc.port}/{svc.proto}")
            add_node({"id": sid, "label": f"{svc.port}/{svc.proto}\n{svc.service_name or ''}".strip(),
                      "type": "service", "in_scope": hin, "service_id": svc.id})
            edges.append({"from": host_ids.get(svc.host_id, ""), "to": sid, "type": "exposes"})

        existing = {n["id"] for n in nodes}
        for host_id, fqdn_list in host_domains.items():
            host_node = host_ids.get(host_id)
            if not host_node:
                continue
            for fqdn in fqdn_list:
                sub_id = nid("sub", fqdn)
                if sub_id not in existing:
                    sub_in = domain_in_scope(fqdn, domains, domain_all_subs)
                    add_node({"id": sub_id, "label": fqdn, "type": "subdomain", "in_scope": sub_in})
                    existing.add(sub_id)
                edges.append({"from": sub_id, "to": host_node, "type": "resolves_to"})

        if only_in_scope:
            ids = {n["id"] for n in nodes}
            edges = [e for e in edges if e["from"] in ids and e["to"] in ids]
        return {"nodes": nodes, "edges": edges}

    @app.get("/graph", response_class=HTMLResponse)
    def graph_page(request: Request):
        return templates.TemplateResponse("graph.html", {"request": request})

    @app.get("/subdomains/export")
    def subdomains_export():
        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            rows = s.execute(select(Subdomain)).scalars().all()
            out = []
            for x in rows:
                ips_found = list_subdomain_ips(s, x.fqdn)
                in_dom = domain_in_scope(x.fqdn, domains, domain_all_subs)
                in_ip = any(ip_in_scope(ip, ips, subnets) for ip in ips_found)
                if in_dom or in_ip:
                    out.append(x.fqdn)
        text_data = "\n".join(sorted(set(out))) + "\n"
        return HTMLResponse(content=text_data, media_type="text/plain")

    @app.post("/api/host/done")
    def api_host_done(host_id: int = Form(...), done: int = Form(...)):
        with db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.done = 1 if int(done) == 1 else 0
            s.commit()
        return {"ok": True}

    @app.post("/api/subdomain/done")
    def api_sub_done(fqdn: str = Form(...), done: int = Form(...)):
        fq = fqdn.strip().lower().rstrip(".")
        with db() as s:
            sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == fq))
            if not sub:
                return JSONResponse({"ok": False}, status_code=404)
            sub.done = 1 if int(done) == 1 else 0
            s.commit()
        return {"ok": True}

    @app.post("/api/host/complete")
    def api_host_complete(host_id: int = Form(...), complete: int = Form(...)):
        with db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.complete = 1 if int(complete) == 1 else 0
            s.commit()
        return {"ok": True}

    @app.post("/api/host/waf")
    def api_host_waf(host_id: int = Form(...), waf: int = Form(...)):
        with db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.waf = 1 if int(waf) == 1 else 0
            s.commit()
        return {"ok": True}

    # Users & Credentials
    @app.get("/users", response_class=HTMLResponse)
    def users_page(request: Request):
        with db() as s:
            users = s.execute(select(ValidUser).order_by(ValidUser.username.asc())).scalars().all()
            creds = s.execute(select(Credential).order_by(Credential.service.asc(), Credential.username.asc())).scalars().all()
        return templates.TemplateResponse("users.html", {"request": request, "users": users, "creds": creds})

    @app.post("/api/users/create")
    def api_user_create(username: str = Form(...), source: str = Form("")):
        with db() as s:
            if not s.scalar(select(ValidUser).where(ValidUser.username == username)):
                s.add(ValidUser(username=username, source=source)); s.commit()
        return {"ok": True}

    @app.post("/api/creds/create")
    def api_cred_create(username: str = Form(...), password: str = Form(""), service: str = Form("")):
        with db() as s:
            s.add(Credential(username=username, password=password, service=service)); s.commit()
        return {"ok": True}

    # Social Media
    @app.get("/social", response_class=HTMLResponse)
    def social_page(request: Request):
        with db() as s:
            rows = s.execute(select(SocialMedia).order_by(SocialMedia.platform.asc(), SocialMedia.handle.asc())).scalars().all()
        return templates.TemplateResponse("social.html", {"request": request, "rows": rows})

    @app.post("/api/social/create")
    async def api_social_create(
        request: Request,
        platform: str = Form(...),
        handle: str = Form(""),
        url: str = Form(""),
        notes: str = Form(""),
        screenshot: UploadFile | None = File(None),
    ):
        artifact_id = None
        if screenshot and screenshot.filename:
            tmp = ws.uploads_dir / f"tmp_{screenshot.filename}"
            tmp.write_bytes(await screenshot.read())
            stored = ws.store_upload(tmp, prefix="screenshot")
            tmp.unlink(missing_ok=True)
            with db() as s:
                art = upsert_artifact(s, "screenshot", stored)
                artifact_id = art.id
        
        with db() as s:
            item = SocialMedia(
                platform=platform[:64],
                handle=handle[:255],
                url=url[:512],
                notes=notes,
                artifact_id=artifact_id,
            )
            s.add(item); s.flush(); s.commit()
            item_id = item.id
        return {"ok": True, "id": item_id}

    @app.post("/api/social/delete")
    def api_social_delete(social_id: int = Form(...)):
        with db() as s:
            item = s.scalar(select(SocialMedia).where(SocialMedia.id == social_id))
            if item:
                s.delete(item); s.commit()
        return {"ok": True}

    # Artifact serving
    @app.get("/api/artifacts/{artifact_id}")
    def serve_artifact(artifact_id: int):
        with db() as s:
            art = s.scalar(select(Artifact).where(Artifact.id == artifact_id))
            if not art or not art.stored_path:
                return JSONResponse({"error": "Not found"}, status_code=404)
            path = Path(art.stored_path)
            if not path.is_absolute():
                path = ws.uploads_dir / path
            if not path.exists():
                return JSONResponse({"error": "File not found"}, status_code=404)
            import mimetypes
            mime, _ = mimetypes.guess_type(path.name)
            return FileResponse(path, media_type=mime or "application/octet-stream")

    @app.get("/api/artifacts/{artifact_id}/thumb")
    def serve_thumb(artifact_id: int):
        with db() as s:
            art = s.scalar(select(Artifact).where(Artifact.id == artifact_id))
            if not art or not art.stored_path:
                return JSONResponse({"error": "Not found"}, status_code=404)
            path = Path(art.stored_path)
            if not path.is_absolute():
                path = ws.uploads_dir / path
            if not path.exists():
                return JSONResponse({"error": "File not found"}, status_code=404)
            import mimetypes
            mime, _ = mimetypes.guess_type(path.name)
            if not mime or not mime.startswith("image"):
                return JSONResponse({"error": "Not an image"}, status_code=400)
            return FileResponse(path, media_type=mime)

    # Web URLs
    @app.get("/urls", response_class=HTMLResponse)
    def urls_page(request: Request):
        show_out = int(request.query_params.get('show_out', '0'))
        with db() as s:
            _, _, domains, _, domain_all_subs = scope_sets(s)
            rows = s.execute(select(WebUrl).order_by(WebUrl.domain.asc(), WebUrl.url.asc())).scalars().all()
            out = []
            for x in rows:
                in_dom = domain_in_scope(x.domain, domains, domain_all_subs) if x.domain else False
                out.append({"id": x.id, "url": x.url, "domain": x.domain, "title": x.title, "in_scope": in_dom})
        out = out if show_out == 1 else [r for r in out if r.get("in_scope")]
        grouped = {}
        for r in out:
            d = r["domain"] or "unknown"
            if d not in grouped:
                grouped[d] = []
            grouped[d].append(r)
        return templates.TemplateResponse("urls.html", {"request": request, "grouped": grouped, "show_out": show_out})

    # RDAP lookup
    @app.get("/api/rdap/{domain}")
    def api_rdap(domain: str):
        import urllib.request, json, socket
        domain = domain.lower().strip()
        tld = domain.split(".")[-1] if "." in domain else domain
        rdap_servers = {
            "com": "whois.verisign.com",
            "net": "whois.verisign.com",
            "org": "rdap.org",
            "info": "rdap.info",
            "io": "rdap.io",
            "co": "whois.co",
            "ai": "rdap.nic.ai",
            "cc": "rdap.nic.cc",
            "tv": "rdap.nic.tv",
        }
        host = rdap_servers.get(tld, "rdap.org")
        error_msg = ""
        try:
            url = f"https://{host}/domain/{domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "ReconBubble/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw) if raw else {}
            if not isinstance(data, dict):
                error_msg = "Invalid RDAP response"
                raise Exception(error_msg)
            
            out = {"domainName": data.get("name")}
            
            # Parse entities (registrar, registrant, admin, tech contacts)
            entities = {}
            for e in data.get("entities", []):
                if isinstance(e, dict):
                    roles = e.get("roles", [])
                    vcard = e.get("vcardArray", [])
                    name = ""
                    email = ""
                    org = ""
                    if isinstance(vcard, list):
                        for v in vcard:
                            if isinstance(v, list) and len(v) > 2:
                                if v[1] == "fn":
                                    name = v[3] if len(v) > 3 else ""
                                elif v[1] == "email":
                                    email = v[3] if len(v) > 3 else ""
                                elif v[1] == "org":
                                    org = v[3] if len(v) > 3 else ""
                    for role in roles:
                        entities[role] = {"name": name, "email": email, "org": org}
            
            if "registrar" in entities:
                out["registrar"] = entities["registrar"].get("name", "")
                out["registrarEmail"] = entities["registrar"].get("email", "")
                out["registrarOrg"] = entities["registrar"].get("org", "")
            if "registrant" in entities:
                out["registrant"] = entities["registrant"].get("name", "")
                out["registrantEmail"] = entities["registrant"].get("email", "")
            if "administrative" in entities or "admin" in entities:
                key = "administrative" if "administrative" in entities else "admin"
                out["adminContact"] = entities[key].get("name", "")
                out["adminEmail"] = entities[key].get("email", "")
            if "technical" in entities:
                out["techContact"] = entities["technical"].get("name", "")
                out["techEmail"] = entities["technical"].get("email", "")
            
            # Parse events
            for e in data.get("events", []):
                if isinstance(e, dict):
                    if e.get("eventAction") == "registration":
                        out["creationDate"] = e.get("eventDate")
                    if e.get("eventAction") == "expiration":
                        out["expirationDate"] = e.get("eventDate")
                    if e.get("eventAction") == "last changed":
                        out["updatedDate"] = e.get("eventDate")
            
            # Parse nameservers with IPs
            ns_list = []
            for ns in data.get("nameservers", []):
                if isinstance(ns, dict):
                    ns_name = ns.get("ldhName", "")
                    ns_ips = []
                    for ip in ns.get("ipAddresses", []) or []:
                        if isinstance(ip, dict):
                            v = ip.get("v", "")
                            if v:
                                ns_ips.append(v)
                    if ns_name:
                        if ns_ips:
                            ns_list.append(f"{ns_name} ({', '.join(ns_ips)})")
                        else:
                            ns_list.append(ns_name)
            if ns_list:
                out["nameServers"] = ns_list
            
            # Status
            if data.get("status"):
                out["status"] = [s.get("v", s) if isinstance(s, dict) else s for s in data.get("status", [])]
            
            # DNSSEC
            if data.get("dnssec"):
                out["dnssec"] = str(data.get("dnssec"))
            
            # Network/ASN info
            if data.get("network"):
                net = data.get("network", {})
                out["network"] = net.get("name", "")
                out["cidr"] = net.get("cidr0", "")
            
        except Exception as e:
            error_msg = str(e)[:150]
            out = {"domainName": domain}
        
        # Save to database
        with db() as s:
            existing = s.scalar(select(DomainInfo).where(DomainInfo.domain == domain))
            di = existing or DomainInfo(domain=domain)
            di.registrar = out.get("registrar", "")
            di.creation_date = out.get("creationDate", "")
            di.expiration_date = out.get("expirationDate", "")
            di.name_servers = ", ".join(out.get("nameServers", [])) if isinstance(out.get("nameServers"), list) else str(out.get("nameServers", ""))
            di.status = ", ".join(out.get("status", [])) if isinstance(out.get("status"), list) else str(out.get("status", ""))
            di.rdap_error = error_msg
            if not existing:
                s.add(di)
            s.commit()
        
        if error_msg and not out.get("registrar") and not out.get("creationDate"):
            return {"error": error_msg, "domainName": domain}
        return out

    # DNS/SMTP 
    @app.get("/dns", response_class=HTMLResponse)
    def dns_page(request: Request):
        from sqlalchemy import text
        with db() as s:
            rows = s.execute(text(
                "SELECT domain, nameserver, status FROM dns_zone_transfers ORDER BY domain ASC, nameserver ASC"
            )).fetchall()
            # Group by domain
            grouped = {}
            for r in rows:
                domain = r[0] or "unknown"
                if domain not in grouped:
                    grouped[domain] = []
                grouped[domain].append({"nameserver": r[1], "status": r[2]})
        return templates.TemplateResponse("dns.html", {"request": request, "grouped": grouped})

    @app.get("/smtp", response_class=HTMLResponse)
    def smtp_page(request: Request):
        from sqlalchemy import text
        with db() as s:
            rows = s.execute(text(
                "SELECT mx_host, vrfy, expn, rcpt FROM smtp_scans ORDER BY mx_host ASC"
            )).fetchall()
            data = [{"mx_host": r[0], "vrfy": r[1], "expn": r[2], "rcpt": r[3]} for r in rows]
        return templates.TemplateResponse("smtp.html", {"request": request, "rows": data})

    return app
