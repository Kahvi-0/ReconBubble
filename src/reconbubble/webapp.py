from __future__ import annotations
from pathlib import Path
import json, ipaddress, re, socket
from urllib.parse import quote_plus, urlsplit
from datetime import datetime

from fastapi import FastAPI, Request, UploadFile, File, Form, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from sqlalchemy import select, func, text
from sqlalchemy.orm import Session

from .db import make_engine, make_session, Base, migrate_sqlite
from .workspace import Workspace
from .models import (
    Host,
    Service,
    Subdomain,
    Email,
    Artifact,
    ServiceEvidence,
    Document,
    Note,
    ScopeItem,
    CloudItem,
    ValidUser,
    Credential,
    SocialMedia,
    WebUrl,
    DomainInfo,
)
from .parsers import (
    upsert_artifact,
    import_nmap_xml,
    import_subdomains,
    import_emails,
    import_document,
    upsert_host,
    import_valid_users,
    import_credentials,
    import_web_urls,
    import_prowl_phase1,
    import_zone_transfers,
    import_smtp,
    import_bbot,
    import_bbot_cloud,
)

DOMAIN_RE = re.compile(
    r"(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.?$"
)


def create_app(
    db_path: Path, workspace_root: Path | None = None, project_name: str = ""
) -> FastAPI:
    ws = Workspace.from_db(db_path, workspace_root)
    engine = make_engine(ws.db_path)
    Base.metadata.create_all(engine)
    migrate_sqlite(engine)
    SessionLocal = make_session(engine)

    app = FastAPI(title="ReconBubble", docs_url=None, redoc_url=None)
    app.mount(
        "/static",
        StaticFiles(directory=Path(__file__).parent / "static"),
        name="static",
    )
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
    templates.env.globals["project_name"] = (project_name or "").strip()

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

    # ---- Scope helpers ----
    def scope_sets(s: Session, sensitive_only: bool = False):
        stmt = select(ScopeItem).where(ScopeItem.in_scope == 1)
        if sensitive_only:
            stmt = stmt.where(ScopeItem.sensitive == 1)
        items = s.execute(stmt).scalars().all()
        ips, subnets, domains, email_domains, domain_all_subs = (
            set(),
            [],
            set(),
            set(),
            set(),
        )
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

    def domain_in_scope(
        fqdn: str, domains: set[str], domain_all_subs: set[str]
    ) -> bool:
        f = (fqdn or "").strip().lower().strip(".")
        if not f:
            return False
        if f in domains:
            return True
        return any(f.endswith("." + d) for d in domain_all_subs)

    def host_in_scope(
        ip: str,
        hostname: str,
        ips: set[str],
        subnets: list,
        domains: set[str],
        domain_all_subs: set[str],
    ) -> bool:
        if ip_in_scope(ip, ips, subnets):
            return True
        if hostname and domain_in_scope(hostname, domains, domain_all_subs):
            return True
        return False

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
        rows = s.execute(
            text(
                "SELECT subdomains.fqdn FROM host_subdomains "
                "JOIN subdomains ON subdomains.id = host_subdomains.subdomain_id "
                "WHERE host_subdomains.host_id = :hid ORDER BY subdomains.fqdn ASC"
            ),
            {"hid": host_id},
        ).fetchall()
        return [r[0] for r in rows]

    def _split_lines(txt: str) -> list[str]:
        return [l.strip() for l in (txt or "").splitlines() if l.strip()]

    def list_subdomain_ips(s: Session, fqdn: str) -> list[str]:
        rows = s.execute(
            text(
                "SELECT hosts.ip FROM host_subdomains "
                "JOIN subdomains ON subdomains.id = host_subdomains.subdomain_id "
                "JOIN hosts ON hosts.id = host_subdomains.host_id "
                "WHERE subdomains.fqdn = :fq ORDER BY hosts.ip ASC"
            ),
            {"fq": fqdn},
        ).fetchall()
        return [r[0] for r in rows]

    def list_subdomain_hosts(s: Session, fqdn: str) -> list[dict]:
        rows = s.execute(
            text(
                "SELECT hosts.id, hosts.ip, hosts.hostname FROM host_subdomains "
                "JOIN subdomains ON subdomains.id = host_subdomains.subdomain_id "
                "JOIN hosts ON hosts.id = host_subdomains.host_id "
                "WHERE subdomains.fqdn = :fq ORDER BY hosts.ip ASC"
            ),
            {"fq": fqdn},
        ).fetchall()
        return [{"id": r[0], "ip": r[1], "hostname": r[2] or ""} for r in rows]

    def link_host_domain(s: Session, host_id: int, fqdn: str) -> None:
        fqdn = fqdn.strip().lower().rstrip(".")
        if not fqdn or not DOMAIN_RE.match(fqdn):
            return
        sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))
        if not sub:
            sub = Subdomain(fqdn=fqdn, root_domain=".".join(fqdn.split(".")[-2:]))
            s.add(sub)
            s.commit()
            s.refresh(sub)
        s.execute(
            text(
                "INSERT OR IGNORE INTO host_subdomains(host_id, subdomain_id, created_at) "
                "VALUES (:hid, :sid, :ts)"
            ),
            {"hid": host_id, "sid": sub.id, "ts": datetime.utcnow().isoformat()},
        )
        s.commit()

    def resolve_ips(fqdn: str) -> list[str]:
        fqdn = fqdn.strip().rstrip(".")
        out = set()
        try:
            for fam in (socket.AF_INET, socket.AF_INET6):
                try:
                    infos = socket.getaddrinfo(
                        fqdn, None, family=fam, type=socket.SOCK_STREAM
                    )
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
        return templates.TemplateResponse(
            "home.html", {"request": request, "stats": stats}
        )

    # Scope
    @app.get("/scope", response_class=HTMLResponse)
    def scope_page(request: Request):
        scope_error = (request.query_params.get("error") or "").strip()
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
                "scope_error": scope_error,
            },
        )

    @app.post("/scope/add")
    def scope_add(
        kind: str = Form(...),
        value: str = Form(""),
        values_raw: str = Form(""),
        note: str = Form(""),
        apply_all_subdomains: int = Form(0),
        sensitive: int = Form(0),
    ):
        items: list[str] = []
        if values_raw and values_raw.strip():
            items = [
                ln.strip()
                for ln in values_raw.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
        elif value and value.strip():
            items = [value.strip()]
        if not items:
            return RedirectResponse(url="/scope", status_code=303)

        if kind == "ip_or_subnet":
            invalid_items: list[str] = []
            normalized_items: list[str] = []
            for raw_item in items:
                raw_item = raw_item.strip()
                if "/" in raw_item:
                    try:
                        normalized_items.append(
                            str(ipaddress.ip_network(raw_item, strict=False))
                        )
                    except ValueError:
                        invalid_items.append(raw_item)
                else:
                    try:
                        normalized_items.append(str(ipaddress.ip_address(raw_item)))
                    except ValueError:
                        invalid_items.append(raw_item)

            if invalid_items:
                err = "Invalid IP/subnet format: " + ", ".join(invalid_items)
                return RedirectResponse(
                    url=f"/scope?error={quote_plus(err)}", status_code=303
                )
            items = normalized_items

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
                    apply_all_subdomains=1
                    if (actual_kind == "domain" and apply_all_subdomains == 1)
                    else 0,
                    sensitive=1 if sensitive == 1 else 0,
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

    @app.post("/scope/sensitive")
    def scope_sensitive(item_id: int = Form(...)):
        with db() as s:
            it = s.scalar(select(ScopeItem).where(ScopeItem.id == item_id))
            if it:
                it.sensitive = 0 if getattr(it, "sensitive", 0) == 1 else 1
                s.commit()
        return RedirectResponse(url="/scope", status_code=303)

    @app.post("/scope/delete")
    def scope_delete(item_id: int = Form(...)):
        with db() as s:
            it = s.scalar(select(ScopeItem).where(ScopeItem.id == item_id))
            if it:
                s.delete(it)
                s.commit()
        return RedirectResponse(url="/scope", status_code=303)

    # Upload
    @app.get("/upload", response_class=HTMLResponse)
    def upload_page(request: Request):
        return templates.TemplateResponse("upload.html", {"request": request})

    @app.post("/upload")
    async def upload(
        request: Request,
        kind: str = Form(...),
        file: list[UploadFile] | None = File(None),
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
                    "emails": "pasted_emails.txt",
                    "doc": "pasted_document.bin",
                    "users": "pasted_users.txt",
                    "creds": "pasted_creds.txt",
                    "urls": "pasted_urls.txt",
                }.get(kind, "pasted.txt")
                fname = (
                    raw_filename.strip()
                    if raw_filename and raw_filename.strip()
                    else default
                )
                stored = ws.store_text(raw_text, fname, prefix=kind)
                with db() as s:
                    art = upsert_artifact(s, kind, Path(stored))
                    if kind == "nmap_xml":
                        import_nmap_xml(s, art, Path(stored))
                    elif kind == "subdomains":
                        import_subdomains(s, art, Path(stored))
                        fqdn_list = s.execute(select(Subdomain.fqdn)).scalars().all()
                        for fqdn in fqdn_list:
                            for ip in resolve_ips(fqdn):
                                try:
                                    h = upsert_host(s, ip, "", "")
                                except Exception:
                                    continue
                                link_host_domain(s, h.id, fqdn)
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
                return RedirectResponse(url="/", status_code=303)
            elif file:
                files = file if isinstance(file, list) else [file]
                stored_files = []
                for f in files:
                    if f and f.filename:
                        tmp = ws.uploads_dir / f"tmp_{f.filename}"
                        tmp.write_bytes(await f.read())
                        stored = ws.store_upload(tmp, prefix=kind)
                        tmp.unlink(missing_ok=True)
                        stored_files.append(stored)
                if not stored_files:
                    return templates.TemplateResponse(
                        "upload.html",
                        {
                            "request": request,
                            "workspace": ws,
                            "error": "No valid files uploaded.",
                        },
                        status_code=400,
                    )
                with db() as s:
                    for stored_path in stored_files:
                        art = upsert_artifact(s, kind, Path(stored_path))
                        if kind == "nmap_xml":
                            import_nmap_xml(s, art, Path(stored_path))
                        elif kind == "subdomains":
                            import_subdomains(s, art, Path(stored_path))
                            fqdn_list = (
                                s.execute(select(Subdomain.fqdn)).scalars().all()
                            )
                            for fqdn in fqdn_list:
                                for ip in resolve_ips(fqdn):
                                    try:
                                        h = upsert_host(s, ip, "", "")
                                    except Exception:
                                        continue
                                    link_host_domain(s, h.id, fqdn)
                        elif kind == "emails":
                            import_emails(s, art, Path(stored_path))
                        elif kind == "doc":
                            import_document(s, art, Path(stored_path))
                        elif kind == "users":
                            import_valid_users(s, art, Path(stored_path))
                        elif kind == "creds":
                            import_credentials(s, art, Path(stored_path))
                        elif kind == "urls":
                            import_web_urls(s, art, Path(stored_path))
                        elif kind == "prowl_phase1":
                            import_prowl_phase1(s, art, Path(stored_path))
                        elif kind == "zone_transfers":
                            import_zone_transfers(s, art, Path(stored_path))
                        elif kind == "smtp":
                            import_smtp(s, art, Path(stored_path))
                        elif kind == "bbot":
                            result = import_bbot(s, art, Path(stored_path))
                            print(f"[bbot] Import complete: {result}")
                        elif kind == "bbot_cloud":
                            result = import_bbot_cloud(s, art, Path(stored_path))
                            print(f"[bbot_cloud] Import complete: {result}")
                return RedirectResponse(url="/", status_code=303)
            else:
                return templates.TemplateResponse(
                    "upload.html",
                    {
                        "request": request,
                        "workspace": ws,
                        "error": "No file uploaded and no raw text provided.",
                    },
                    status_code=400,
                )

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
        show_out = int(request.query_params.get("show_out", "0"))
        row_limit_raw = (request.query_params.get("row_limit", "0") or "0").strip()
        try:
            row_limit = max(0, int(row_limit_raw))
        except ValueError:
            row_limit = 0

        def subnet_sort_key(net):
            return (net.version, int(net.network_address), net.prefixlen)

        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs = scope_sets(
                s, sensitive_only=True
            )
            rows = s.execute(
                select(
                    Host.id,
                    Host.ip,
                    Host.hostname,
                    Host.done,
                    Host.complete,
                    Host.waf,
                    func.count(Service.id).label("svc_count"),
                )
                .outerjoin(Service, Service.host_id == Host.id)
                .group_by(Host.id)
                .order_by(func.count(Service.id).desc(), Host.ip.asc())
            ).all()
            domains_by_host = {r.id: list_host_domains(s, r.id) for r in rows}
        data = []
        for r in rows:
            ip_in = ip_in_scope(r.ip, ips, subnets)
            ip_sensitive = ip_in_scope(r.ip, s_ips, s_subnets)
            host_domains = domains_by_host.get(r.id, [])
            # Check scope for each individual domain
            domain_list = []
            any_domain_in = False
            any_domain_sensitive = False
            for d in host_domains:
                d_in = domain_in_scope(d, domains, domain_all_subs)
                d_sensitive = domain_in_scope(d, s_domains, s_domain_all_subs)
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
                    "waf": getattr(r, "waf", 0),
                    "svc_count": r.svc_count,
                    "ip_in_scope": ip_in,
                    "ip_sensitive": ip_sensitive,
                    "domain_in_scope": any_domain_in,
                    "in_scope": ip_in or any_domain_in,
                    "sensitive": ip_sensitive or any_domain_sensitive,
                    "domains": domain_list,
                }
            )

        in_scope_data = [d for d in data if d.get("in_scope")]
        filtered_data = data if show_out == 1 else in_scope_data

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

        for row in in_scope_data:
            label = classify_subnet_label(row.get("ip", ""), allow_infer=True)
            if not label:
                continue
            if label in subnet_stats:
                subnet_stats[label] = subnet_stats.get(label, 0) + 1
            else:
                inferred_stats[label] = inferred_stats.get(label, 0) + 1

        grouped: dict[str, list[dict]] = {}
        for row in filtered_data:
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

        total_before_limit = sum(len(v) for v in grouped_ordered.values())
        if row_limit > 0:
            limited_grouped: dict[str, list[dict]] = {}
            remaining = row_limit
            for name in ordered_group_names:
                if remaining <= 0:
                    break
                rows_in_group = grouped_ordered[name]
                take = rows_in_group[:remaining]
                if take:
                    limited_grouped[name] = take
                    remaining -= len(take)
            grouped_ordered = limited_grouped

        subnet_stats_list = [{"subnet": k, "count": v} for k, v in subnet_stats.items()]
        for k in sorted(
            inferred_stats.keys(),
            key=lambda name: subnet_sort_key(
                ipaddress.ip_network(name.split(": ", 1)[1], strict=False)
            ),
        ):
            subnet_stats_list.append({"subnet": k, "count": inferred_stats[k]})

        shown_count = sum(len(v) for v in grouped_ordered.values())
        return templates.TemplateResponse(
            "assets.html",
            {
                "request": request,
                "grouped": grouped_ordered,
                "show_out": show_out,
                "row_limit": row_limit,
                "shown_count": shown_count,
                "total_count": total_before_limit,
                "subnet_stats": subnet_stats_list,
                "in_scope_total": len(in_scope_data),
            },
        )

    @app.post("/api/host/create")
    def api_host_create(
        ip: str = Form(...), hostname: str = Form(""), domains_raw: str = Form("")
    ):
        ip = ip.strip()
        hostname = (hostname or "").strip()
        domains = [
            ln.strip().lower().rstrip(".")
            for ln in (domains_raw or "").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
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

    @app.post("/api/note/delete")
    def api_note_delete(note_id: int = Form(...)):
        with db() as s:
            n = s.scalar(select(Note).where(Note.id == note_id))
            if not n:
                return JSONResponse({"ok": False}, status_code=404)
            s.delete(n)
            s.commit()
        return {"ok": True}

    @app.get("/api/global-notes")
    def api_global_notes_get():
        with db() as s:
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

    @app.post("/api/global-notes")
    def api_global_notes_save(note: str = Form("")):
        note = note or ""
        with db() as s:
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
            },
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
    def api_host_update(
        host_id: int = Form(...),
        ip: str = Form(...),
        hostname: str = Form(""),
        os_guess: str = Form(""),
        domains_raw: str = Form(""),
    ):
        ip = ip.strip()
        hostname = (hostname or "").strip()
        os_guess = (os_guess or "").strip()
        domains = [
            ln.strip().lower().rstrip(".")
            for ln in (domains_raw or "").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
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

    @app.get("/service/{service_id}", response_class=HTMLResponse)
    def service_page(request: Request, service_id: int):
        with db() as s:
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
        return templates.TemplateResponse(
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

    @app.get("/api/subdomain")
    def api_subdomain(fqdn: str = Query(...)):
        fq = fqdn.strip().lower().rstrip(".")
        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs = scope_sets(
                s, sensitive_only=True
            )
            ips_found = list_subdomain_ips(s, fq)
            in_dom = domain_in_scope(fq, domains, domain_all_subs)
            in_ip = any(ip_in_scope(ip, ips, subnets) for ip in ips_found)
            sensitive_dom = domain_in_scope(fq, s_domains, s_domain_all_subs)
            sensitive_ip = any(ip_in_scope(ip, s_ips, s_subnets) for ip in ips_found)
            hosts = list_subdomain_hosts(s, fq)
        return {
            "ok": True,
            "fqdn": fq,
            "ips": ips_found,
            "in_scope": bool(in_dom or in_ip),
            "sensitive": bool(sensitive_dom or sensitive_ip),
            "hosts": hosts,
        }

    # Internal
    def _default_checklist_map(map_name: str) -> dict:
        if map_name == "authenticated":
            return {
                "title": "Domain Auth Checklist",
                "phase_label": "Enumeration",
                "nodes": [
                    {
                        "key": "adcs",
                        "label": "ADCS Enumeration",
                        "color_start": "#1abc9c",
                        "color_end": "#148f77",
                        "initial": 1,
                        "exploit_text": "Map templates and enrollment rights for ESC paths.",
                    },
                    {
                        "key": "ldap_security",
                        "label": "LDAP Security (Signing / Binding)",
                        "color_start": "#2980b9",
                        "color_end": "#1f618d",
                        "initial": 1,
                        "exploit_text": "Test for relay-enabling LDAP security misconfigurations.",
                    },
                    {
                        "key": "smb_signing",
                        "label": "SMB Signing",
                        "color_start": "#8e44ad",
                        "color_end": "#6c3483",
                        "initial": 1,
                        "exploit_text": "Validate SMB signing enforcement and relay viability.",
                    },
                    {
                        "key": "ntlmv1",
                        "label": "NTLMv1",
                        "color_start": "#b91c1c",
                        "color_end": "#7f1d1d",
                        "initial": 1,
                        "exploit_text": "Identify NTLMv1 usage and prioritize downgrade/crack abuse paths.",
                    },
                    {
                        "key": "endpoint_detection",
                        "label": "Endpoint Protection Detected",
                        "color_start": "#2ecc71",
                        "color_end": "#1e8449",
                        "initial": 1,
                        "exploit_text": "Identify endpoint protection coverage and bypass opportunities.",
                    },
                    {
                        "key": "domain_trusts",
                        "label": "Domain Trusts",
                        "color_start": "#e74c3c",
                        "color_end": "#c0392b",
                        "initial": 1,
                        "exploit_text": "Review trust boundaries and abuse paths.",
                    },
                    {
                        "key": "weak_user_flags",
                        "label": "Weak User Flags",
                        "color_start": "#3498db",
                        "color_end": "#2980b9",
                        "initial": 1,
                        "exploit_text": "Assess weak account control settings.",
                    },
                    {
                        "key": "accounts_no_password",
                        "label": "Accounts That Do Not Require Passwords",
                        "color_start": "#c0392b",
                        "color_end": "#922b21",
                        "initial": 1,
                        "exploit_text": "Identify accounts configured with password-not-required behavior and validate abuse paths.",
                    },
                    {
                        "key": "insecure_domain_priv_dacl",
                        "label": "Insecure Domain Privileges and DACL",
                        "color_start": "#7c2d12",
                        "color_end": "#9a3412",
                        "initial": 1,
                        "exploit_text": "Track risky delegated privileges and DACL misconfigurations that enable privilege escalation.",
                    },
                    {
                        "key": "pre2k_auth",
                        "label": "Pre2k Computer Account Checks",
                        "color_start": "#334155",
                        "color_end": "#1e293b",
                        "initial": 1,
                        "exploit_text": "Test legacy machine-account naming/password patterns for weak auth.",
                    },
                    {
                        "key": "ldap_descriptions",
                        "label": "LDAP Descriptions Harvest",
                        "color_start": "#9b59b6",
                        "color_end": "#8e44ad",
                        "initial": 1,
                        "exploit_text": "Look for secrets and internal metadata in descriptions.",
                    },
                    {
                        "key": "maq",
                        "label": "MachineAccountQuota (MAQ)",
                        "color_start": "#16a085",
                        "color_end": "#117864",
                        "initial": 1,
                        "exploit_text": "Check if machine account creation can be abused.",
                    },
                    {
                        "key": "gpo_enum",
                        "label": "Domain GPO Enumeration",
                        "color_start": "#d35400",
                        "color_end": "#a04000",
                        "initial": 1,
                        "exploit_text": "Identify writable or risky GPOs and scripts.",
                    },
                    {
                        "key": "sysvol_policy",
                        "label": "SYSVOL Password Policy Parsing",
                        "color_start": "#2c3e50",
                        "color_end": "#1f2d3a",
                        "initial": 1,
                        "exploit_text": "Validate lockout and complexity weaknesses.",
                    },
                    {
                        "key": "dangerous_attrs",
                        "label": "Dangerous LDAP Attributes",
                        "color_start": "#7f8c8d",
                        "color_end": "#566573",
                        "initial": 1,
                        "exploit_text": "Identify exposed password-like attributes.",
                    },
                    {
                        "key": "kerberoast",
                        "label": "Kerberoastable Accounts",
                        "color_start": "#8e44ad",
                        "color_end": "#6c3483",
                        "initial": 1,
                        "exploit_text": "Find service accounts vulnerable to Kerberoasting.",
                    },
                    {
                        "key": "asreproast",
                        "label": "AS-REP Roastable Accounts",
                        "color_start": "#c0392b",
                        "color_end": "#922b21",
                        "initial": 1,
                        "exploit_text": "Find users with pre-auth disabled.",
                    },
                    {
                        "key": "unconstrained_delegation",
                        "label": "Unconstrained Delegation",
                        "color_start": "#f39c12",
                        "color_end": "#b9770e",
                        "initial": 1,
                        "exploit_text": "Identify hosts/users allowing unconstrained delegation abuse.",
                    },
                    {
                        "key": "constrained_delegation",
                        "label": "Constrained Delegation",
                        "color_start": "#27ae60",
                        "color_end": "#1e8449",
                        "initial": 1,
                        "exploit_text": "Assess S4U abuse paths on constrained delegation objects.",
                    },
                    {
                        "key": "rbcd",
                        "label": "RBCD",
                        "color_start": "#e67e22",
                        "color_end": "#af601a",
                        "initial": 1,
                        "exploit_text": "Assess msDS-AllowedToActOnBehalfOfOtherIdentity abuse paths.",
                    },
                    {
                        "key": "laps",
                        "label": "LAPS Presence Check",
                        "color_start": "#5dade2",
                        "color_end": "#2e86c1",
                        "initial": 1,
                        "exploit_text": "Determine LAPS deployment and read-access exposure.",
                    },
                    {
                        "key": "sccm",
                        "label": "SCCM Discovery",
                        "color_start": "#884ea0",
                        "color_end": "#6c3483",
                        "initial": 1,
                        "exploit_text": "Evaluate SCCM infrastructure and takeover opportunities.",
                    },
                    {
                        "key": "mssql",
                        "label": "MSSQL Host Discovery",
                        "color_start": "#cb4335",
                        "color_end": "#943126",
                        "initial": 1,
                        "exploit_text": "Identify SQL hosts and credential/delegation pivot paths.",
                    },
                    {
                        "key": "wsus",
                        "label": "WSUS Discovery",
                        "color_start": "#17a589",
                        "color_end": "#117a65",
                        "initial": 1,
                        "exploit_text": "Assess WSUS trust and update-delivery abuse risk.",
                    },
                    {
                        "key": "managed_service_accounts",
                        "label": "Managed Service Accounts",
                        "color_start": "#7d3c98",
                        "color_end": "#5b2c6f",
                        "initial": 1,
                        "exploit_text": "Assess gMSA/MSA retrieval permissions and abuse paths.",
                    },
                    {
                        "key": "protected_users",
                        "label": "Protected Users Membership",
                        "color_start": "#34495e",
                        "color_end": "#212f3d",
                        "initial": 1,
                        "exploit_text": "Validate hardening coverage for protected accounts.",
                    },
                    {
                        "key": "legacy_hosts",
                        "label": "Obsolete Host / Legacy OS",
                        "color_start": "#a04000",
                        "color_end": "#6e2c00",
                        "initial": 1,
                        "exploit_text": "Prioritize legacy systems with high exploitability.",
                    },
                    {
                        "key": "dns_permissions",
                        "label": "DNS Permissions",
                        "color_start": "#566573",
                        "color_end": "#2e4053",
                        "initial": 1,
                        "exploit_text": "Assess dynamic update and ACL abuse opportunities.",
                    },
                ],
                "edges": [
                    {
                        "from": "ldap_security",
                        "to": "rbcd",
                        "label": "Relay/identity chain",
                    },
                    {
                        "from": "kerberoast",
                        "to": "constrained_delegation",
                        "label": "Credential to delegation pivot",
                    },
                    {
                        "from": "asreproast",
                        "to": "kerberoast",
                        "label": "Credential capture progression",
                    },
                ],
                "vuln_branches": [
                    {
                        "id": "trust_external_forest",
                        "parent_id": "domain_trusts",
                        "label": "External/forest trust misconfig",
                        "title": "Trust Misconfiguration",
                        "text": "Validate filtering, SID history protections, and trust direction weaknesses.",
                    },
                    {
                        "id": "trust_sidhistory",
                        "parent_id": "domain_trusts",
                        "label": "SIDHistory abuse path",
                        "title": "SIDHistory Abuse",
                        "text": "Test SIDHistory injection paths across trust boundaries.",
                    },
                    {
                        "id": "trust_selective_auth",
                        "parent_id": "domain_trusts",
                        "label": "Selective auth bypass checks",
                        "title": "Selective Auth Review",
                        "text": "Assess selective authentication controls and bypass opportunities.",
                    },
                    {
                        "id": "flags_no_pwd",
                        "parent_id": "weak_user_flags",
                        "label": "No Password Required users",
                        "title": "No Password Required",
                        "text": "Validate accounts with weak UAC flags and prioritise privileged accounts.",
                    },
                    {
                        "id": "flags_smartcard",
                        "parent_id": "weak_user_flags",
                        "label": "Smartcard-required edge cases",
                        "title": "Smartcard Required Edge Cases",
                        "text": "Check for fallback auth paths and inconsistent enforcement.",
                    },
                    {
                        "id": "flags_no_deleg",
                        "parent_id": "weak_user_flags",
                        "label": "No delegation accounts review",
                        "title": "No Delegation Review",
                        "text": "Verify protected accounts are correctly flagged and applied.",
                    },
                    {
                        "id": "desc_creds",
                        "parent_id": "ldap_descriptions",
                        "label": "Credentials in descriptions",
                        "title": "Credential Leakage",
                        "text": "Look for passwords/tokens/API keys in description fields.",
                    },
                    {
                        "id": "desc_internal",
                        "parent_id": "ldap_descriptions",
                        "label": "Internal URLs/hosts leakage",
                        "title": "Internal Metadata Leakage",
                        "text": "Map leaked hostnames and internal endpoints for pivoting.",
                    },
                    {
                        "id": "desc_service",
                        "parent_id": "ldap_descriptions",
                        "label": "Service account clues",
                        "title": "Service Account Clues",
                        "text": "Extract service identities and infer privilege relationships.",
                    },
                    {
                        "id": "maq_gt_zero",
                        "parent_id": "maq",
                        "label": "MAQ > 0 exploitation path",
                        "title": "MAQ Abuse",
                        "text": "Create machine account and chain into delegation abuse paths.",
                    },
                    {
                        "id": "maq_computer_create",
                        "parent_id": "maq",
                        "label": "Computer account creation abuse",
                        "title": "Computer Account Creation",
                        "text": "Assess ability to create and control machine identities.",
                    },
                    {
                        "id": "maq_rbcd_chain",
                        "parent_id": "maq",
                        "label": "RBCD chain setup",
                        "title": "MAQ to RBCD",
                        "text": "Link newly created machine account to RBCD attack chain.",
                    },
                    {
                        "id": "gpo_writable",
                        "parent_id": "gpo_enum",
                        "label": "Writable GPO paths",
                        "title": "Writable GPO",
                        "text": "Identify ACL misconfigs enabling policy/script tampering.",
                    },
                    {
                        "id": "gpo_scripts",
                        "parent_id": "gpo_enum",
                        "label": "Risky startup/logon scripts",
                        "title": "Risky Scripts",
                        "text": "Review scripts for command injection and credential exposure.",
                    },
                    {
                        "id": "gpo_priv_assign",
                        "parent_id": "gpo_enum",
                        "label": "Privilege assignment abuse",
                        "title": "Privilege Assignment Abuse",
                        "text": "Abuse dangerous user-right assignments from linked GPOs.",
                    },
                    {
                        "id": "sysvol_lockout",
                        "parent_id": "sysvol_policy",
                        "label": "Weak lockout policy",
                        "title": "Weak Lockout",
                        "text": "Low lockout thresholds enable effective spraying.",
                    },
                    {
                        "id": "sysvol_complexity",
                        "parent_id": "sysvol_policy",
                        "label": "Weak complexity policy",
                        "title": "Weak Complexity",
                        "text": "Inadequate complexity controls reduce cracking cost.",
                    },
                    {
                        "id": "sysvol_spray_window",
                        "parent_id": "sysvol_policy",
                        "label": "Spray window identified",
                        "title": "Spray Window",
                        "text": "Use reset durations and thresholds to tune spray cadence.",
                    },
                    {
                        "id": "attrs_userpwd",
                        "parent_id": "dangerous_attrs",
                        "label": "userPassword found",
                        "title": "userPassword Exposure",
                        "text": "Validate plaintext/legacy password attribute exposure.",
                    },
                    {
                        "id": "attrs_unicodepwd",
                        "parent_id": "dangerous_attrs",
                        "label": "unicodePwd indicators",
                        "title": "unicodePwd Indicators",
                        "text": "Investigate unexpected password data artifacts.",
                    },
                    {
                        "id": "attrs_legacy",
                        "parent_id": "dangerous_attrs",
                        "label": "Other legacy password attrs",
                        "title": "Legacy Password Attributes",
                        "text": "Review msSFU30Password/dbCSPwd and similar fields.",
                    },
                    {
                        "id": "kerb_high_value",
                        "parent_id": "kerberoast",
                        "label": "High-value SPN accounts",
                        "title": "High-Value SPNs",
                        "text": "Prioritise SPNs linked to admin/service control contexts.",
                    },
                    {
                        "id": "kerb_rc4",
                        "parent_id": "kerberoast",
                        "label": "RC4-enabled targets",
                        "title": "RC4 Targets",
                        "text": "Prefer targets with weaker encryption for cracking success.",
                    },
                    {
                        "id": "kerb_cracked",
                        "parent_id": "kerberoast",
                        "label": "Cracked hash follow-up",
                        "title": "Cracked Credential Follow-up",
                        "text": "Validate lateral movement and privilege gained from cracked creds.",
                    },
                    {
                        "id": "asrep_preauth",
                        "parent_id": "asreproast",
                        "label": "Pre-auth disabled users",
                        "title": "Pre-auth Disabled",
                        "text": "Enumerate users with UF_DONT_REQUIRE_PREAUTH set.",
                    },
                    {
                        "id": "asrep_cracked",
                        "parent_id": "asreproast",
                        "label": "Cracked credential follow-up",
                        "title": "AS-REP Crack Follow-up",
                        "text": "Use recovered credentials for privilege and path validation.",
                    },
                    {
                        "id": "asrep_priv_context",
                        "parent_id": "asreproast",
                        "label": "Privilege context validation",
                        "title": "Privilege Context",
                        "text": "Map cracked users to groups and delegated rights.",
                    },
                    {
                        "id": "adcs_esc1",
                        "parent_id": "adcs",
                        "label": "ESC1 candidate templates",
                        "title": "ESC1 Candidates",
                        "text": "Find client-auth templates with dangerous enrollment controls.",
                    },
                    {
                        "id": "adcs_esc23",
                        "parent_id": "adcs",
                        "label": "ESC2/ESC3 checks",
                        "title": "ESC2/ESC3 Checks",
                        "text": "Assess alternate template abuse and agent constraints.",
                    },
                    {
                        "id": "adcs_enroll_rights",
                        "parent_id": "adcs",
                        "label": "Enrollment rights abuse",
                        "title": "Enrollment Rights Abuse",
                        "text": "Identify low-priv users with enrollment rights on risky templates.",
                    },
                    {
                        "id": "ldap_signing_off",
                        "parent_id": "ldap_security",
                        "label": "Signing not required",
                        "title": "LDAP Signing Disabled",
                        "text": "Validate unsigned LDAP channel exploitation/relay viability.",
                    },
                    {
                        "id": "ldap_binding_off",
                        "parent_id": "ldap_security",
                        "label": "Channel binding not enforced",
                        "title": "LDAP Binding Weak",
                        "text": "Assess missing channel-binding protections for relay chains.",
                    },
                    {
                        "id": "ldap_relay",
                        "parent_id": "ldap_security",
                        "label": "Relay path validation",
                        "title": "LDAP Relay Path",
                        "text": "Confirm practical relay path in the target environment.",
                    },
                    {
                        "id": "smb_signing_required",
                        "parent_id": "smb_signing",
                        "label": "Signing not required",
                        "title": "SMB Signing Weak",
                        "text": "Identify hosts where SMB signing is not enforced.",
                    },
                    {
                        "id": "smb_relay_path",
                        "parent_id": "smb_signing",
                        "label": "SMB relay path validation",
                        "title": "SMB Relay Path",
                        "text": "Validate practical NTLM relay paths via SMB services.",
                    },
                    {
                        "id": "smb_coercion",
                        "parent_id": "smb_signing",
                        "label": "Coercion opportunities",
                        "title": "SMB Coercion",
                        "text": "Check coercion vectors that force auth to relay targets.",
                    },
                    {
                        "id": "ntlmv1_hosts",
                        "parent_id": "ntlmv1",
                        "label": "NTLMv1 detected on hosts",
                        "title": "NTLMv1 Hosts",
                        "text": "Record hosts/services still accepting NTLMv1.",
                    },
                    {
                        "id": "ntlmv1_downgrade",
                        "parent_id": "ntlmv1",
                        "label": "Downgrade/coercion path",
                        "title": "Downgrade Path",
                        "text": "Validate downgrade or coercion paths forcing NTLMv1 auth.",
                    },
                    {
                        "id": "ntlmv1_crack",
                        "parent_id": "ntlmv1",
                        "label": "Captured challenge crackable",
                        "title": "Crackability",
                        "text": "Assess crack feasibility and credential reuse impact.",
                    },
                    {
                        "id": "endpoint_edr",
                        "parent_id": "endpoint_detection",
                        "label": "EDR",
                        "title": "EDR Present",
                        "text": "Document vendor/coverage and validate realistic bypass paths.",
                    },
                    {
                        "id": "endpoint_antivirus",
                        "parent_id": "endpoint_detection",
                        "label": "Antivirus",
                        "title": "Antivirus Present",
                        "text": "Document AV controls, signatures, and likely payload constraints.",
                    },
                    {
                        "id": "ud_host_compromise",
                        "parent_id": "unconstrained_delegation",
                        "label": "Delegation host compromise path",
                        "title": "Host Compromise Path",
                        "text": "Target unconstrained hosts for ticket capture opportunities.",
                    },
                    {
                        "id": "ud_ticket_capture",
                        "parent_id": "unconstrained_delegation",
                        "label": "Ticket capture opportunity",
                        "title": "Ticket Capture",
                        "text": "Capture and reuse inbound TGT/TGS material.",
                    },
                    {
                        "id": "ud_da_impersonation",
                        "parent_id": "unconstrained_delegation",
                        "label": "DA impersonation validation",
                        "title": "DA Impersonation",
                        "text": "Validate impersonation of high-privilege users via delegation.",
                    },
                    {
                        "id": "cd_s4u",
                        "parent_id": "constrained_delegation",
                        "label": "S4U2Self/S4U2Proxy abuse",
                        "title": "S4U Abuse",
                        "text": "Test constrained delegation principals for S4U abuse.",
                    },
                    {
                        "id": "cd_target_expand",
                        "parent_id": "constrained_delegation",
                        "label": "Service target expansion",
                        "title": "Service Target Expansion",
                        "text": "Map reachable SPNs and constrained target scope.",
                    },
                    {
                        "id": "cd_sensitive_imp",
                        "parent_id": "constrained_delegation",
                        "label": "Sensitive account impersonation",
                        "title": "Sensitive Impersonation",
                        "text": "Assess impersonation impact against privileged identities.",
                    },
                    {
                        "id": "rbcd_writable_obj",
                        "parent_id": "rbcd",
                        "label": "Writable computer object path",
                        "title": "Writable Object Path",
                        "text": "Find writable machine objects for msDS-AllowedToAct abuse.",
                    },
                    {
                        "id": "rbcd_set_attr",
                        "parent_id": "rbcd",
                        "label": "Set AllowedToAct attribute",
                        "title": "Set AllowedToAct",
                        "text": "Set msDS-AllowedToActOnBehalfOfOtherIdentity on target object.",
                    },
                    {
                        "id": "rbcd_impersonate",
                        "parent_id": "rbcd",
                        "label": "Impersonation to target service",
                        "title": "RBCD Impersonation",
                        "text": "Use S4U chain to impersonate users to target services.",
                    },
                    {
                        "id": "laps_missing",
                        "parent_id": "laps",
                        "label": "LAPS missing",
                        "title": "LAPS Missing",
                        "text": "No managed local admin password control present.",
                    },
                    {
                        "id": "laps_acl",
                        "parent_id": "laps",
                        "label": "LAPS ACL overexposed",
                        "title": "LAPS ACL Exposure",
                        "text": "Too many principals can read LAPS-managed passwords.",
                    },
                    {
                        "id": "laps_read_abuse",
                        "parent_id": "laps",
                        "label": "Password read permission abuse",
                        "title": "LAPS Read Abuse",
                        "text": "Exploit excessive LAPS read rights for local admin access.",
                    },
                    {
                        "id": "sccm_takeover",
                        "parent_id": "sccm",
                        "label": "SCCM site takeover path",
                        "title": "SCCM Takeover",
                        "text": "Assess SCCM role trust for administrative takeover.",
                    },
                    {
                        "id": "sccm_client_push",
                        "parent_id": "sccm",
                        "label": "Client push account abuse",
                        "title": "Client Push Abuse",
                        "text": "Test client push credentials/permissions for lateral movement.",
                    },
                    {
                        "id": "sccm_dp_trust",
                        "parent_id": "sccm",
                        "label": "Distribution point trust abuse",
                        "title": "DP Trust Abuse",
                        "text": "Abuse content distribution trust and package execution paths.",
                    },
                    {
                        "id": "mssql_auth",
                        "parent_id": "mssql",
                        "label": "Weak SQL auth / trusted links",
                        "title": "SQL Auth Weakness",
                        "text": "Check weak SQL auth, linked servers, and trust misconfigs.",
                    },
                    {
                        "id": "mssql_xpcmd",
                        "parent_id": "mssql",
                        "label": "xp_cmdshell path",
                        "title": "xp_cmdshell Abuse",
                        "text": "Assess command execution via xp_cmdshell and proxy contexts.",
                    },
                    {
                        "id": "mssql_service_pivot",
                        "parent_id": "mssql",
                        "label": "Service account pivot",
                        "title": "Service Account Pivot",
                        "text": "Pivot using SQL service account privileges and delegation.",
                    },
                    {
                        "id": "wsus_insecure",
                        "parent_id": "wsus",
                        "label": "Insecure WSUS config",
                        "title": "Insecure WSUS",
                        "text": "Review WSUS transport/signing and policy constraints.",
                    },
                    {
                        "id": "wsus_http_unsigned",
                        "parent_id": "wsus",
                        "label": "HTTP/unsigned update path",
                        "title": "Unsigned Update Path",
                        "text": "Test unsigned update acceptance and transport downgrade.",
                    },
                    {
                        "id": "wsus_client_trust",
                        "parent_id": "wsus",
                        "label": "Client trust abuse",
                        "title": "Client Trust Abuse",
                        "text": "Exploit client trust in rogue or tampered update paths.",
                    },
                    {
                        "id": "pre2k_auth_hostlist",
                        "parent_id": "pre2k_auth",
                        "label": "Hostname list built",
                        "title": "Pre2k Candidate Hostnames",
                        "text": "Prepared host-derived candidate machine accounts for pre2k checks.",
                    },
                    {
                        "id": "pre2k_auth_userpass",
                        "parent_id": "pre2k_auth",
                        "label": "hostname$:hostname hit",
                        "title": "Pre2k Default Pattern Hit",
                        "text": "Legacy computer-account password pattern produced successful auth.",
                    },
                    {
                        "id": "pre2k_auth_blank",
                        "parent_id": "pre2k_auth",
                        "label": "Blank machine password works",
                        "title": "Blank Machine Password",
                        "text": "Blank password accepted for candidate machine account.",
                    },
                    {
                        "id": "msa_principals",
                        "parent_id": "managed_service_accounts",
                        "label": "Overbroad retrieval principals",
                        "title": "Overbroad Retrieval",
                        "text": "Too many principals allowed to retrieve managed passwords.",
                    },
                    {
                        "id": "msa_gmsa_retrieval",
                        "parent_id": "managed_service_accounts",
                        "label": "gMSA retrieval abuse",
                        "title": "gMSA Retrieval Abuse",
                        "text": "Abuse retrieval rights to obtain gMSA credentials.",
                    },
                    {
                        "id": "msa_priv_pivot",
                        "parent_id": "managed_service_accounts",
                        "label": "Service account privilege pivot",
                        "title": "Service Account Pivot",
                        "text": "Use managed account context for privilege escalation paths.",
                    },
                    {
                        "id": "protected_missing",
                        "parent_id": "protected_users",
                        "label": "Expected protected admins missing",
                        "title": "Missing Protected Users",
                        "text": "Critical admins absent from Protected Users group.",
                    },
                    {
                        "id": "protected_bypass",
                        "parent_id": "protected_users",
                        "label": "Policy bypass opportunities",
                        "title": "Protection Bypass",
                        "text": "Identify alternate auth paths bypassing expected restrictions.",
                    },
                    {
                        "id": "protected_fallback",
                        "parent_id": "protected_users",
                        "label": "Fallback auth path checks",
                        "title": "Fallback Auth Review",
                        "text": "Validate NTLM/legacy fallback isn't available for protected accounts.",
                    },
                    {
                        "id": "legacy_proto",
                        "parent_id": "legacy_hosts",
                        "label": "Legacy protocol exposure",
                        "title": "Legacy Protocols",
                        "text": "SMBv1/NTLMv1/old cipher support on legacy systems.",
                    },
                    {
                        "id": "legacy_exploitable",
                        "parent_id": "legacy_hosts",
                        "label": "Known exploitable OS targets",
                        "title": "Known Exploitable Targets",
                        "text": "Prioritize hosts with known unpatched exploit paths.",
                    },
                    {
                        "id": "legacy_patch_gap",
                        "parent_id": "legacy_hosts",
                        "label": "Patch/segmentation gap",
                        "title": "Patch and Segmentation Gap",
                        "text": "Assess segmentation failures and patch debt on legacy hosts.",
                    },
                    {
                        "id": "dns_dynamic",
                        "parent_id": "dns_permissions",
                        "label": "Dynamic update abuse",
                        "title": "Dynamic Update Abuse",
                        "text": "Assess unauthenticated/weakly-authenticated update permissions.",
                    },
                    {
                        "id": "dns_acl",
                        "parent_id": "dns_permissions",
                        "label": "Zone ACL misconfig",
                        "title": "Zone ACL Misconfiguration",
                        "text": "Review zone ACLs for writable records by low-priv users.",
                    },
                    {
                        "id": "dns_hijack",
                        "parent_id": "dns_permissions",
                        "label": "Record hijack path",
                        "title": "Record Hijack",
                        "text": "Exploit writable DNS records for relay and service redirection.",
                    },
                ],
            }
        return {
            "title": "Domain Unauth Checklist",
            "phase_label": "Enumeration",
            "nodes": [
                {
                    "key": "traffic_capture",
                    "label": "Network Traffic Baseline",
                    "color_start": "#2563eb",
                    "color_end": "#1d4ed8",
                    "initial": 1,
                    "exploit_text": "Capture baseline traffic and identify broadcast/authentication opportunities.",
                },
                {
                    "key": "network_equipment",
                    "label": "Network Equipment Discovery",
                    "color_start": "#0f766e",
                    "color_end": "#115e59",
                    "initial": 1,
                    "exploit_text": "Map infrastructure devices and management-plane exposure from passive data.",
                },
                {
                    "key": "dns_dc_discovery",
                    "label": "Find DNS / Domain Controllers",
                    "color_start": "#7c3aed",
                    "color_end": "#6d28d9",
                    "initial": 1,
                    "exploit_text": "Identify name servers and DCs via resolv/nslookup/SRV records.",
                },
                {
                    "key": "guest_null_sessions",
                    "label": "Guest / Null Session Enumeration",
                    "color_start": "#b45309",
                    "color_end": "#92400e",
                    "initial": 1,
                    "exploit_text": "Test anonymous SMB/RPC access and collect shares/users/policy data.",
                },
                {
                    "key": "smb_security",
                    "label": "SMB Security Weaknesses",
                    "color_start": "#9333ea",
                    "color_end": "#7e22ce",
                    "initial": 1,
                    "exploit_text": "Track SMB signing disabled and SMBv1 exposure for relay and legacy abuse.",
                },
                {
                    "key": "responder_poisoning",
                    "label": "LLMNR/NBNS Poisoning (Responder)",
                    "color_start": "#dc2626",
                    "color_end": "#b91c1c",
                    "initial": 1,
                    "exploit_text": "Validate poisoning opportunities and capture authentication attempts safely.",
                },
                {
                    "key": "mitm6_relay",
                    "label": "IPv6 MITM / NTLM Relay",
                    "color_start": "#0891b2",
                    "color_end": "#0e7490",
                    "initial": 1,
                    "exploit_text": "Assess mitm6 + ntlmrelayx path to LDAP/SMB/ADCS targets.",
                },
                {
                    "key": "ldap_unauth",
                    "label": "LDAP Unauthenticated Access",
                    "color_start": "#4f46e5",
                    "color_end": "#4338ca",
                    "initial": 1,
                    "exploit_text": "Test unauthenticated bind and LDAP-based user discovery opportunities.",
                },
                {
                    "key": "valid_user_discovery",
                    "label": "Valid User Discovery",
                    "color_start": "#15803d",
                    "color_end": "#166534",
                    "initial": 1,
                    "exploit_text": "Build/verify a valid user list through LDAP, Kerberos, and external sources.",
                },
                {
                    "key": "password_attacks",
                    "label": "Password Attack Paths",
                    "color_start": "#be123c",
                    "color_end": "#9f1239",
                    "initial": 1,
                    "exploit_text": "Run low-noise spray checks aligned to policy windows and engagement limits.",
                },
                {
                    "key": "asrep_roast",
                    "label": "AS-REP Roasting",
                    "color_start": "#b91c1c",
                    "color_end": "#991b1b",
                    "initial": 1,
                    "exploit_text": "Check blind AS-REP roastability and prioritize crackable/high-value accounts.",
                },
                {
                    "key": "kerberoast_blind",
                    "label": "Blind Kerberoast",
                    "color_start": "#a16207",
                    "color_end": "#854d0e",
                    "initial": 1,
                    "exploit_text": "Test no-preauth chaining paths for SPN roast opportunities without creds.",
                },
                {
                    "key": "timeroast",
                    "label": "Timeroast",
                    "color_start": "#0d9488",
                    "color_end": "#0f766e",
                    "initial": 1,
                    "exploit_text": "Validate SNTP-based roastability and extract usable hashes.",
                },
                {
                    "key": "pre2k",
                    "label": "Pre2k Computer Account Checks",
                    "color_start": "#334155",
                    "color_end": "#1e293b",
                    "initial": 1,
                    "exploit_text": "Test legacy machine-account naming/password patterns for weak auth.",
                },
                {
                    "key": "sccm_unauth",
                    "label": "SCCM Unauthenticated Vulnerabilities",
                    "color_start": "#6d28d9",
                    "color_end": "#5b21b6",
                    "initial": 1,
                    "exploit_text": "Track SCCM servers and validate unauthenticated vulnerability paths.",
                },
                {
                    "key": "auth_coerce",
                    "label": "Authentication Coercion",
                    "color_start": "#ea580c",
                    "color_end": "#c2410c",
                    "initial": 1,
                    "exploit_text": "Validate coercion vectors and whether relay targets are practically reachable.",
                },
                {
                    "key": "adcs_relay",
                    "label": "ADCS Relay Opportunities",
                    "color_start": "#0369a1",
                    "color_end": "#075985",
                    "initial": 1,
                    "exploit_text": "Identify certsrv endpoints and validate NTLM relay-to-ADCS feasibility.",
                },
                {
                    "key": "dns_updates",
                    "label": "Anonymous DNS Updates",
                    "color_start": "#7c2d12",
                    "color_end": "#9a3412",
                    "initial": 1,
                    "exploit_text": "Assess non-secure/anonymous dynamic DNS update risk and relay implications.",
                },
                {
                    "key": "wsus_unauth",
                    "label": "WSUS Discovery (Unauth)",
                    "color_start": "#166534",
                    "color_end": "#14532d",
                    "initial": 1,
                    "exploit_text": "Check unauth WSUS discovery paths before authenticated validation.",
                },
                {
                    "key": "web_applications",
                    "label": "Web Applications",
                    "color_start": "#0369a1",
                    "color_end": "#0c4a6e",
                    "initial": 1,
                    "exploit_text": "Check internal web apps for default credentials and practical exploit paths.",
                },
            ],
            "edges": [
                {
                    "from": "traffic_capture",
                    "to": "responder_poisoning",
                    "label": "Broadcast intel",
                },
                {
                    "from": "dns_dc_discovery",
                    "to": "guest_null_sessions",
                    "label": "Target list",
                },
                {"from": "smb_security", "to": "mitm6_relay", "label": "Relay targets"},
                {
                    "from": "valid_user_discovery",
                    "to": "password_attacks",
                    "label": "Spray input",
                },
                {"from": "auth_coerce", "to": "adcs_relay", "label": "Coerce to relay"},
            ],
            "vuln_branches": [
                {
                    "id": "traffic_llmnr",
                    "parent_id": "traffic_capture",
                    "label": "LLMNR/NBNS observed",
                    "title": "Broadcast Name Resolution",
                    "text": "LLMNR/NBNS traffic observed; poisoning and capture paths likely present.",
                },
                {
                    "id": "traffic_ipv6",
                    "parent_id": "traffic_capture",
                    "label": "IPv6 auth traffic observed",
                    "title": "IPv6 Authentication Traffic",
                    "text": "IPv6 auth chatter present; mitm6/relay path may be viable.",
                },
                {
                    "id": "traffic_sensitive",
                    "parent_id": "traffic_capture",
                    "label": "Sensitive data in capture",
                    "title": "Sensitive Packet Data",
                    "text": "Review PCAP for leaked creds, tokens, hostnames, and internal service clues.",
                },
                {
                    "id": "equip_arp",
                    "parent_id": "network_equipment",
                    "label": "ARP MACs translated",
                    "title": "ARP Device Identification",
                    "text": "Mapped MAC OUIs to likely vendors/network gear.",
                },
                {
                    "id": "equip_cdp",
                    "parent_id": "network_equipment",
                    "label": "CDP/LLDP discovered",
                    "title": "Discovery Protocol Exposure",
                    "text": "CDP/LLDP details exposed topology and device metadata.",
                },
                {
                    "id": "equip_mgmt",
                    "parent_id": "network_equipment",
                    "label": "Mgmt interfaces identified",
                    "title": "Management Plane Targets",
                    "text": "Potentially exposed switch/router management interfaces identified.",
                },
                {
                    "id": "dc_srv_records",
                    "parent_id": "dns_dc_discovery",
                    "label": "LDAP SRV records found",
                    "title": "Domain Controller SRV Records",
                    "text": "_ldap._tcp.dc._msdcs records resolved and DC list extracted.",
                },
                {
                    "id": "dc_nameservers",
                    "parent_id": "dns_dc_discovery",
                    "label": "Authoritative NS discovered",
                    "title": "Authoritative Name Servers",
                    "text": "Domain DNS servers identified for follow-on checks.",
                },
                {
                    "id": "dc_scope_hosts",
                    "parent_id": "dns_dc_discovery",
                    "label": "DCs in scope confirmed",
                    "title": "In-Scope DC Confirmation",
                    "text": "Validated which discovered DCs are approved targets.",
                },
                {
                    "id": "null_enum4",
                    "parent_id": "guest_null_sessions",
                    "label": "Unauth LDAP sessions",
                    "title": "Unauthenticated LDAP Sessions",
                    "text": "Validate anonymous/unauth LDAP session behavior and exposed directory data.",
                },
                {
                    "id": "null_smbmap",
                    "parent_id": "guest_null_sessions",
                    "label": "SMB null/anon session",
                    "title": "SMB Null/Anonymous Session",
                    "text": "Validate SMB null/anonymous session access and reachable share data.",
                },
                {
                    "id": "null_rpc",
                    "parent_id": "guest_null_sessions",
                    "label": "RPC null session works",
                    "title": "RPC Null Session",
                    "text": "rpcclient unauthenticated calls returned domain user/group data.",
                },
                {
                    "id": "smb_signing_off_unauth",
                    "parent_id": "smb_security",
                    "label": "SMB signing disabled",
                    "title": "SMB Signing Not Required",
                    "text": "Hosts identified where SMB signing is not enforced.",
                },
                {
                    "id": "smb_v1_legacy",
                    "parent_id": "smb_security",
                    "label": "SMBv1 enabled",
                    "title": "SMBv1 Exposure",
                    "text": "Legacy SMBv1-enabled hosts identified.",
                },
                {
                    "id": "smb_relay_list",
                    "parent_id": "smb_security",
                    "label": "Relay target list built",
                    "title": "SMB Relay Candidate List",
                    "text": "Generated relay list for ntlmrelayx and downstream validation.",
                },
                {
                    "id": "resp_host_repeat",
                    "parent_id": "responder_poisoning",
                    "label": "Repeated hostname requests",
                    "title": "Repeated Name Requests",
                    "text": "Recurring unresolved hostnames indicate likely broad poison opportunity.",
                },
                {
                    "id": "resp_hashes",
                    "parent_id": "responder_poisoning",
                    "label": "NTLM captures collected",
                    "title": "Captured NTLM Material",
                    "text": "Responder collected NTLM authentication attempts for validation.",
                },
                {
                    "id": "resp_relay_chain",
                    "parent_id": "responder_poisoning",
                    "label": "Capture-to-relay path",
                    "title": "Capture to Relay",
                    "text": "Observed captures can be chained into relay against approved targets.",
                },
                {
                    "id": "mitm6_running",
                    "parent_id": "mitm6_relay",
                    "label": "mitm6 successful",
                    "title": "mitm6 Active",
                    "text": "mitm6 operational and intercepting relevant authentication traffic.",
                },
                {
                    "id": "mitm6_ntlmrelay",
                    "parent_id": "mitm6_relay",
                    "label": "ntlmrelayx IPv6 relay works",
                    "title": "IPv6 NTLM Relay Success",
                    "text": "IPv6 relay chain validated with ntlmrelayx against target set.",
                },
                {
                    "id": "mitm6_ldap_or_adcs",
                    "parent_id": "mitm6_relay",
                    "label": "LDAP/ADCS relay target reachable",
                    "title": "High-Value Relay Target",
                    "text": "Relayable LDAP/ADCS endpoint reachable from coerced traffic.",
                },
                {
                    "id": "ldap_anon_bind",
                    "parent_id": "ldap_unauth",
                    "label": "Anonymous bind allowed",
                    "title": "Anonymous LDAP Bind",
                    "text": "LDAP accepts unauthenticated bind with meaningful response data.",
                },
                {
                    "id": "ldap_anon_enum",
                    "parent_id": "ldap_unauth",
                    "label": "Unauth user enumeration",
                    "title": "Unauthenticated LDAP Enumeration",
                    "text": "LDAP unauth enumeration yielded users/groups/metadata for follow-up.",
                },
                {
                    "id": "ldap_anon_null",
                    "parent_id": "ldap_unauth",
                    "label": "Null session LDAP checks",
                    "title": "LDAP Null Session Path",
                    "text": "Null/anonymous LDAP checks returned exploitable directory visibility.",
                },
                {
                    "id": "users_seed_lists",
                    "parent_id": "valid_user_discovery",
                    "label": "Seed lists collected",
                    "title": "User Seed Collection",
                    "text": "Built initial user list from OSINT, printer books, and naming patterns.",
                },
                {
                    "id": "users_ldapnomnom",
                    "parent_id": "valid_user_discovery",
                    "label": "LDAP user validation",
                    "title": "LDAP User Validation",
                    "text": "Validated candidate users through LDAP-focused enumeration tooling.",
                },
                {
                    "id": "users_kerbrute",
                    "parent_id": "valid_user_discovery",
                    "label": "Kerberos userenum hits",
                    "title": "Kerberos User Enumeration",
                    "text": "Kerberos userenum produced confirmed valid accounts.",
                },
                {
                    "id": "pwd_policy_checked",
                    "parent_id": "password_attacks",
                    "label": "Policy-safe spray window",
                    "title": "Spray Safety Confirmed",
                    "text": "Password policy reviewed before spraying to reduce lockout risk.",
                },
                {
                    "id": "pwd_blank_or_userpass",
                    "parent_id": "password_attacks",
                    "label": "Blank/user-as-pass tested",
                    "title": "Low-Noise Password Guessing",
                    "text": "Tested blank and user-as-password patterns against valid users.",
                },
                {
                    "id": "pwd_common_format_hits",
                    "parent_id": "password_attacks",
                    "label": "Common format hit",
                    "title": "Password Format Success",
                    "text": "Season/company-based pattern produced valid authentication.",
                },
                {
                    "id": "asrep_enum",
                    "parent_id": "asrep_roast",
                    "label": "AS-REP roastable users found",
                    "title": "Roastable Users Identified",
                    "text": "Enumerated users with pre-auth disabled and collected hashes.",
                },
                {
                    "id": "asrep_crackable",
                    "parent_id": "asrep_roast",
                    "label": "Crackable hash material",
                    "title": "AS-REP Crackability",
                    "text": "Captured hashes suitable for cracking workflows.",
                },
                {
                    "id": "asrep_priv",
                    "parent_id": "asrep_roast",
                    "label": "Privileged account impact",
                    "title": "High-Impact AS-REP Accounts",
                    "text": "Roastable/cracked accounts map to elevated access.",
                },
                {
                    "id": "kerb_no_preauth_chain",
                    "parent_id": "kerberoast_blind",
                    "label": "No-preauth chain viable",
                    "title": "Blind Kerberoast Chain",
                    "text": "No-preauth account path supports blind Kerberoast attempt.",
                },
                {
                    "id": "kerb_spn_candidates",
                    "parent_id": "kerberoast_blind",
                    "label": "SPN candidates identified",
                    "title": "SPN Candidate Set",
                    "text": "Built candidate SPN user list for focused roasting checks.",
                },
                {
                    "id": "kerb_ticket_material",
                    "parent_id": "kerberoast_blind",
                    "label": "TGS material captured",
                    "title": "Kerberoast Ticket Capture",
                    "text": "Collected ticket material for offline cracking assessment.",
                },
                {
                    "id": "time_hashes",
                    "parent_id": "timeroast",
                    "label": "SNTP roast hashes found",
                    "title": "Timeroast Hash Capture",
                    "text": "Timeroast module returned hash artifacts for cracking attempts.",
                },
                {
                    "id": "time_crackability",
                    "parent_id": "timeroast",
                    "label": "Hash crackability assessed",
                    "title": "Timeroast Crackability",
                    "text": "Validated cracking feasibility and likely impact of recovered material.",
                },
                {
                    "id": "time_reuse",
                    "parent_id": "timeroast",
                    "label": "Recovered cred reuse path",
                    "title": "Credential Reuse Path",
                    "text": "Recovered/derived creds can be reused against additional services.",
                },
                {
                    "id": "pre2k_hostlist",
                    "parent_id": "pre2k",
                    "label": "Hostname list built",
                    "title": "Pre2k Candidate Hostnames",
                    "text": "Prepared host-derived candidate machine accounts for pre2k checks.",
                },
                {
                    "id": "pre2k_userpass",
                    "parent_id": "pre2k",
                    "label": "hostname$:hostname hit",
                    "title": "Pre2k Default Pattern Hit",
                    "text": "Legacy computer-account password pattern produced successful auth.",
                },
                {
                    "id": "pre2k_blank",
                    "parent_id": "pre2k",
                    "label": "Blank machine password works",
                    "title": "Blank Machine Password",
                    "text": "Blank password accepted for candidate machine account.",
                },
                {
                    "id": "sccm_pxe",
                    "parent_id": "sccm_unauth",
                    "label": "PXE discovery path",
                    "title": "PXE Exposure",
                    "text": "PXE services exposed enough data for unauth reconnaissance.",
                },
                {
                    "id": "sccm_policy_read",
                    "parent_id": "sccm_unauth",
                    "label": "Unauth policy read",
                    "title": "Unauthenticated Policy Access",
                    "text": "SCCM policies readable without valid credentials.",
                },
                {
                    "id": "sccm_file_read",
                    "parent_id": "sccm_unauth",
                    "label": "Unauth file read",
                    "title": "Unauthenticated File Access",
                    "text": "SCCM distribution/file endpoints exposed sensitive artifacts.",
                },
                {
                    "id": "coerce_petipotam",
                    "parent_id": "auth_coerce",
                    "label": "PetitPotam works",
                    "title": "PetitPotam Coercion",
                    "text": "Unauthentication coercion triggered target auth to listener.",
                },
                {
                    "id": "coerce_printerbug",
                    "parent_id": "auth_coerce",
                    "label": "Printer bug path works",
                    "title": "Printer Coercion",
                    "text": "Printer-based coercion path validated against in-scope hosts.",
                },
                {
                    "id": "coerce_relayable",
                    "parent_id": "auth_coerce",
                    "label": "Coerced auth relayable",
                    "title": "Relayable Coercion",
                    "text": "Coerced authentication can be relayed to approved targets.",
                },
                {
                    "id": "adcs_web_enum",
                    "parent_id": "adcs_relay",
                    "label": "certsrv endpoints found",
                    "title": "ADCS Web Enrollment Found",
                    "text": "Identified /certsrv endpoints reachable over HTTP/HTTPS.",
                },
                {
                    "id": "adcs_ntlmrelay",
                    "parent_id": "adcs_relay",
                    "label": "Relay-to-ADCS successful",
                    "title": "ADCS Relay Success",
                    "text": "ntlmrelayx relay to ADCS endpoint succeeded.",
                },
                {
                    "id": "adcs_template_dc",
                    "parent_id": "adcs_relay",
                    "label": "Template abuse path",
                    "title": "ADCS Template Abuse",
                    "text": "Identified viable certificate template for escalation path.",
                },
                {
                    "id": "dns_anon_update",
                    "parent_id": "dns_updates",
                    "label": "Anonymous update accepted",
                    "title": "Anonymous DNS Update",
                    "text": "DNS server accepted unauthenticated/non-secure dynamic update.",
                },
                {
                    "id": "dns_safe_demo",
                    "parent_id": "dns_updates",
                    "label": "Non-disruptive proof",
                    "title": "Safe DNS Update Demonstration",
                    "text": "Demonstrated update using controlled/non-destructive record target.",
                },
                {
                    "id": "dns_kerbrelay_path",
                    "parent_id": "dns_updates",
                    "label": "Kerberos relay implication",
                    "title": "DNS-to-Relay Path",
                    "text": "Confirmed that DNS update weakness can support relay/impersonation chain.",
                },
                {
                    "id": "wsus_discover",
                    "parent_id": "wsus_unauth",
                    "label": "WSUS service discovered",
                    "title": "WSUS Discovery",
                    "text": "WSUS identified and reachable for unauth reconnaissance.",
                },
                {
                    "id": "wsus_only_discover",
                    "parent_id": "wsus_unauth",
                    "label": "Discovery-only evidence",
                    "title": "WSUS Discovery Evidence",
                    "text": "Captured discovery evidence for follow-on authenticated validation.",
                },
                {
                    "id": "wsus_followup_auth",
                    "parent_id": "wsus_unauth",
                    "label": "Auth follow-up required",
                    "title": "Authenticated WSUS Follow-up",
                    "text": "Marked for authenticated checks on trust/signing and update abuse.",
                },
                {
                    "id": "webapp_default_creds",
                    "parent_id": "web_applications",
                    "label": "Default creds",
                    "title": "Default Credentials Path",
                    "text": "Default or weak baseline credentials identified on a web application.",
                },
                {
                    "id": "webapp_exploit",
                    "parent_id": "web_applications",
                    "label": "Exploit",
                    "title": "Web Exploit Path",
                    "text": "Exploit path identified against a web application component.",
                },
            ],
        }

    def _load_checklist_map(s: Session, map_name: str) -> dict:
        row = s.execute(
            text(
                "SELECT title, phase_label, data_json FROM checklist_maps WHERE map_name = :n"
            ),
            {"n": map_name},
        ).fetchone()
        if not row:
            default = _default_checklist_map(map_name)
            s.execute(
                text(
                    "INSERT INTO checklist_maps(map_name, title, phase_label, data_json, updated_at) "
                    "VALUES (:n, :t, :p, :d, :u)"
                ),
                {
                    "n": map_name,
                    "t": default["title"],
                    "p": default["phase_label"],
                    "d": json.dumps(
                        {
                            "nodes": default["nodes"],
                            "edges": default["edges"],
                            "vuln_branches": default.get("vuln_branches", []),
                        }
                    ),
                    "u": datetime.utcnow().isoformat(),
                },
            )
            s.commit()
            return default
        data = json.loads(row[2] or "{}")
        if (
            map_name == "unauthenticated"
            and not data.get("nodes")
            and not data.get("vuln_branches")
        ):
            default = _default_checklist_map(map_name)
            s.execute(
                text(
                    "UPDATE checklist_maps SET title = :t, phase_label = :p, data_json = :d, updated_at = :u "
                    "WHERE map_name = :n"
                ),
                {
                    "n": map_name,
                    "t": default["title"],
                    "p": default["phase_label"],
                    "d": json.dumps(
                        {
                            "nodes": default["nodes"],
                            "edges": default["edges"],
                            "vuln_branches": default.get("vuln_branches", []),
                        }
                    ),
                    "u": datetime.utcnow().isoformat(),
                },
            )
            s.commit()
            return default

        if map_name in ("unauthenticated", "authenticated"):
            default = _default_checklist_map(map_name)
            cur_nodes = (
                data.get("nodes", []) if isinstance(data.get("nodes"), list) else []
            )
            cur_branches = (
                data.get("vuln_branches", [])
                if isinstance(data.get("vuln_branches"), list)
                else []
            )
            cur_node_keys = {str(n.get("key") or "") for n in cur_nodes}
            cur_branch_ids = {str(b.get("id") or "") for b in cur_branches}

            added = False
            for n in default.get("nodes", []):
                k = str(n.get("key") or "")
                if k and k not in cur_node_keys:
                    cur_nodes.append(n)
                    added = True

            for b in default.get("vuln_branches", []):
                bid = str(b.get("id") or "")
                if bid and bid not in cur_branch_ids:
                    cur_branches.append(b)
                    added = True

            if added:
                data["nodes"] = cur_nodes
                data["vuln_branches"] = cur_branches
                if not isinstance(data.get("edges"), list):
                    data["edges"] = default.get("edges", [])
                s.execute(
                    text(
                        "UPDATE checklist_maps SET data_json = :d, updated_at = :u WHERE map_name = :n"
                    ),
                    {
                        "n": map_name,
                        "d": json.dumps(data),
                        "u": datetime.utcnow().isoformat(),
                    },
                )
                s.commit()
        return {
            "title": row[0]
            or (
                "Domain Auth Checklist"
                if map_name == "authenticated"
                else "Domain Unauth Checklist"
            ),
            "phase_label": row[1] or "Enumeration",
            "nodes": data.get("nodes", []),
            "edges": data.get("edges", []),
            "vuln_branches": data.get("vuln_branches", []),
        }

    @app.get("/checklist-unauthenticated", response_class=HTMLResponse)
    def checklist_unauthenticated_page(request: Request):
        with db() as s:
            map_data = _load_checklist_map(s, "unauthenticated")
        for n in map_data.get("nodes", []):
            if str(n.get("key") or "") == "sccm_unauth":
                n["label"] = "SCCM Unauthenticated Vulnerabilities"
                n["exploit_text"] = (
                    "Track SCCM servers and validate unauthenticated vulnerability paths."
                )
        for b in map_data.get("vuln_branches", []):
            bid = str(b.get("id") or "")
            if bid == "null_enum4":
                b["label"] = "Unauth LDAP sessions"
                b["title"] = "Unauthenticated LDAP Sessions"
                b["text"] = (
                    "Validate anonymous/unauth LDAP session behavior and exposed directory data."
                )
            elif bid == "null_smbmap":
                b["label"] = "SMB null/anon session"
                b["title"] = "SMB Null/Anonymous Session"
                b["text"] = (
                    "Validate SMB null/anonymous session access and reachable share data."
                )
        map_data["title"] = "Domain Unauth Checklist"
        return templates.TemplateResponse(
            "checklist.html",
            {"request": request, "map_name": "unauthenticated", "map_data": map_data},
        )

    @app.get("/checklist", response_class=HTMLResponse)
    def checklist_page(request: Request):
        with db() as s:
            map_data = _load_checklist_map(s, "authenticated")
        map_data["title"] = "Domain Auth Checklist"
        return templates.TemplateResponse(
            "checklist.html",
            {"request": request, "map_name": "authenticated", "map_data": map_data},
        )

    @app.get("/checklist-attack-path", response_class=HTMLResponse)
    def checklist_attack_path_page(request: Request):
        def checklist_state(s: Session) -> dict[str, object]:
            rows = s.execute(text("SELECT item_key, done FROM checklist")).fetchall()
            out: dict[str, object] = {}
            for r in rows:
                key = str(r[0])
                val = int(r[1] or 0)
                if key.endswith("_vuln"):
                    out[key] = (
                        "vuln" if val == 1 else ("notvuln" if val == 2 else "unchecked")
                    )
                else:
                    out[key] = bool(val)
            return out

        def build_attack_map_for_source(
            map_data: dict,
            state: dict[str, object],
        ) -> dict[str, list[dict]]:
            nodes = (
                map_data.get("nodes", [])
                if isinstance(map_data.get("nodes"), list)
                else []
            )
            branches = (
                map_data.get("vuln_branches", [])
                if isinstance(map_data.get("vuln_branches"), list)
                else []
            )
            branch_by_id = {str(b.get("id") or ""): b for b in branches if b.get("id")}

            def node_is_vuln(node_key: str) -> bool:
                return state.get(f"{node_key}_vuln") == "vuln"

            def branch_selected(branch_id: str) -> bool:
                return bool(state.get(f"branch_{branch_id}", False))

            def branch_active(branch_id: str) -> bool:
                b = branch_by_id.get(branch_id)
                if not b:
                    return False
                if not branch_selected(branch_id):
                    return False
                parent_id = str(b.get("parent_id") or "")
                if parent_id in branch_by_id:
                    return branch_active(parent_id)
                return node_is_vuln(parent_id)

            vuln_node_keys = {
                str(n.get("key") or "")
                for n in nodes
                if str(n.get("key") or "") and node_is_vuln(str(n.get("key") or ""))
            }

            active_branch_ids = {
                str(b.get("id") or "")
                for b in branches
                if str(b.get("id") or "") and branch_active(str(b.get("id") or ""))
            }

            filtered_nodes = [
                n for n in nodes if str(n.get("key") or "") in vuln_node_keys
            ]
            filtered_branches = []
            for b in branches:
                bid = str(b.get("id") or "")
                if bid not in active_branch_ids:
                    continue
                parent_id = str(b.get("parent_id") or "")
                if parent_id in vuln_node_keys or parent_id in active_branch_ids:
                    filtered_branches.append(b)

            return {"nodes": filtered_nodes, "vuln_branches": filtered_branches}

        with db() as s:
            state = checklist_state(s)
            auth_map = _load_checklist_map(s, "authenticated")
            unauth_map = _load_checklist_map(s, "unauthenticated")

        unauth_attack = build_attack_map_for_source(unauth_map, state)
        auth_attack = build_attack_map_for_source(auth_map, state)

        merged_nodes: list[dict] = []
        merged_branches: list[dict] = []
        seen_nodes: set[str] = set()
        seen_branches: set[str] = set()

        for n in unauth_attack["nodes"] + auth_attack["nodes"]:
            key = str(n.get("key") or "")
            if not key or key in seen_nodes:
                continue
            seen_nodes.add(key)
            merged_nodes.append(n)

        for b in unauth_attack["vuln_branches"] + auth_attack["vuln_branches"]:
            bid = str(b.get("id") or "")
            parent_id = str(b.get("parent_id") or "")
            if not bid or bid in seen_branches:
                continue
            if parent_id not in seen_nodes and parent_id not in seen_branches:
                continue
            seen_branches.add(bid)
            merged_branches.append(b)

        if not merged_nodes:
            merged_nodes = [
                {
                    "key": "attack_path_empty",
                    "label": "No Vulnerable Items Yet",
                    "color_start": "#64748b",
                    "color_end": "#334155",
                    "initial": 1,
                    "exploit_text": "Mark items as Vulnerable in Domain Unauth Checklist or Domain Auth Checklist to build this attack path map.",
                }
            ]
            merged_branches = []

        attack_map = {
            "title": "Attack Path",
            "phase_label": "Consolidated",
            "nodes": merged_nodes,
            "edges": [],
            "vuln_branches": merged_branches,
        }
        return templates.TemplateResponse(
            "checklist.html",
            {"request": request, "map_name": "attack_path", "map_data": attack_map},
        )

    @app.get("/smb-shares", response_class=HTMLResponse)
    def smb_shares_page(request: Request):
        return templates.TemplateResponse("smb_shares.html", {"request": request})

    @app.get("/topology", response_class=HTMLResponse)
    def topology_page(request: Request):
        with db() as s:
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
        return templates.TemplateResponse(
            "topology.html", {"request": request, "topology_data": data}
        )

    @app.get("/api/topology")
    def api_topology_get():
        with db() as s:
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

    @app.post("/api/topology")
    async def api_topology_save(request: Request):
        body = await request.json()
        nodes = body.get("nodes") if isinstance(body.get("nodes"), list) else []
        edges = body.get("edges") if isinstance(body.get("edges"), list) else []
        payload = json.dumps({"nodes": nodes, "edges": edges})

        with db() as s:
            row = (
                s.execute(
                    select(Note)
                    .where(Note.object_type == "topology_map", Note.object_id == 0)
                    .order_by(Note.updated_at.desc(), Note.id.desc())
                )
                .scalars()
                .first()
            )
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

    @app.get("/checklist/edit", response_class=HTMLResponse)
    def checklist_edit(request: Request, map_name: str = Query("authenticated")):
        with db() as s:
            map_data = _load_checklist_map(s, map_name)
        return templates.TemplateResponse(
            "checklist_edit.html",
            {"request": request, "map_name": map_name, "map_data": map_data},
        )

    @app.post("/api/checklist-map/{map_name}")
    async def api_checklist_map_save(map_name: str, request: Request):
        body = await request.json()
        title = (body.get("title") or "").strip() or (
            "Domain Auth Checklist"
            if map_name == "authenticated"
            else "Domain Unauth Checklist"
        )
        phase_label = (body.get("phase_label") or "").strip() or "Enumeration"
        nodes = body.get("nodes") if isinstance(body.get("nodes"), list) else []
        edges = body.get("edges") if isinstance(body.get("edges"), list) else []
        vuln_branches = (
            body.get("vuln_branches")
            if isinstance(body.get("vuln_branches"), list)
            else []
        )
        data_json = json.dumps(
            {"nodes": nodes, "edges": edges, "vuln_branches": vuln_branches}
        )
        with db() as s:
            s.execute(
                text(
                    "INSERT OR REPLACE INTO checklist_maps(map_name, title, phase_label, data_json, updated_at) "
                    "VALUES (:n, :t, :p, :d, :u)"
                ),
                {
                    "n": map_name,
                    "t": title,
                    "p": phase_label,
                    "d": data_json,
                    "u": datetime.utcnow().isoformat(),
                },
            )
            s.commit()
        return {"ok": True}

    @app.get("/api/checklist")
    def api_checklist_get():
        from sqlalchemy import text

        with db() as s:
            rows = s.execute(text("SELECT item_key, done FROM checklist")).fetchall()
        result = {}
        for r in rows:
            if str(r[0]).endswith("_vuln"):
                result[r[0]] = (
                    "vuln" if r[1] == 1 else ("notvuln" if r[1] == 2 else "unchecked")
                )
            else:
                result[r[0]] = bool(r[1])
        return result

    @app.get("/api/checklist-notes")
    def api_checklist_notes_get():
        from sqlalchemy import text

        with db() as s:
            rows = s.execute(
                text("SELECT item_key, note FROM checklist_notes")
            ).fetchall()
        return {str(r[0]): str(r[1] or "") for r in rows}

    @app.post("/api/checklist-note/{item_key}")
    def api_checklist_note_set(item_key: str, note: str = Form("")):
        from sqlalchemy import text

        with db() as s:
            s.execute(
                text(
                    "INSERT OR REPLACE INTO checklist_notes (item_key, note) VALUES (:k, :n)"
                ),
                {"k": item_key, "n": note},
            )
            s.commit()
        return {"ok": True}

    @app.post("/api/checklist/ldap_vuln")
    def api_checklist_ldap_vuln(vuln: str = Form("")):
        from sqlalchemy import text

        val = 0 if vuln == "unchecked" else (1 if vuln == "vuln" else 2)
        with db() as s:
            s.execute(
                text(
                    "INSERT OR REPLACE INTO checklist (item_key, done) VALUES ('ldap_vuln', :vuln)"
                ),
                {"vuln": val},
            )
            s.commit()
        return {"ok": True}

    @app.post("/api/checklist/{item_key}")
    def api_checklist_set(item_key: str, done: int = Form(0), vuln: str = Form("")):
        from sqlalchemy import text

        if str(item_key).endswith("_vuln"):
            done = 0 if vuln == "unchecked" else (1 if vuln == "vuln" else 2)
        with db() as s:
            s.execute(
                text(
                    "INSERT OR REPLACE INTO checklist (item_key, done) VALUES (:key, :done)"
                ),
                {"key": item_key, "done": done},
            )
            s.commit()
        return {"ok": True}

    # Lists
    @app.get("/subdomains", response_class=HTMLResponse)
    def subdomains(request: Request):
        show_out = int(request.query_params.get("show_out", "0"))
        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs = scope_sets(
                s, sensitive_only=True
            )
            rows = (
                s.execute(
                    select(Subdomain).order_by(
                        Subdomain.root_domain.asc(), Subdomain.fqdn.asc()
                    )
                )
                .scalars()
                .all()
            )
            # Get all RDAP info
            rdap_info = {}
            for di in s.execute(select(DomainInfo)).scalars().all():
                rdap_info[di.domain] = {
                    "registrar": di.registrar,
                    "registrarEmail": di.registrar_email or "",
                    "registrarOrg": di.registrar_org or "",
                    "creationDate": di.creation_date or "",
                    "creation_date": di.creation_date or "",
                    "expirationDate": di.expiration_date or "",
                    "expiration_date": di.expiration_date or "",
                    "updatedDate": di.updated_date or "",
                    "nameServers": di.name_servers.split(", ")
                    if di.name_servers
                    else [],
                    "name_servers": di.name_servers or "",
                    "status": di.status or "",
                    "dnssec": di.dnssec or "",
                    "registrant": di.registrant or "",
                    "registrantEmail": di.registrant_email or "",
                    "adminContact": di.admin_contact or "",
                    "adminEmail": di.admin_email or "",
                    "techContact": di.tech_contact or "",
                    "techEmail": di.tech_email or "",
                    "error": di.rdap_error or "",
                }
            out = []
            root_domains = {}
            for x in rows:
                ips_found = list_subdomain_ips(s, x.fqdn)
                in_dom = domain_in_scope(x.fqdn, domains, domain_all_subs)
                in_ip = any(ip_in_scope(ip, ips, subnets) for ip in ips_found)
                in_scope = bool(in_dom or in_ip)
                sensitive_dom = domain_in_scope(x.fqdn, s_domains, s_domain_all_subs)
                sensitive_ip = any(
                    ip_in_scope(ip, s_ips, s_subnets) for ip in ips_found
                )
                sensitive = bool(sensitive_dom or sensitive_ip)
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
                out.append(
                    {
                        "fqdn": x.fqdn,
                        "root_domain": x.root_domain,
                        "ips": ips_found,
                        "in_scope": in_scope,
                        "sensitive": sensitive,
                        "rdap": rdap,
                        "prowl": prowl,
                    }
                )
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
            filtered = (
                data["subs"]
                if show_out == 1
                else [s for s in data["subs"] if s.get("in_scope")]
            )
            if filtered:
                grouped_filtered[rd] = {"subs": filtered, "rdap": data["rdap"]}

        return templates.TemplateResponse(
            "subdomains.html",
            {"request": request, "grouped": grouped_filtered, "show_out": show_out},
        )

    @app.get("/emails", response_class=HTMLResponse)
    def emails(request: Request):
        with db() as s:
            _, _, _, email_domains, _ = scope_sets(s)
            _, _, _, s_email_domains, _ = scope_sets(s, sensitive_only=True)
            rows = (
                s.execute(select(Email).order_by(Email.domain.asc(), Email.email.asc()))
                .scalars()
                .all()
            )
        out = [
            {
                "email": x.email,
                "domain": x.domain,
                "in_scope": email_in_scope(x.email, email_domains),
                "sensitive": email_in_scope(x.email, s_email_domains),
            }
            for x in rows
        ]
        return templates.TemplateResponse(
            "emails.html", {"request": request, "rows": out}
        )

    @app.get("/emails/export")
    def export_emails():
        with db() as s:
            _, _, _, email_domains, _ = scope_sets(s)
            emails = (
                s.execute(select(Email).order_by(Email.email.asc())).scalars().all()
            )
        lines = [x.email for x in emails if email_in_scope(x.email, email_domains)]
        txt = "\n".join(lines)
        return Response(
            content=txt,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=reconbubble-emails.txt"
            },
        )

    @app.get("/docs", response_class=HTMLResponse)
    def docs(request: Request):
        with db() as s:
            rows = (
                s.execute(select(Document).order_by(Document.created_at.desc()))
                .scalars()
                .all()
            )
        return templates.TemplateResponse(
            "docs.html", {"request": request, "rows": rows}
        )

    @app.get("/api/doc/{doc_id}")
    def api_doc(doc_id: int):
        with db() as s:
            d = s.scalar(select(Document).where(Document.id == doc_id))
            if not d:
                return JSONResponse({"error": "not found"}, status_code=404)
            return {
                "id": d.id,
                "title": d.title,
                "mime": d.mime,
                "artifact_id": d.artifact_id,
            }

    @app.get("/doc/{doc_id}", response_class=HTMLResponse)
    def doc_detail(doc_id: int, request: Request):
        with db() as s:
            d = s.scalar(select(Document).where(Document.id == doc_id))
            art = (
                s.scalar(select(Artifact).where(Artifact.id == d.artifact_id))
                if d
                else None
            )
        meta = json.loads(d.meta_json) if d else {}
        return templates.TemplateResponse(
            "doc_detail.html",
            {"request": request, "doc": d, "artifact": art, "meta": meta},
        )

    # Graph API

    @app.get("/cloud", response_class=HTMLResponse)
    def cloud(request: Request):
        with db() as s:
            rows = (
                s.execute(select(CloudItem).order_by(CloudItem.created_at.desc()))
                .scalars()
                .all()
            )
            out = []
            for r in rows:
                data = {}
                try:
                    data = json.loads(r.data_json) if r.data_json else {}
                except Exception:
                    data = {}
                out.append(
                    {
                        "id": r.id,
                        "provider": r.provider,
                        "name": r.name,
                        "notes": r.notes or "",
                        "data": data,
                        "created_at": r.created_at,
                    }
                )
        return templates.TemplateResponse(
            "cloud.html", {"request": request, "rows": out}
        )

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
            item = CloudItem(
                provider=provider[:64],
                name=name[:255],
                notes=notes,
                data_json=json.dumps(data, ensure_ascii=False),
            )
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
                data = {
                    "account_id": account_id.strip(),
                    "regions": _split_lines(regions),
                    "buckets": _split_lines(buckets),
                }
                provider = "AWS"
            elif provider.lower() in ("azure",):
                data = {
                    "tenant_id": tenant_id.strip(),
                    "subscriptions": _split_lines(subscriptions),
                    "regions": _split_lines(regions),
                }
                provider = "Azure"
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
            else:
                data = {
                    "tenant_id": tenant_id.strip(),
                    "primary_domain": primary_domain.strip(),
                    "app_ids": _split_lines(app_ids),
                    "domains": _split_lines(subscriptions),
                }
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

    @app.get("/api/port-research/{port}")
    def api_port_research(port: int):
        from sqlalchemy import text

        with db() as s:
            rows = s.execute(
                text(
                    "SELECT port, service, research_url, research_notes FROM port_research WHERE port = :port"
                ),
                {"port": port},
            ).fetchall()
        if rows:
            r = rows[0]
            return {"port": r[0], "service": r[1], "url": r[2], "notes": r[3]}
        return {"port": port, "service": "", "url": "", "notes": ""}

    @app.get("/services", response_class=HTMLResponse)
    def services_page(request: Request):
        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)

            services = (
                s.execute(select(Service).where(Service.state == "open"))
                .scalars()
                .all()
            )

            service_map = {}
            for svc in services:
                host = s.scalar(select(Host).where(Host.id == svc.host_id))
                if not host:
                    continue

                key = f"{svc.port}/{svc.proto}"
                host_in = host_in_scope(
                    host.ip, host.hostname or "", ips, subnets, domains, domain_all_subs
                )

                if key not in service_map:
                    service_map[key] = {
                        "port": svc.port,
                        "proto": svc.proto,
                        "hosts": [],
                        "service_types": set(),
                        "products": set(),
                        "outputs": set(),
                    }

                if host_in:
                    service_map[key]["hosts"].append(
                        {"id": host.id, "ip": host.ip, "hostname": host.hostname or ""}
                    )

                if svc.service_name:
                    service_map[key]["service_types"].add(svc.service_name)

                if svc.product:
                    service_map[key]["products"].add(
                        f"{svc.product} {svc.version}".strip()
                    )

                ev = (
                    s.execute(
                        select(ServiceEvidence).where(
                            ServiceEvidence.service_id == svc.id
                        )
                    )
                    .scalars()
                    .all()
                )
                for e in ev:
                    if e.raw_output:
                        cleaned = e.raw_output
                        for h in service_map[key]["hosts"]:
                            cleaned = cleaned.replace(h["ip"], "<IP>")
                            if h["hostname"]:
                                cleaned = cleaned.replace(h["hostname"], "<HOST>")
                        service_map[key]["outputs"].add(cleaned[:800])

            rows = []
            for key, data in service_map.items():
                if data["hosts"]:
                    rows.append(
                        {
                            "port": data["port"],
                            "proto": data["proto"],
                            "service_types": list(data["service_types"]),
                            "products": list(data["products"]),
                            "host_count": len(data["hosts"]),
                            "hosts": data["hosts"],
                            "outputs": list(data["outputs"]),
                        }
                    )

            rows.sort(key=lambda x: (x["port"], x["proto"]))

        return templates.TemplateResponse(
            "services.html", {"request": request, "rows": rows}
        )

    @app.get("/api/graph")
    def api_graph(only_in_scope: bool = Query(False)):
        nodes, edges = [], []
        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs = scope_sets(
                s, sensitive_only=True
            )
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
            sub_sensitive = domain_in_scope(fq, s_domains, s_domain_all_subs)
            dom_sensitive = (
                domain_in_scope(rd, s_domains, s_domain_all_subs) if rd else False
            )
            if rd and rd not in domain_nodes:
                did = nid("domain", rd)
                domain_nodes[rd] = did
                add_node(
                    {
                        "id": did,
                        "label": rd,
                        "type": "domain",
                        "in_scope": dom_in,
                        "sensitive": dom_sensitive,
                    }
                )
            sid = nid("sub", fq)
            add_node(
                {
                    "id": sid,
                    "label": fq,
                    "type": "subdomain",
                    "in_scope": sub_in,
                    "sensitive": sub_sensitive,
                }
            )
            if rd:
                edges.append({"from": domain_nodes[rd], "to": sid, "type": "has"})

        host_ids = {}
        host_scope = {}
        for h in hosts:
            hid = nid("host", h.ip)
            host_ids[h.id] = hid
            hin = ip_in_scope(h.ip, ips, subnets)
            hs = ip_in_scope(h.ip, s_ips, s_subnets)
            host_scope[h.id] = hin
            label = h.ip + (("\n" + h.hostname) if h.hostname else "")
            add_node(
                {
                    "id": hid,
                    "label": label,
                    "type": "host",
                    "in_scope": hin,
                    "sensitive": hs,
                    "host_id": h.id,
                }
            )

        for svc in svcs:
            hin = host_scope.get(svc.host_id, False)
            hs = False
            host_obj = next((h for h in hosts if h.id == svc.host_id), None)
            if host_obj:
                hs = ip_in_scope(host_obj.ip, s_ips, s_subnets)
            sid = nid("svc", f"{svc.host_id}:{svc.port}/{svc.proto}")
            add_node(
                {
                    "id": sid,
                    "label": f"{svc.port}/{svc.proto}\n{svc.service_name or ''}".strip(),
                    "type": "service",
                    "in_scope": hin,
                    "sensitive": hs,
                    "service_id": svc.id,
                }
            )
            edges.append(
                {"from": host_ids.get(svc.host_id, ""), "to": sid, "type": "exposes"}
            )

        existing = {n["id"] for n in nodes}
        for host_id, fqdn_list in host_domains.items():
            host_node = host_ids.get(host_id)
            if not host_node:
                continue
            for fqdn in fqdn_list:
                sub_id = nid("sub", fqdn)
                if sub_id not in existing:
                    sub_in = domain_in_scope(fqdn, domains, domain_all_subs)
                    sub_sensitive = domain_in_scope(fqdn, s_domains, s_domain_all_subs)
                    add_node(
                        {
                            "id": sub_id,
                            "label": fqdn,
                            "type": "subdomain",
                            "in_scope": sub_in,
                            "sensitive": sub_sensitive,
                        }
                    )
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
        txt = "\n".join(sorted(set(out)))
        return Response(
            content=txt,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=reconbubble-subdomains.txt"
            },
        )

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
    @app.get("/users")
    def users_page_legacy():
        return RedirectResponse(url="/user-discovery", status_code=303)

    @app.get("/user-discovery", response_class=HTMLResponse)
    def user_discovery_page(request: Request):
        with db() as s:
            users = (
                s.execute(select(ValidUser).order_by(ValidUser.username.asc()))
                .scalars()
                .all()
            )
        return templates.TemplateResponse(
            "user_discovery.html", {"request": request, "users": users}
        )

    @app.get("/app-credentials", response_class=HTMLResponse)
    def app_credentials_page(request: Request):
        with db() as s:
            creds = (
                s.execute(
                    select(Credential).order_by(
                        Credential.service.asc(), Credential.username.asc()
                    )
                )
                .scalars()
                .all()
            )
        return templates.TemplateResponse(
            "app_credentials.html", {"request": request, "creds": creds}
        )

    @app.get("/ad-users", response_class=HTMLResponse)
    def ad_users_page(request: Request):
        return templates.TemplateResponse("ad_users.html", {"request": request})

    @app.post("/api/users/create")
    def api_user_create(
        username: str = Form(...), source: str = Form(""), notes: str = Form("")
    ):
        username = username.strip()
        if not username:
            return JSONResponse(
                {"ok": False, "error": "Username is required"}, status_code=400
            )
        with db() as s:
            if not s.scalar(select(ValidUser).where(ValidUser.username == username)):
                s.add(
                    ValidUser(
                        username=username, source=source.strip(), notes=notes.strip()
                    )
                )
                s.commit()
        return {"ok": True}

    @app.post("/api/creds/create")
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
        with db() as s:
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

    @app.get("/user-discovery/export/usernames")
    @app.get("/users/export/usernames")
    def export_usernames():
        with db() as s:
            users = (
                s.execute(select(ValidUser.username).order_by(ValidUser.username.asc()))
                .scalars()
                .all()
            )
        txt = "\n".join(users)
        return Response(
            content=txt,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=reconbubble-usernames.txt"
            },
        )

    @app.get("/app-credentials/export/creds")
    @app.get("/users/export/creds")
    def export_creds():
        with db() as s:
            creds = (
                s.execute(
                    select(Credential).order_by(
                        Credential.service.asc(), Credential.username.asc()
                    )
                )
                .scalars()
                .all()
            )
        lines = []
        for c in creds:
            if c.password:
                lines.append(f"{c.username}:{c.password}")
            else:
                lines.append(f"{c.username}")
        txt = "\n".join(lines)
        return Response(
            content=txt,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=reconbubble-creds.txt"
            },
        )

    # Social Media
    @app.get("/social", response_class=HTMLResponse)
    def social_page(request: Request):
        with db() as s:
            rows = (
                s.execute(
                    select(SocialMedia).order_by(
                        SocialMedia.platform.asc(), SocialMedia.handle.asc()
                    )
                )
                .scalars()
                .all()
            )
        return templates.TemplateResponse(
            "social.html", {"request": request, "rows": rows}
        )

    @app.post("/api/social/create")
    async def api_social_create(
        request: Request,
        platform: str = Form(...),
        handle: str = Form(""),
        url: str = Form(""),
        notes: str = Form(""),
        screenshot: list[UploadFile] | None = File(None),
    ):
        artifact_ids = []
        if screenshot:
            for ss in screenshot:
                if ss and ss.filename:
                    tmp = ws.uploads_dir / f"tmp_{ss.filename}"
                    tmp.write_bytes(await ss.read())
                    stored = ws.store_upload(tmp, prefix="screenshot")
                    tmp.unlink(missing_ok=True)
                    with db() as s:
                        art = upsert_artifact(s, "screenshot", stored)
                        artifact_ids.append(art.id)

        artifact_id = artifact_ids[0] if artifact_ids else None

        with db() as s:
            item = SocialMedia(
                platform=platform[:64],
                handle=handle[:255],
                url=url[:512],
                notes=notes,
                artifact_id=artifact_id,
            )
            s.add(item)
            s.flush()
            s.commit()
            item_id = item.id
        return {"ok": True, "id": item_id}

    @app.post("/api/social/delete")
    def api_social_delete(social_id: int = Form(...)):
        with db() as s:
            item = s.scalar(select(SocialMedia).where(SocialMedia.id == social_id))
            if item:
                s.delete(item)
                s.commit()
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
        show_out = int(request.query_params.get("show_out", "0"))

        def best_matching_subnet_label(host: str, subnets: list) -> str:
            try:
                ip_obj = ipaddress.ip_address(host)
            except ValueError:
                return ""
            matches = [n for n in subnets if ip_obj in n]
            if not matches:
                return ""
            return str(max(matches, key=lambda n: n.prefixlen))

        with db() as s:
            ips, subnets, domains, _, domain_all_subs = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs = scope_sets(
                s, sensitive_only=True
            )
            rows = (
                s.execute(
                    select(WebUrl).order_by(WebUrl.domain.asc(), WebUrl.url.asc())
                )
                .scalars()
                .all()
            )
            out = []
            for x in rows:
                parsed_host = ""
                try:
                    parsed_host = (
                        (urlsplit(x.url).hostname or "").strip().lower().strip(".")
                    )
                except Exception:
                    parsed_host = ""

                in_dom = (
                    domain_in_scope(x.domain, domains, domain_all_subs)
                    if x.domain
                    else False
                )
                sensitive_dom = (
                    domain_in_scope(x.domain, s_domains, s_domain_all_subs)
                    if x.domain
                    else False
                )
                subnet_label = ""
                in_ip_or_subnet = False
                sensitive_ip_or_subnet = False
                if parsed_host:
                    if parsed_host in ips:
                        in_ip_or_subnet = True
                    subnet_label = best_matching_subnet_label(parsed_host, subnets)
                    if subnet_label:
                        in_ip_or_subnet = True
                    if parsed_host in s_ips:
                        sensitive_ip_or_subnet = True
                    if best_matching_subnet_label(parsed_host, s_subnets):
                        sensitive_ip_or_subnet = True

                in_scope = bool(in_dom or in_ip_or_subnet)
                sensitive = bool(sensitive_dom or sensitive_ip_or_subnet)
                if x.domain:
                    group_key = x.domain
                elif subnet_label:
                    group_key = f"subnet:{subnet_label}"
                elif parsed_host:
                    group_key = f"ip:{parsed_host}"
                else:
                    group_key = "unknown"

                out.append(
                    {
                        "id": x.id,
                        "url": x.url,
                        "domain": x.domain,
                        "host": parsed_host,
                        "subnet": subnet_label,
                        "group_key": group_key,
                        "title": x.title,
                        "in_scope": in_scope,
                        "sensitive": sensitive,
                    }
                )
        out = out if show_out == 1 else [r for r in out if r.get("in_scope")]
        grouped = {}
        for r in out:
            d = r.get("group_key") or r.get("domain") or "unknown"
            if d not in grouped:
                grouped[d] = []
            grouped[d].append(r)
        return templates.TemplateResponse(
            "urls.html", {"request": request, "grouped": grouped, "show_out": show_out}
        )

    @app.get("/urls/export")
    def export_urls():
        with db() as s:
            rows = s.execute(select(WebUrl).order_by(WebUrl.url.asc())).scalars().all()
        lines = [x.url for x in rows]
        txt = "\n".join(lines)
        return Response(
            content=txt,
            media_type="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=reconbubble-urls.txt"
            },
        )

    # RDAP/whois lookup
    @app.get("/api/rdap/{domain}")
    def api_rdap(domain: str):
        import urllib.request, json, socket

        domain = domain.lower().strip()

        out = {"domainName": domain}
        error_msg = ""

        # Try whois first (port 43)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(("whois.iana.org", 43))
            s.send(f"{domain}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()

            whois_text = response.decode("utf-8", errors="ignore")

            # Parse whois response
            lines = whois_text.split("\n")
            for line in lines:
                line = line.strip()
                if line.startswith("registrar:"):
                    out["registrar"] = line.split(":", 1)[1].strip()
                elif line.startswith("Registrar:"):
                    out["registrar"] = line.split(":", 1)[1].strip()
                elif line.startswith("created:"):
                    out["creationDate"] = line.split(":", 1)[1].strip()
                elif line.startswith("Created:"):
                    out["creationDate"] = line.split(":", 1)[1].strip()
                elif line.startswith("expires:"):
                    out["expirationDate"] = line.split(":", 1)[1].strip()
                elif line.startswith("Expires:"):
                    out["expirationDate"] = line.split(":", 1)[1].strip()
                elif line.startswith("updated:"):
                    out["updatedDate"] = line.split(":", 1)[1].strip()
                elif line.startswith("Updated:"):
                    out["updatedDate"] = line.split(":", 1)[1].strip()
                elif (
                    line.startswith("Name Server:")
                    or line.startswith("name-server:")
                    or line.startswith("nserver:")
                ):
                    ns = line.split(":", 1)[1].strip().lower()
                    if ns:
                        if "nameServers" not in out:
                            out["nameServers"] = []
                        if ns not in out["nameServers"]:
                            out["nameServers"].append(ns)
                elif line.startswith("DNSSEC:"):
                    out["dnssec"] = line.split(":", 1)[1].strip()
                elif "registrar url" in line.lower():
                    out["registrarUrl"] = line.split(":", 1)[1].strip()

            # If we got some data from whois, try RDAP for more details
            if out.get("registrar") or out.get("creationDate"):
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
                try:
                    url = f"https://{host}/domain/{domain}"
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "ReconBubble/1.0"}
                    )
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        raw = resp.read().decode("utf-8", errors="ignore")
                        data = json.loads(raw) if raw else {}
                    if isinstance(data, dict):
                        entities = {}
                        for e in data.get("entities", []):
                            if isinstance(e, dict):
                                roles = e.get("roles", [])
                                vcard = e.get("vcardArray", [])
                                name = email = org = ""
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
                                    entities[role] = {
                                        "name": name,
                                        "email": email,
                                        "org": org,
                                    }

                        if "registrar" in entities:
                            if not out.get("registrar"):
                                out["registrar"] = entities["registrar"].get("name", "")
                            out["registrarEmail"] = entities["registrar"].get(
                                "email", ""
                            )
                            out["registrarOrg"] = entities["registrar"].get("org", "")
                        if "registrant" in entities:
                            out["registrant"] = entities["registrant"].get("name", "")
                            out["registrantEmail"] = entities["registrant"].get(
                                "email", ""
                            )
                        if "administrative" in entities or "admin" in entities:
                            key = (
                                "administrative"
                                if "administrative" in entities
                                else "admin"
                            )
                            out["adminContact"] = entities[key].get("name", "")
                            out["adminEmail"] = entities[key].get("email", "")
                        if "technical" in entities:
                            out["techContact"] = entities["technical"].get("name", "")
                            out["techEmail"] = entities["technical"].get("email", "")

                        for e in data.get("events", []):
                            if isinstance(e, dict):
                                if e.get(
                                    "eventAction"
                                ) == "registration" and not out.get("creationDate"):
                                    out["creationDate"] = e.get("eventDate")
                                if e.get("eventAction") == "expiration" and not out.get(
                                    "expirationDate"
                                ):
                                    out["expirationDate"] = e.get("eventDate")
                                if e.get(
                                    "eventAction"
                                ) == "last changed" and not out.get("updatedDate"):
                                    out["updatedDate"] = e.get("eventDate")

                        if "nameServers" not in out:
                            out["nameServers"] = []
                            for ns in data.get("nameservers", []):
                                if isinstance(ns, dict):
                                    ns_name = ns.get("ldhName", "")
                                    if ns_name and ns_name not in out["nameServers"]:
                                        out["nameServers"].append(ns_name)

                        if data.get("status") and not out.get("status"):
                            out["status"] = [
                                s.get("v", s) if isinstance(s, dict) else s
                                for s in data.get("status", [])
                            ]
                        if data.get("dnssec") and not out.get("dnssec"):
                            out["dnssec"] = str(data.get("dnssec"))
                except Exception:
                    pass  # RDAP supplementary failed, whois worked
        except Exception as e:
            # Whois failed, try RDAP as fallback
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
            try:
                url = f"https://{host}/domain/{domain}"
                req = urllib.request.Request(
                    url, headers={"User-Agent": "ReconBubble/1.0"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
                    data = json.loads(raw) if raw else {}
                if not isinstance(data, dict):
                    error_msg = "Invalid RDAP response"
                    raise Exception(error_msg)

                out = {"domainName": data.get("name")}

                entities = {}
                for e in data.get("entities", []):
                    if isinstance(e, dict):
                        roles = e.get("roles", [])
                        vcard = e.get("vcardArray", [])
                        name = email = org = ""
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

                for e in data.get("events", []):
                    if isinstance(e, dict):
                        if e.get("eventAction") == "registration":
                            out["creationDate"] = e.get("eventDate")
                        if e.get("eventAction") == "expiration":
                            out["expirationDate"] = e.get("eventDate")
                        if e.get("eventAction") == "last changed":
                            out["updatedDate"] = e.get("eventDate")

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
                            ns_list.append(
                                f"{ns_name} ({', '.join(ns_ips)})"
                                if ns_ips
                                else ns_name
                            )
                if ns_list:
                    out["nameServers"] = ns_list

                if data.get("status"):
                    out["status"] = [
                        s.get("v", s) if isinstance(s, dict) else s
                        for s in data.get("status", [])
                    ]
                if data.get("dnssec"):
                    out["dnssec"] = str(data.get("dnssec"))
                if data.get("network"):
                    net = data.get("network", {})
                    out["network"] = net.get("name", "")
                    out["cidr"] = net.get("cidr0", "")
            except Exception as rdap_err:
                error_msg = str(rdap_err)[:150]
                out = {"domainName": domain}

        # Save to database
        with db() as s:
            existing = s.scalar(select(DomainInfo).where(DomainInfo.domain == domain))
            di = existing or DomainInfo(domain=domain)
            di.registrar = out.get("registrar", "")
            di.registrar_email = out.get("registrarEmail", "")
            di.registrar_org = out.get("registrarOrg", "")
            di.creation_date = out.get("creationDate", "")
            di.expiration_date = out.get("expirationDate", "")
            di.updated_date = out.get("updatedDate", "")
            di.name_servers = (
                ", ".join(out.get("nameServers", []))
                if isinstance(out.get("nameServers"), list)
                else str(out.get("nameServers", ""))
            )
            di.status = (
                ", ".join(out.get("status", []))
                if isinstance(out.get("status"), list)
                else str(out.get("status", ""))
            )
            di.dnssec = out.get("dnssec", "")
            di.registrant = out.get("registrant", "")
            di.registrant_email = out.get("registrantEmail", "")
            di.admin_contact = out.get("adminContact", "")
            di.admin_email = out.get("adminEmail", "")
            di.tech_contact = out.get("techContact", "")
            di.tech_email = out.get("techEmail", "")
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
            rows = s.execute(
                text(
                    "SELECT domain, nameserver, status FROM dns_zone_transfers ORDER BY domain ASC, nameserver ASC"
                )
            ).fetchall()
            # Group by domain
            grouped = {}
            for r in rows:
                domain = r[0] or "unknown"
                if domain not in grouped:
                    grouped[domain] = []
                grouped[domain].append({"nameserver": r[1], "status": r[2]})
        return templates.TemplateResponse(
            "dns.html", {"request": request, "grouped": grouped}
        )

    @app.get("/smtp", response_class=HTMLResponse)
    def smtp_page(request: Request):
        from sqlalchemy import text

        with db() as s:
            rows = s.execute(
                text(
                    "SELECT mx_host, vrfy, expn, rcpt FROM smtp_scans ORDER BY mx_host ASC"
                )
            ).fetchall()
            data = [
                {"mx_host": r[0], "vrfy": r[1], "expn": r[2], "rcpt": r[3]}
                for r in rows
            ]
        return templates.TemplateResponse(
            "smtp.html", {"request": request, "rows": data}
        )

    return app
