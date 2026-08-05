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
    import_credentials,
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

    @app.middleware("http")
    async def add_cache_headers(request: Request, call_next):
        response = await call_next(request)
        if request.method == "GET":
            if request.url.path.startswith("/api/"):
                response.headers["Cache-Control"] = "private, max-age=30, must-revalidate"
            elif request.url.path.startswith("/static/"):
                response.headers.setdefault("Cache-Control", "public, max-age=86400")
            else:
                response.headers["Cache-Control"] = "private, max-age=10, must-revalidate"
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

    def load_scope_exclusions(s: Session) -> set[str]:
        rows = s.execute(select(ScopeExclusion)).scalars().all()
        return {r.fqdn.strip().lower().strip(".") for r in rows if r.fqdn.strip()}

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

    # ---- Scope helpers ----
    def scope_sets(s: Session, sensitive_only: bool = False):
        if sensitive_only:
            stmt = select(ScopeItem).where(ScopeItem.sensitive == 1)
        else:
            stmt = select(ScopeItem).where(ScopeItem.in_scope == 1)
        items = s.execute(stmt).scalars().all()
        ips, subnets, domains, email_domains, domain_all_subs, domain_subs_if_ip = (
            set(),
            [],
            set(),
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
                if getattr(it, "apply_subdomains_with_in_scope_ip", 0) == 1:
                    if not sensitive_only:
                        domain_subs_if_ip.add(v)
                    else:
                        domain_all_subs.add(v)
            elif it.kind == "email_domain":
                email_domains.add(v)
        excluded = load_scope_exclusions(s)
        # Domains explicitly toggled Out on the scope page also count as exclusions
        # so they override parent apply_all_subdomains / IP-resolve rules
        out_items = s.execute(
            select(ScopeItem)
            .where(
                ScopeItem.in_scope == 0,
                ScopeItem.kind.in_(["domain", "ip", "subnet"]),
            )
        ).scalars().all()
        for it in out_items:
            v = (it.value or "").strip().lower().strip(".")
            if v:
                excluded.add(v)
        return ips, subnets, domains, email_domains, domain_all_subs, domain_subs_if_ip, excluded

    def ip_in_scope(ip: str, ips: set[str], subnets: list, excluded: set[str] | None = None) -> bool:
        ip = (ip or "").strip()
        if not ip:
            return False
        if ip in (excluded or set()):
            return False
        if ip in ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        return any(addr in net for net in subnets)

    def domain_in_scope(
        fqdn: str,
        domains: set[str],
        domain_all_subs: set[str],
        domain_subs_if_ip: set[str] | None = None,
        resolved_ips: list[str] | None = None,
        ips: set[str] | None = None,
        subnets: list | None = None,
        excluded: set[str] | None = None,
    ) -> bool:
        f = (fqdn or "").strip().lower().strip(".")
        if not f:
            return False
        if f in (excluded or set()):
            return False
        needs_ip_match = bool(domain_subs_if_ip and f in domain_subs_if_ip)
        if needs_ip_match:
            ipset = ips or set()
            nets = subnets or []
            result = any(ip_in_scope(ip, ipset, nets, excluded) for ip in (resolved_ips or []))
            return result
        if f in domains:
            return True
        if any(f.endswith("." + d) for d in domain_all_subs if d not in (domain_subs_if_ip or set())):
            return True
        if domain_subs_if_ip:
            matched = any(f == d or f.endswith("." + d) for d in domain_subs_if_ip)
            if matched:
                ipset = ips or set()
                nets = subnets or []
                return any(ip_in_scope(ip, ipset, nets, excluded) for ip in (resolved_ips or []))
        return False

    def host_in_scope(
        ip: str,
        hostname: str,
        ips: set[str],
        subnets: list,
        domains: set[str],
        domain_all_subs: set[str],
        excluded: set[str] | None = None,
    ) -> bool:
        if ip_in_scope(ip, ips, subnets, excluded):
            return True
        if hostname and domain_in_scope(hostname, domains, domain_all_subs, None, [], ips, subnets, excluded):
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

    def list_all_host_domains(s: Session) -> dict[int, list[str]]:
        """Fetch all host-subdomain mappings in a single query."""
        rows = s.execute(
            text(
                "SELECT host_subdomains.host_id, subdomains.fqdn FROM host_subdomains "
                "JOIN subdomains ON subdomains.id = host_subdomains.subdomain_id "
                "ORDER BY host_subdomains.host_id, subdomains.fqdn ASC"
            )
        ).fetchall()
        result: dict[int, list[str]] = {}
        for hid, fqdn in rows:
            result.setdefault(hid, []).append(fqdn)
        return result

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

    def list_all_subdomain_ips(s: Session) -> dict[str, list[str]]:
        """Fetch all subdomain-IP mappings in a single query."""
        rows = s.execute(
            text(
                "SELECT subdomains.fqdn, hosts.ip FROM host_subdomains "
                "JOIN subdomains ON subdomains.id = host_subdomains.subdomain_id "
                "JOIN hosts ON hosts.id = host_subdomains.host_id "
                "ORDER BY subdomains.fqdn, hosts.ip ASC"
            )
        ).fetchall()
        result: dict[str, list[str]] = {}
        for fqdn, ip in rows:
            result.setdefault(fqdn, []).append(ip)
        return result

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

    # ---- Pages ----
    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        with db() as s:
            # Get scope sets
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)

            # Get all hosts
            hosts = s.execute(select(Host)).scalars().all()

            # Count hosts in scope
            hosts_in_scope = sum(1 for h in hosts if host_in_scope(
                h.ip or "",
                h.hostname or "",
                ips, subnets, domains, domain_all_subs
            ))
            hosts_total = len(hosts)
            hosts_out_scope = hosts_total - hosts_in_scope

            # Get all services
            services = s.execute(select(Service)).scalars().all()
            services_total = len(services)

            # Count services by port
            services_by_port = {}
            for svc in services:
                port = str(svc.port)
                services_by_port[port] = services_by_port.get(port, 0) + 1

            # Convert to list for template
            services_by_port_list = list(services_by_port.items())

            stats = {
                "hosts_total": hosts_total,
                "hosts_in_scope": hosts_in_scope,
                "hosts_out_scope": hosts_out_scope,
                "services_total": services_total,
                "services_by_port": services_by_port_list,
            }

        return templates.TemplateResponse(
            "stats.html", {"request": request, "stats": stats}
        )

    # Stats
    @app.get("/stats", response_class=HTMLResponse)
    def stats_page(request: Request):
        with db() as s:
            # Get scope sets
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)

            # Get all hosts
            hosts = s.execute(select(Host)).scalars().all()

            # Count hosts in scope
            hosts_in_scope = sum(1 for h in hosts if host_in_scope(
                h.ip or "",
                h.hostname or "",
                ips, subnets, domains, domain_all_subs
            ))
            hosts_total = len(hosts)
            hosts_out_scope = hosts_total - hosts_in_scope

            # Get all services
            services = s.execute(select(Service)).scalars().all()
            services_total = len(services)

            # Count services by port (only in-scope services)
            services_by_port = {}
            for svc in services:
                # Check if host is in scope
                host = s.get(Host, svc.host_id)
                if host and host_in_scope(
                    host.ip or "",
                    host.hostname or "",
                    ips, subnets, domains, domain_all_subs
                ):
                    port = str(svc.port)
                    services_by_port[port] = services_by_port.get(port, 0) + 1

            # Convert to list for template
            services_by_port_list = list(services_by_port.items())

            stats = {
                "hosts_total": hosts_total,
                "hosts_in_scope": hosts_in_scope,
                "hosts_out_scope": hosts_out_scope,
                "services_total": services_total,
                "services_by_port": services_by_port_list,
            }

        return templates.TemplateResponse(
            "stats.html", {"request": request, "stats": stats}
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
            exclusions = (
                s.execute(
                    select(ScopeExclusion).order_by(ScopeExclusion.created_at.desc())
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
                "exclusions": exclusions,
            },
        )

    @app.post("/scope/add")
    def scope_add(
        kind: str = Form(...),
        value: str = Form(""),
        values_raw: str = Form(""),
        note: str = Form(""),
        apply_all_subdomains: int = Form(0),
        apply_subdomains_with_in_scope_ip: int = Form(0),
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
                    apply_subdomains_with_in_scope_ip=1
                    if (
                        actual_kind == "domain"
                        and apply_subdomains_with_in_scope_ip == 1
                    )
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

    @app.post("/scope/delete-checked")
    def scope_delete_checked(item_ids: list[int] = Form([])):
        ids = [int(x) for x in (item_ids or []) if int(x) > 0]
        if not ids:
            return RedirectResponse(url="/scope", status_code=303)
        with db() as s:
            rows = (
                s.execute(select(ScopeItem).where(ScopeItem.id.in_(ids)))
                .scalars()
                .all()
            )
            for it in rows:
                s.delete(it)
            s.commit()
        return RedirectResponse(url="/scope", status_code=303)

    # Upload
    @app.get("/upload", response_class=HTMLResponse)
    def upload_page(request: Request):
        return templates.TemplateResponse("upload.html", {"request": request, "workspace": ws})

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
        redirect_map = {
            "nmap_xml": "/assets",
            "subdomains": "/subdomains",
            "names_emails": "/users",
            "doc": "/docs",
            "ad_users": "/users",
            "creds": "/app-credentials",
            "urls": "/assets",
            "names": "/users",
            "bbot": "/subdomains",
            "prowl_phase1": "/subdomains",
            "zone_transfers": "/subdomains",
            "smtp": "/users",
            "mixed_hashes": "/users",
            "bbot_cloud": "/cloud",
            "smb_shares": "/smb-shares",
        }
        def _import_file(s: Session, art: Artifact, stored_path: str, fname: str) -> dict:
            """Run the appropriate parser and return normalized result dict."""
            p = Path(stored_path)
            try:
                if kind == "nmap_xml":
                    res = import_nmap_xml(s, art, p)
                elif kind == "subdomains":
                    count = import_subdomains(s, art, p)
                    fqdn_list = s.execute(select(Subdomain.fqdn)).scalars().all()
                    ip_map = resolve_ips_concurrent(list(fqdn_list))
                    for fqdn, ips in ip_map.items():
                        for ip in ips:
                            try:
                                h = upsert_host(s, ip, "", "")
                                link_host_domain(s, h.id, fqdn)
                            except Exception:
                                continue
                    res = {"added": count, "skipped": 0, "unmatched": []}
                elif kind == "names_emails":
                    res = {"added": import_names_emails(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "doc":
                    res = {"added": import_document(s, art, p), "skipped": 0, "unmatched": []}
                    extract_doc_names(s)
                    extract_doc_software(s)
                elif kind == "ad_users":
                    res = {"added": import_ad_users(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "creds":
                    res = {"added": import_credentials(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "urls":
                    res = {"added": import_web_urls(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "names":
                    res = {"added": import_names(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "prowl_phase1":
                    res = {"added": import_prowl_phase1(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "zone_transfers":
                    res = {"added": import_zone_transfers(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "smtp":
                    res = {"added": import_smtp(s, art, p), "skipped": 0, "unmatched": []}
                elif kind == "bbot":
                    res = import_bbot(s, art, p)
                elif kind == "bbot_cloud":
                    res = import_bbot_cloud(s, art, p)
                elif kind == "mixed_hashes":
                    res = import_mixed_hashes(s, art, p)
                elif kind == "smb_shares":
                    res = import_smbmap(s, art, p)
                else:
                    res = {"added": 0, "skipped": 0, "unmatched": [f"Unknown type: {kind}"]}
            except Exception as e:
                res = {"added": 0, "skipped": 0, "unmatched": [f"Error parsing {fname}: {e}"]}
            return res

        def _normalize_result(res: dict) -> dict:
            """Normalize any parser result to {added, skipped, unmatched, details}."""
            if isinstance(res, dict):
                added = res.get("added", 0)
                skipped = res.get("skipped", 0)
                unmatched = res.get("unmatched", []) or []
                details = res.get("details", {})
                # Map known parser-specific keys
                if kind == "nmap_xml":
                    added = res.get("hosts_added", 0)
                    details = {
                        "hosts": res.get("hosts_added", 0),
                        "services": res.get("services_added", 0),
                        "evidence": res.get("evidence_added", 0),
                    }
                elif kind == "bbot":
                    added = res.get("subdomains", 0) + res.get("hosts", 0)
                    details = {
                        "subdomains": res.get("subdomains", 0),
                        "hosts": res.get("hosts", 0),
                        "services": res.get("services", 0),
                        "urls": res.get("urls", 0),
                        "notes": res.get("notes", 0),
                    }
                elif kind == "bbot_cloud":
                    added = res.get("subdomains", 0) + res.get("hosts", 0)
                    details = {
                        "subdomains": res.get("subdomains", 0),
                        "hosts": res.get("hosts", 0),
                        "cloud_items": res.get("cloud_items", 0),
                        "notes": res.get("notes", 0),
                    }
                elif kind == "mixed_hashes":
                    added = res.get("added", 0)
                    skipped = res.get("skipped", 0)
                    unmatched = res.get("unmatched", []) or []
                return {
                    "added": added,
                    "skipped": skipped,
                    "unmatched": unmatched,
                    "details": details,
                }
            return {"added": res, "skipped": 0, "unmatched": [], "details": {}}

        def _get_label(kind: str) -> str:
            return {
                "nmap_xml": "Nmap XML",
                "subdomains": "Subdomains",
                "names_emails": "Names & Emails",
                "doc": "OSINT Document",
                "ad_users": "AD Users",
                "creds": "Credentials",
                "urls": "Web URLs",
                "names": "Names",
                "mixed_hashes": "Mixed Hashes",
                "bbot": "BBOT",
                "bbot_cloud": "BBOT Cloud",
                "prowl_phase1": "Prowler Phase 1",
                "zone_transfers": "Prowler Phase 2",
                "smtp": "Prowler Phase 3",
                "smb_shares": "SMB Shares",
            }.get(kind, kind)

        def _log_upload(kind: str, label: str, filename: str, norm: dict):
            """Persist upload result to DB."""
            with db() as s:
                s.add(UploadLog(
                    kind=kind,
                    label=label,
                    filename=filename,
                    added=norm["added"],
                    skipped=norm["skipped"],
                    failed=len(norm["unmatched"]),
                    unmatched=json.dumps(norm["unmatched"])[:10000],
                    details=json.dumps(norm.get("details", {}))[:5000],
                ))
                s.commit()

        try:
            if raw_text and raw_text.strip():
                default = {
                    "nmap_xml": "pasted_scan.xml",
                    "subdomains": "pasted_subdomains.txt",
                    "names_emails": "pasted_names_emails.txt",
                    "doc": "pasted_document.bin",
                    "ad_users": "pasted_ad_users.txt",
                    "creds": "pasted_creds.txt",
                    "urls": "pasted_urls.txt",
                    "names": "pasted_names.txt",
                    "mixed_hashes": "pasted_mixed_hashes.txt",
                    "smb_shares": "pasted_smb_shares.txt",
                }.get(kind, "pasted.txt")
                fname = (
                    raw_filename.strip()
                    if raw_filename and raw_filename.strip()
                    else default
                )
                stored = ws.store_text(raw_text, fname, prefix=kind)
                with db() as s:
                    art = upsert_artifact(s, kind, Path(stored))
                    raw_result = _import_file(s, art, stored, fname)
                norm = _normalize_result(raw_result)
                _log_upload(kind, _get_label(kind), fname, norm)
                all_errors = list(norm["unmatched"])
                upload_results = [{
                    "type": kind,
                    "added": norm["added"],
                    "skipped": norm["skipped"],
                    "unmatched": norm["unmatched"],
                    "details": norm.get("details", {}),
                }]
                return templates.TemplateResponse(
                    "upload.html",
                    {
                        "request": request,
                        "workspace": ws,
                        "upload_results": upload_results,
                        "upload_results_summary": {
                            "files": [fname],
                            "redirect": redirect_map.get(kind, "/"),
                            "errors": all_errors,
                        },
                    },
                )
            elif file:
                files = file if isinstance(file, list) else [file]
                stored_files = []
                fnames = []
                for f in files:
                    if f and f.filename:
                        tmp = ws.uploads_dir / f"tmp_{f.filename}"
                        tmp.write_bytes(await f.read())
                        stored = ws.store_upload(tmp, prefix=kind)
                        tmp.unlink(missing_ok=True)
                        stored_files.append(stored)
                        fnames.append(f.filename)
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
                upload_results = []
                all_errors = []
                with db() as s:
                    for i, stored_path in enumerate(stored_files):
                        fname = fnames[i] if i < len(fnames) else "file"
                        art = upsert_artifact(s, kind, Path(stored_path))
                        raw_result = _import_file(s, art, stored_path, fname)
                        norm = _normalize_result(raw_result)
                        _log_upload(kind, _get_label(kind), fname, norm)
                        all_errors.extend(norm["unmatched"])
                        upload_results.append({
                            "type": kind,
                            "added": norm["added"],
                            "skipped": norm["skipped"],
                            "unmatched": norm["unmatched"],
                            "details": norm.get("details", {}),
                        })
                return templates.TemplateResponse(
                    "upload.html",
                    {
                        "request": request,
                        "workspace": ws,
                        "upload_results": upload_results,
                        "upload_results_summary": {
                            "files": fnames,
                            "redirect": redirect_map.get(kind, "/"),
                            "errors": all_errors,
                        },
                    },
                )
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

    @app.get("/api/upload-log")
    def get_upload_log(request: Request):
        with db() as s:
            rows = s.execute(select(UploadLog).order_by(UploadLog.created_at.desc()).limit(50)).scalars().all()
        return {
            entry.id: {
                "id": entry.id,
                "kind": entry.kind,
                "label": entry.label,
                "filename": entry.filename,
                "added": entry.added,
                "skipped": entry.skipped,
                "failed": entry.failed,
                "unmatched": json.loads(entry.unmatched) if entry.unmatched else [],
                "details": json.loads(entry.details) if entry.details else {},
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
            }
            for entry in rows
        }

    @app.post("/api/upload-log/clear")
    def clear_upload_log(request: Request):
        with db() as s:
            s.execute(UploadLog.__table__.delete())
            s.commit()
        return {"ok": True}

    # Assets
    @app.get("/assets", response_class=HTMLResponse)
    def assets(request: Request):
        show_out = int(request.query_params.get("show_out", "0"))
        hide_completed = int(request.query_params.get("hide_completed", "0"))
        hide_zero_services = int(request.query_params.get("hide_zero_services", "0"))
        row_limit_raw = (request.query_params.get("row_limit", "0") or "0").strip()
        try:
            row_limit = max(0, int(row_limit_raw))
        except ValueError:
            row_limit = 0

        page_raw = (request.query_params.get("page", "1") or "1").strip()
        try:
            page = max(1, int(page_raw))
        except ValueError:
            page = 1
        page_size = 200 if row_limit == 0 else 0

        def subnet_sort_key(net):
            return (net.version, int(net.network_address), net.prefixlen)

        with db() as s:
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs, s_domain_subs_if_ip, s_excluded = (
                scope_sets(s, sensitive_only=True)
            )
            scope_is_empty = not bool(ips or subnets or domains)
            total_count = s.execute(
                select(func.count(Host.id))
            ).scalar()

            offset = (page - 1) * page_size if page_size > 0 else 0
            q = select(
                Host.id,
                Host.ip,
                Host.hostname,
                Host.done,
                Host.complete,
                Host.inprogress,
                Host.waf,
                Host.tag,
                func.count(Service.id).label("svc_count"),
            ).outerjoin(Service, Service.host_id == Host.id).group_by(Host.id).order_by(func.count(Service.id).desc(), Host.ip.asc())
            if page_size > 0:
                q = q.limit(page_size).offset(offset)
            rows = s.execute(q).all()
            all_host_domains = list_all_host_domains(s)
            domains_by_host = {r.id: all_host_domains.get(r.id, []) for r in rows}
            # Fetch all IPs for accurate subnet stats, independent of pagination/row_limit
            all_rows = s.execute(select(Host.id, Host.ip)).all()
            all_ips = {r.id: r.ip for r in all_rows}
        data = []
        for r in rows:
            ip_in = ip_in_scope(r.ip, ips, subnets, excluded)
            ip_sensitive = ip_in_scope(r.ip, s_ips, s_subnets, s_excluded)
            host_domains = domains_by_host.get(r.id, [])
            # Check scope for each individual domain
            domain_list = []
            any_domain_in = False
            any_domain_sensitive = False
            for d in host_domains:
                d_in = domain_in_scope(
                    d, domains, domain_all_subs, domain_subs_if_ip, [r.ip], ips, subnets, excluded
                )
                d_sensitive = domain_in_scope(
                    d,
                    s_domains,
                    s_domain_all_subs,
                    s_domain_subs_if_ip,
                    [r.ip],
                    s_ips,
                    s_subnets,
                    s_excluded,
                )
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
                    "inprogress": getattr(r, "inprogress", 0),
                    "waf": getattr(r, "waf", 0),
                    "tag": getattr(r, "tag", ""),
                    "svc_count": r.svc_count,
                    "ip_in_scope": ip_in,
                    "ip_sensitive": ip_sensitive,
                    "domain_in_scope": any_domain_in,
                    "in_scope": ip_in or any_domain_in,
                    "sensitive": ip_sensitive or any_domain_sensitive,
                    "domains": domain_list,
                }
            )

        compromised_ids = _topology_compromised_ids()
        compromised_asset_ids = compromised_ids.get("asset_ids", set()) if compromised_ids else set()

        # Build asset_id -> topology_node_id mapping for row-level topo buttons
        topology_asset_node_ids: dict[str, str] = {}
        with db() as s:
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
                        aid = n.get("linked_asset_id")
                        if aid:
                            topology_asset_node_ids[str(aid)] = n.get("id", "")
                except Exception:
                    pass

        in_scope_data = [d for d in data if d.get("in_scope")]
        filtered_data = data if show_out == 1 else in_scope_data
        if hide_completed == 1:
            filtered_data = [d for d in filtered_data if int(d.get("complete", 0)) != 1]
        if hide_zero_services == 1:
            filtered_data = [d for d in filtered_data if int(d.get("svc_count", 0)) > 0]

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

        # Build subnet stats from ALL hosts, not just the current page
        all_in_scope_ips = []
        for hid, hip in all_ips.items():
            if ip_in_scope(hip, ips, subnets, excluded):
                all_in_scope_ips.append(hip)
        for ip_str in all_in_scope_ips:
            label = classify_subnet_label(ip_str, allow_infer=True)
            if not label:
                continue
            if label in subnet_stats:
                subnet_stats[label] = subnet_stats.get(label, 0) + 1
            else:
                inferred_stats[label] = inferred_stats.get(label, 0) + 1

        grouped: dict[str, list[dict]] = {}
        for row in data:
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
                "hide_completed": hide_completed,
                "hide_zero_services": hide_zero_services,
                "row_limit": row_limit,
                "shown_count": shown_count,
                "total_count": total_before_limit,
                "subnet_stats": subnet_stats_list,
                "in_scope_total": len(all_in_scope_ips),
                "scope_is_empty": scope_is_empty,
                "compromised_asset_ids": compromised_asset_ids,
                "topology_asset_node_ids": topology_asset_node_ids,
                "page": page,
                "page_size": page_size,
                "total_hosts": total_count,
            },
        )

    @app.post("/api/host/create")
    def api_host_create(
        ip: str = Form(...), hostname: str = Form(""), tag: str = Form(""), domains_raw: str = Form("")
    ):
        ip = ip.strip()
        hostname = (hostname or "").strip()
        tag = (tag or "").strip()
        domains = [
            ln.strip().lower().rstrip(".")
            for ln in (domains_raw or "").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        with db() as s:
            # Check for duplicate IP
            existing = s.scalar(select(Host).where(Host.ip == ip))
            if existing:
                return {"ok": False, "error": f"IP {ip} already exists as an asset."}

            try:
                host = upsert_host(s, ip, hostname, "")
                if tag:
                    host.tag = tag
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
                    "tag": host.tag,
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

    @app.get("/api/hosts/list")
    def api_hosts_list():
        with db() as s:
            hosts = s.execute(select(Host).order_by(Host.ip.asc())).scalars().all()
        compromised_ids = _topology_compromised_ids()
        compromised_asset_ids = compromised_ids.get("asset_ids", set()) if compromised_ids else set()
        return {
            "ok": True,
            "hosts": [
                {
                    "id": h.id,
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "os_guess": h.os_guess,
                    "compromised": str(h.id) in compromised_asset_ids,
                }
                for h in hosts
            ],
        }

    @app.get("/api/hosts/{host_id}")
    def api_host_detail(host_id: int):
        with db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host:
                return JSONResponse({"ok": False, "error": "Host not found"}, status_code=404)
            
            services = s.execute(
                select(Service).where(Service.host_id == host.id)
            ).scalars().all()
            
            return {
                "ok": True,
                "host": {
                    "id": host.id,
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "os": host.os_guess,
                    "status": "active",
                    "services": [
                        {
                            "id": svc.id,
                            "port": svc.port,
                            "protocol": svc.proto,
                            "service": svc.service_name,
                            "version": svc.version,
                        }
                        for svc in services
                    ],
                    "tags": [t.strip() for t in host.tag.split(",") if t.strip()],
                },
            }

    @app.post("/api/host/tag/delete")
    def api_host_tag_delete(host_id: int = Form(...), tag: str = Form(...)):
        with db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host or not host.tag:
                return JSONResponse({"ok": False}, status_code=404)
            
            tags = [t.strip() for t in host.tag.split(",") if t.strip()]
            if tag in tags:
                tags.remove(tag)
                host.tag = ",".join(tags)
                s.commit()
                return {"ok": True}
            return JSONResponse({"ok": False, "error": "Tag not found"}, status_code=404)

    @app.post("/api/host/update")
    def api_host_update(
        host_id: int = Form(...),
        ip: str = Form(...),
        hostname: str = Form(""),
        os_guess: str = Form(""),
        tag: str = Form(""),
        domains_raw: str = Form(""),
    ):
        ip = ip.strip()
        hostname = (hostname or "").strip()
        os_guess = (os_guess or "").strip()
        tag = (tag or "").strip()
        domains = [
            ln.strip().lower().rstrip(".")
            for ln in (domains_raw or "").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        with db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host:
                return JSONResponse({"ok": False, "error": "Host not found"}, status_code=404)

            # Check for duplicate IP on another host
            if ip != host.ip:
                clash = s.scalar(select(Host).where(Host.ip == ip, Host.id != host_id))
                if clash:
                    return {"ok": False, "error": f"IP {ip} already belongs to another host."}

            host.ip = ip
            host.hostname = hostname
            host.os_guess = os_guess
            if tag:
                host.tag = tag

            try:
                s.commit()
            except Exception:
                s.rollback()
                return {"ok": False, "error": "Failed to save host (check for duplicate IP)."}

            try:
                existing_domains = list_host_domains(s, host.id)
                # Remove domains no longer in the list
                for d in existing_domains:
                    if d not in domains:
                        s.execute(
                            text(
                                "DELETE FROM host_subdomains WHERE host_id = :hid AND subdomain_id = (SELECT id FROM subdomains WHERE fqdn = :fq)"
                            ),
                            {"hid": host.id, "fq": d},
                        )
                s.commit()
                # Add new domains
                for d in domains:
                    if DOMAIN_RE.match(d):
                        link_host_domain(s, host.id, d)
            except Exception as e:
                return {"ok": True, "warning": f"Saved but failed to link domains: {e}"}

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

    @app.post("/api/service/create")
    def api_service_create(
        host_id: int = Form(...),
        port: int = Form(...),
        proto: str = Form("tcp"),
        state: str = Form("open"),
        service_name: str = Form(""),
        product: str = Form(""),
        version: str = Form(""),
        extra_info: str = Form(""),
        raw_output: str = Form(""),
    ):
        proto = (proto or "tcp").strip().lower()[:8]
        state = (state or "open").strip().lower()[:16]
        service_name = (service_name or "").strip()
        product = (product or "").strip()
        version = (version or "").strip()
        extra_info = (extra_info or "").strip()
        raw_output = (raw_output or "").strip()

        if port <= 0 or port > 65535:
            return JSONResponse(
                {"ok": False, "error": "Port must be 1-65535"}, status_code=400
            )

        with db() as s:
            host = s.scalar(select(Host).where(Host.id == host_id))
            if not host:
                return JSONResponse(
                    {"ok": False, "error": "Host not found"}, status_code=404
                )

            svc = s.scalar(
                select(Service).where(
                    Service.host_id == host_id,
                    Service.port == port,
                    Service.proto == proto,
                )
            )

            if not svc:
                svc = Service(
                    host_id=host_id,
                    port=port,
                    proto=proto,
                    state=state or "open",
                    service_name=service_name,
                    product=product,
                    version=version,
                    extra_info=extra_info,
                )
                s.add(svc)
                s.flush()
            else:
                svc.state = state or svc.state
                svc.service_name = service_name or svc.service_name
                svc.product = product or svc.product
                svc.version = version or svc.version
                svc.extra_info = extra_info or svc.extra_info

            if raw_output:
                manual_dir = ws.uploads_dir / "manual_evidence"
                manual_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
                ev_path = manual_dir / f"service-{host_id}-{port}-{proto}-{stamp}.txt"
                ev_path.write_text(raw_output, encoding="utf-8", errors="replace")
                art = upsert_artifact(s, "service-evidence", ev_path)
                s.add(
                    ServiceEvidence(
                        service_id=svc.id,
                        artifact_id=art.id,
                        raw_output=raw_output,
                    )
                )

            s.commit()
            return {"ok": True, "service_id": svc.id}

    @app.post("/api/service/update")
    def api_service_update(
        service_id: int = Form(...),
        port: int = Form(...),
        proto: str = Form("tcp"),
        state: str = Form("open"),
        service_name: str = Form(""),
        product: str = Form(""),
        version: str = Form(""),
        extra_info: str = Form(""),
        raw_output: str = Form(""),
    ):
        proto = (proto or "tcp").strip().lower()[:8]
        state = (state or "open").strip().lower()[:16]
        service_name = (service_name or "").strip()
        product = (product or "").strip()
        version = (version or "").strip()
        extra_info = (extra_info or "").strip()
        raw_output = (raw_output or "").strip()

        if port <= 0 or port > 65535:
            return JSONResponse(
                {"ok": False, "error": "Port must be 1-65535"}, status_code=400
            )

        with db() as s:
            svc = s.scalar(select(Service).where(Service.id == service_id))
            if not svc:
                return JSONResponse(
                    {"ok": False, "error": "Service not found"}, status_code=404
                )

            clash = s.scalar(
                select(Service).where(
                    Service.host_id == svc.host_id,
                    Service.port == port,
                    Service.proto == proto,
                    Service.id != svc.id,
                )
            )
            if clash:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": "Another service already exists for this host+port+proto",
                    },
                    status_code=400,
                )

            svc.port = port
            svc.proto = proto
            svc.state = state
            svc.service_name = service_name
            svc.product = product
            svc.version = version
            svc.extra_info = extra_info

            if raw_output:
                manual_dir = ws.uploads_dir / "manual_evidence"
                manual_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
                ev_path = (
                    manual_dir / f"service-{svc.host_id}-{port}-{proto}-{stamp}.txt"
                )
                ev_path.write_text(raw_output, encoding="utf-8", errors="replace")
                art = upsert_artifact(s, "service-evidence", ev_path)
                s.add(
                    ServiceEvidence(
                        service_id=svc.id,
                        artifact_id=art.id,
                        raw_output=raw_output,
                    )
                )

            s.commit()
            return {"ok": True, "service_id": svc.id}

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
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs, s_domain_subs_if_ip, s_excluded = (
                scope_sets(s, sensitive_only=True)
            )
            all_ips = list_all_subdomain_ips(s)
            ips_found = all_ips.get(fq, [])
            in_dom = domain_in_scope(
                fq, domains, domain_all_subs, domain_subs_if_ip, ips_found, ips, subnets, excluded
            )
            in_ip = any(ip_in_scope(ip, ips, subnets, excluded) for ip in ips_found)
            sensitive_dom = domain_in_scope(
                fq,
                s_domains,
                s_domain_all_subs,
                s_domain_subs_if_ip,
                ips_found,
                s_ips,
                s_subnets,
                s_excluded,
            )
            sensitive_ip = any(ip_in_scope(ip, s_ips, s_subnets, s_excluded) for ip in ips_found)
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
        with db() as s:
            shares = s.execute(
                select(SmbShare).order_by(SmbShare.host, SmbShare.share)
            ).scalars().all()
            hosts_map: dict[str, list[SmbShare]] = {}
            for sh in shares:
                hosts_map.setdefault(sh.host, []).append(sh)
        return templates.TemplateResponse("smb_shares.html", {"request": request, "shares": shares, "hosts_map": hosts_map})

    @app.post("/api/smb-shares/create", response_class=JSONResponse)
    def smb_shares_create(host: str = Form(""), shares: str = Form("")):
        host = host.strip()
        if not host:
            return {"ok": False, "error": "Host is required."}
        lines = [l.strip() for l in shares.strip().split("\n") if l.strip()]
        if not lines:
            return {"ok": False, "error": "At least one share entry is required."}
        added = 0
        skipped = 0
        errors = []
        with db() as s:
            for idx, line in enumerate(lines, 1):
                parts = line.split(",")
                if len(parts) < 1:
                    errors.append(f"Row {idx}: empty line")
                    continue
                share_name = parts[0].strip()
                access_val = parts[1].strip().upper() if len(parts) > 1 else "NO_ACCESS"
                note_val = ", ".join(p.strip() for p in parts[2:]).strip() if len(parts) > 2 else ""
                if not share_name:
                    errors.append(f"Row {idx}: share name is empty")
                    continue
                existing = s.scalar(
                    select(SmbShare).where(
                        SmbShare.host == host,
                        SmbShare.share == share_name,
                    )
                )
                if existing:
                    skipped += 1
                    continue
                s.add(SmbShare(host=host, share=share_name, access=access_val, notes=note_val))
                added += 1
            s.commit()
        return {"ok": True, "added": added, "skipped": skipped, "errors": errors}

    @app.post("/api/smb-shares/create-one", response_class=JSONResponse)
    def smb_shares_create_one(host: str = Form(""), share: str = Form(""), access: str = Form(""), notes: str = Form("")):
        host = host.strip()
        share = share.strip()
        access = access.strip().upper()
        notes = notes.strip()
        if not host or not share:
            return {"ok": False, "error": "Host and share are required."}
        with db() as s:
            existing = s.scalar(
                select(SmbShare).where(
                    SmbShare.host == host,
                    SmbShare.share == share,
                )
            )
            if existing:
                return {"ok": False, "error": "This share entry already exists."}
            s.add(SmbShare(host=host, share=share, access=access, notes=notes))
            s.commit()
        return {"ok": True}

    @app.post("/api/smb-shares/update", response_class=JSONResponse)
    def smb_shares_update(share_id: int = Form(0), host: str = Form(""), share: str = Form(""), access: str = Form(""), notes: str = Form("")):
        if not share_id:
            return {"ok": False, "error": "share_id is required."}
        host = host.strip()
        share = share.strip()
        access = access.strip().upper()
        notes = notes.strip()
        if not host or not share:
            return {"ok": False, "error": "Host and share are required."}
        with db() as s:
            target = s.get(SmbShare, share_id)
            if not target:
                return {"ok": False, "error": "Not found."}
            existing = s.scalar(
                select(SmbShare).where(
                    SmbShare.host == host,
                    SmbShare.share == share,
                    SmbShare.id != share_id,
                )
            )
            if existing:
                return {"ok": False, "error": "Another share entry already exists with these values."}
            target.host = host
            target.share = share
            target.access = access
            target.notes = notes
            s.commit()
        return {"ok": True}

    @app.post("/api/smb-shares/delete", response_class=JSONResponse)
    def smb_shares_delete(share_id: int = Form(0)):
        if not share_id:
            return {"ok": False, "error": "share_id is required."}
        with db() as s:
            target = s.get(SmbShare, share_id)
            if not target:
                return {"ok": False, "error": "Not found."}
            s.delete(target)
            s.commit()
        return {"ok": True}

    @app.get("/api/smb-shares/list", response_class=JSONResponse)
    def smb_shares_list():
        with db() as s:
            shares = s.execute(
                select(SmbShare).order_by(SmbShare.host, SmbShare.share)
            ).scalars().all()
            hosts_map: dict[str, list[dict]] = {}
            for sh in shares:
                hosts_map.setdefault(sh.host, []).append({
                    "id": sh.id,
                    "share": sh.share,
                    "access": sh.access,
                    "notes": sh.notes,
                })
        return {"hosts": hosts_map, "total": len(shares)}

    @app.get("/topology", response_class=HTMLResponse)
    def topology_page(request: Request):
        return templates.TemplateResponse("topology.html", {"request": request})

    @app.get("/osint/registrars", response_class=HTMLResponse)
    def osint_registrars_page(request: Request):
        with db() as s:
            subs = s.execute(
                select(Subdomain)
                .order_by(Subdomain.root_domain, Subdomain.fqdn)
            ).scalars().all()

            # Get registrar overrides
            reg_overrides = s.execute(
                select(RegistrarInfo).order_by(RegistrarInfo.domain)
            ).scalars().all()

        # Group subdomains by root domain (only those with prowl data)
        grouped: dict[str, list[Subdomain]] = {}
        for sub in subs:
            if sub.prowl_ips or sub.prowl_registrar or sub.prowl_netblocks:
                grouped.setdefault(sub.root_domain, []).append(sub)

        # Also include domains from RegistrarInfo that aren't in grouped
        for ri in reg_overrides:
            if ri.domain not in grouped:
                grouped[ri.domain] = []

        # Build registrar/netblock/asn info per root domain + manual subdomain_ips
        root_info: dict[str, dict[str, str]] = {}
        manual_sub_ips: dict[str, str] = {}
        for root, sub_list in grouped.items():
            # Start with prowl data
            registrar = next((s.prowl_registrar for s in sub_list if s.prowl_registrar), "")
            netblocks = next((s.prowl_netblocks for s in sub_list if s.prowl_netblocks), "")
            asn = ""

            # Override with manual RegistrarInfo if exists
            for ri in reg_overrides:
                if ri.domain == root:
                    registrar = ri.registrar or registrar
                    netblocks = ri.netblocks or netblocks
                    asn = ri.asn or asn
                    if ri.subdomain_ips:
                        manual_sub_ips[root] = ri.subdomain_ips
                    break

            root_info[root] = {
                "registrar": registrar,
                "netblocks": netblocks,
                "asn": asn,
            }

        return templates.TemplateResponse(
            "osint_registrars.html",
            {
                "request": request,
                "grouped": dict(sorted(grouped.items())),
                "root_info": root_info,
                "manual_sub_ips": manual_sub_ips,
            },
        )

    @app.get("/api/registrar")
    def api_registrar_list(domain: str | None = Query(None)):
        with db() as s:
            if domain:
                # Return merged data for specific domain
                ri = s.execute(select(RegistrarInfo).where(RegistrarInfo.domain == domain.lower().strip())).scalars().first()
                subs = s.execute(select(Subdomain).where(Subdomain.root_domain == domain.lower().strip()).order_by(Subdomain.fqdn)).scalars().all()
                prowl_reg = next((sb.prowl_registrar for sb in subs if sb.prowl_registrar), "")
                prowl_nb = next((sb.prowl_netblocks for sb in subs if sb.prowl_netblocks), "")
                subdomain_list = [{"fqdn": sb.fqdn, "ips": sb.prowl_ips} for sb in subs if sb.prowl_ips or sb.fqdn]
                manual_sub_ips = ""
                if ri:
                    manual_sub_ips = ri.subdomain_ips or ""
                else:
                    # Build subdomain list from Prowler data for initial textarea
                    for sb in subs:
                        ips = sb.prowl_ips if sb.prowl_ips else ""
                        manual_sub_ips += f"{sb.fqdn} {ips}\n" if ips else f"{sb.fqdn}\n"
                if ri:
                    return {
                        "ok": True,
                        "item": {
                            "id": ri.id,
                            "domain": ri.domain,
                            "asn": ri.asn,
                            "registrar": ri.registrar,
                            "netblocks": ri.netblocks,
                        },
                        "subdomains": subdomain_list,
                        "subdomain_ips": manual_sub_ips.rstrip('\n'),
                    }
                else:
                    return {
                        "ok": True,
                        "item": {
                            "id": None,
                            "domain": domain.lower().strip(),
                            "asn": "",
                            "registrar": prowl_reg,
                            "netblocks": prowl_nb,
                        },
                        "subdomains": subdomain_list,
                        "subdomain_ips": manual_sub_ips.rstrip('\n'),
                    }
            else:
                items = s.execute(select(RegistrarInfo)).scalars().all()
                return {
                    "ok": True,
                    "items": [
                        {
                            "id": i.id,
                            "domain": i.domain,
                            "asn": i.asn,
                            "registrar": i.registrar,
                            "netblocks": i.netblocks,
                            "subdomain_ips": i.subdomain_ips,
                        }
                        for i in items
                    ],
                }

    @app.get("/api/registrar/copy")
    def api_registrar_copy(domain: str = Query(...)):
        domain = domain.lower().strip()
        with db() as s:
            ri = s.execute(select(RegistrarInfo).where(RegistrarInfo.domain == domain)).scalars().first()
            subs = s.execute(select(Subdomain).where(Subdomain.root_domain == domain).order_by(Subdomain.fqdn)).scalars().all()
            prowl_reg = next((sb.prowl_registrar for sb in subs if sb.prowl_registrar), "")
            prowl_nb = next((sb.prowl_netblocks for sb in subs if sb.prowl_netblocks), "")
            prowl_asn = ""

            registrar = (ri.registrar if ri else "") or prowl_reg
            netblocks = (ri.netblocks if ri else "") or prowl_nb
            asn = (ri.asn if ri else "") or prowl_asn
            manual_sub_ips = ri.subdomain_ips if ri else ""

        html = f"<ul><li>{domain}<ul>"
        html += f"<li>Registrar: {registrar}</li>"
        if asn:
            html += f"<li>ASN: {asn}</li>"
        if netblocks:
            for nb in netblocks.split(","):
                nb = nb.strip()
                if nb:
                    html += f"<li>Network: {nb}</li>"
        sub_lines = []
        if manual_sub_ips:
            for line in manual_sub_ips.strip().split("\n"):
                parts = line.strip().split()
                if parts:
                    fqdn = parts[0]
                    ips = parts[1:]
                    sub_lines.append(f"<li>{fqdn} : {', '.join(ips)}</li>")
        else:
            for sb in subs:
                if sb.prowl_ips:
                    ips = [ip.strip() for ip in sb.prowl_ips.split(",") if ip.strip()]
                    sub_lines.append(f"<li>{sb.fqdn} : {', '.join(ips)}</li>")
        if sub_lines:
            html += f"<li>Subdomains<ul>{''.join(sub_lines)}</ul></li>"
        html += "</ul></li></ul>"

        # Plain text fallback
        lines = [f"• {domain}"]
        lines.append(f"  • Registrar: {registrar}")
        if asn:
            lines.append(f"  • ASN: {asn}")
        if netblocks:
            for nb in netblocks.split(","):
                nb = nb.strip()
                if nb:
                    lines.append(f"  • Network: {nb}")
        plain_subs = []
        if manual_sub_ips:
            for line in manual_sub_ips.strip().split("\n"):
                parts = line.strip().split()
                if parts:
                    fqdn = parts[0]
                    ips = parts[1:]
                    plain_subs.append(f"    • {fqdn} : {', '.join(ips)}")
        else:
            for sb in subs:
                if sb.prowl_ips:
                    ips = [ip.strip() for ip in sb.prowl_ips.split(",") if ip.strip()]
                    plain_subs.append(f"    • {sb.fqdn} : {', '.join(ips)}")
        if plain_subs:
            lines.append(f"  • Subdomains")
            lines.extend(plain_subs)
        text = "\n".join(lines) + "\n"

        return {"text": text, "html": html}

    @app.post("/api/registrar/create")
    def api_registrar_create(
        domain: str = Form(""),
        asn: str = Form(""),
        registrar: str = Form(""),
        registrar_email: str = Form(""),
        registrar_org: str = Form(""),
        netblocks: str = Form(""),
        subdomain_ips: str = Form(""),
        creation_date: str = Form(""),
        expiration_date: str = Form(""),
        notes: str = Form(""),
        has_existing: str = Form("0"),
    ):
        domain = domain.lower().strip()
        with db() as s:
            if has_existing == "0":
                existing = s.execute(select(RegistrarInfo).where(RegistrarInfo.domain == domain)).scalars().first()
                if existing:
                    return {"ok": False, "error": "Domain already exists."}
                ri = RegistrarInfo(
                    domain=domain,
                    asn=asn,
                    registrar=registrar,
                    registrar_email=registrar_email,
                    registrar_org=registrar_org,
                    netblocks=netblocks,
                    subdomain_ips=subdomain_ips,
                    creation_date=creation_date,
                    expiration_date=expiration_date,
                    notes=notes,
                )
                s.add(ri)
            else:
                ri = s.execute(select(RegistrarInfo).where(RegistrarInfo.domain == domain)).scalars().first()
                if ri:
                    ri.asn = asn
                    ri.registrar = registrar
                    ri.registrar_email = registrar_email
                    ri.registrar_org = registrar_org
                    ri.netblocks = netblocks
                    ri.subdomain_ips = subdomain_ips
                    ri.creation_date = creation_date
                    ri.expiration_date = expiration_date
                    ri.notes = notes
            s.commit()
        return {"ok": True}

    @app.post("/api/registrar/update")
    def api_registrar_update(
        registrar_id: int = Form(...),
        domain: str = Form(""),
        asn: str = Form(""),
        registrar: str = Form(""),
        registrar_email: str = Form(""),
        registrar_org: str = Form(""),
        netblocks: str = Form(""),
        subdomain_ips: str = Form(""),
        creation_date: str = Form(""),
        expiration_date: str = Form(""),
        notes: str = Form(""),
    ):
        with db() as s:
            ri = s.get(RegistrarInfo, registrar_id)
            if not ri:
                return {"ok": False, "error": "Not found."}
            if domain:
                ri.domain = domain.lower().strip()
            ri.asn = asn
            ri.registrar = registrar
            ri.registrar_email = registrar_email
            ri.registrar_org = registrar_org
            ri.netblocks = netblocks
            ri.subdomain_ips = subdomain_ips
            ri.creation_date = creation_date
            ri.expiration_date = expiration_date
            ri.notes = notes
            s.commit()
        return {"ok": True}

    @app.post("/api/registrar/delete")
    def api_registrar_delete(registrar_id: int = Form(...)):
        with db() as s:
            ri = s.get(RegistrarInfo, registrar_id)
            if not ri:
                return {"ok": False, "error": "Not found."}
            s.delete(ri)
            s.commit()
        return {"ok": True}

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

            # Detect deleted user nodes and clear topology_node_id from NameItem
            if row and (row.body or "").strip():
                try:
                    old_data = json.loads(row.body)
                    old_user_ids = {
                        n["id"]
                        for n in (old_data.get("nodes") or [])
                        if n.get("type") == "user"
                    }
                    new_user_ids = {n["id"] for n in nodes if n.get("type") == "user"}
                    deleted_user_ids = old_user_ids - new_user_ids
                    if deleted_user_ids:
                        for ni in s.execute(
                            select(NameItem).where(NameItem.topology_node_id.in_(deleted_user_ids))
                        ).scalars().all():
                            ni.topology_node_id = ""
                except Exception:
                    pass

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
        with db() as s:
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

    @app.post("/api/topology/add-node")
    async def api_topology_add_node(request: Request):
        body = await request.json()
        asset_id = body.get("asset_id")
        hostname = body.get("hostname", "unknown")
        ip = body.get("ip", "")

        # Load current topology
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

    @app.post("/api/topology/add-domain")
    async def api_topology_add_domain(request: Request):
        body = await request.json()
        domain = body.get("domain", "").strip()
        asn = body.get("asn", "").strip()
        registrar = body.get("registrar", "").strip()
        netblocks = body.get("netblocks", "").strip()
        subdomain_ips = body.get("subdomain_ips", "").strip()
        if not domain:
            return {"ok": False, "error": "Domain is required"}

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

    @app.post("/api/topology/add-user")
    async def api_topology_add_user(request: Request):
        body = await request.json()
        label = body.get("label", "").strip()
        email = body.get("email", "").strip()
        phone = body.get("phone", "").strip()
        name_id = body.get("name_id")
        if not label:
            return {"ok": False, "error": "Label is required"}

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

            existing = [n for n in data["nodes"] if n.get("label") == label and n.get("type") == "user"]
            if existing:
                return {"ok": False, "error": f"User node \"{label}\" already exists in topology"}

            import time
            node_id = f"n_user_{label.replace(' ', '_')}_{int(time.time())}"

            # Resolve name_id: use provided id, or auto-match by first/last name
            resolved_name_id = name_id
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
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs, s_domain_subs_if_ip, s_excluded = (
                scope_sets(s, sensitive_only=True)
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
            all_ips_map = list_all_subdomain_ips(s)
            root_domains = {}
            for x in rows:
                ips_found = all_ips_map.get(x.fqdn, [])
                prowl_ips_list = (x.prowl_ips or "").split(",")
                prowl_ips_cleaned = [ip.strip() for ip in prowl_ips_list if ip.strip()]
                all_ips = list(set(ips_found) | set(prowl_ips_cleaned))
                in_dom = domain_in_scope(
                    x.fqdn,
                    domains,
                    domain_all_subs,
                    domain_subs_if_ip,
                    ips_found,
                    ips,
                    subnets,
                    excluded,
                )
                in_ip = any(ip_in_scope(ip, ips, subnets, excluded) for ip in all_ips)
                in_scope = bool(in_dom or in_ip)
                sensitive_dom = domain_in_scope(
                    x.fqdn,
                    s_domains,
                    s_domain_all_subs,
                    s_domain_subs_if_ip,
                    ips_found,
                    s_ips,
                    s_subnets,
                    s_excluded,
                )
                sensitive_ip_set = {
                    ip for ip in all_ips if ip_in_scope(ip, s_ips, s_subnets, s_excluded)
                }
                sensitive = bool(sensitive_dom or bool(sensitive_ip_set))
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
                        "sensitive_ips": sensitive_ip_set,
                        "rdap": rdap,
                        "prowl": prowl,
                        "scope_override": None,
                    }
                )
                if x.root_domain and x.root_domain not in root_domains:
                    root_domains[x.root_domain] = rdap

            # Query all WebUrl records
            url_rows = (
                s.execute(
                    select(WebUrl).order_by(WebUrl.domain.asc(), WebUrl.url.asc())
                )
                .scalars()
                .all()
            )
            # Build hostname -> urls lookup
            url_by_host: dict[str, list[dict]] = {}
            for u in url_rows:
                try:
                    hostname = (urlsplit(u.url).hostname or "").strip().lower().strip(".")
                    if not hostname:
                        hostname = (urlsplit("http://" + u.url).hostname or "").strip().lower().strip(".")
                except Exception:
                    hostname = ""
                if not hostname:
                    continue
                if hostname not in url_by_host:
                    url_by_host[hostname] = []
                url_by_host[hostname].append(
                    {
                        "id": u.id,
                        "url": u.url,
                        "domain": u.domain,
                        "title": u.title,
                        "status_code": u.status_code,
                    }
                )

        # Group by root domain, attaching matched URLs to each subdomain
        grouped = {}
        for r in out:
            rd = r["root_domain"] or "unknown"
            if rd not in grouped:
                grouped[rd] = {"subs": [], "rdap": root_domains.get(rd, {})}
            # Attach URLs matching this subdomain's FQDN
            r["urls"] = url_by_host.get(r["fqdn"], [])
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
            {"request": request, "grouped": grouped_filtered, "show_out": show_out, "excluded": excluded},
        )

    @app.get("/docs", response_class=HTMLResponse)
    def docs(request: Request):
        from .parsers import DOC_NAME_FIELDS, DOC_SOFTWARE_FIELDS
        with db() as s:
            rows = (
                s.execute(select(Document).order_by(Document.created_at.desc()))
                .scalars()
                .all()
            )
        return templates.TemplateResponse(
            "docs.html", {"request": request, "rows": rows, "name_fields": sorted(DOC_NAME_FIELDS), "software_fields": sorted(DOC_SOFTWARE_FIELDS)}
        )

    @app.get("/api/doc/names")
    def api_doc_names(field: str = ""):
        from .models import DocExtractedName
        from .parsers import DOC_NAME_FIELDS
        with db() as s:
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

    @app.post("/api/doc/extract-software")
    def api_doc_extract_software(fields: str = ""):
        from .models import DocExtractedSoftware
        from .parsers import DOC_SOFTWARE_FIELDS, extract_doc_software
        with db() as s:
            s.query(DocExtractedSoftware).delete()
            s.commit()
            field_set = {f.strip() for f in fields.split(",") if f.strip()}
            if not field_set:
                field_set = DOC_SOFTWARE_FIELDS
            count = extract_doc_software(s, field_set)
        return {"ok": True, "count": count}

    @app.get("/api/doc/software")
    def api_doc_software(field: str = ""):
        from .models import DocExtractedSoftware
        from .parsers import DOC_SOFTWARE_FIELDS
        with db() as s:
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

    @app.get("/api/doc/{doc_id}/text")
    def api_doc_text(doc_id: int):
        with db() as s:
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
            path = ws.uploads_dir / path
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

    @app.post("/api/doc/delete")
    def api_doc_delete(doc_id: int = Form(...)):
        file_to_delete: Path | None = None
        with db() as s:
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

    @app.post("/api/doc/extract-names")
    def api_doc_extract_names(fields: str = Form("")):
        from .parsers import DOC_NAME_FIELDS, extract_doc_names
        target = set(f.strip() for f in fields.split(",") if f.strip()) if fields else None
        with db() as s:
            count = extract_doc_names(s, target)
        return {"ok": True, "count": count}

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

    # Profiling page
    @app.get("/profiling", response_class=HTMLResponse)
    def profiling_page(request: Request):
        return templates.TemplateResponse("profiling.html", {"request": request})

    @app.get("/api/profiling")
    def api_profiling_list():
        with db() as s:
            rows = (
                s.execute(select(ProfilingRow).order_by(ProfilingRow.order_index))
                .scalars()
                .all()
            )
        return [
            {
                "id": r.id,
                "category": r.category,
                "description": r.description,
                "comments": r.comments,
                "order_index": r.order_index,
            }
            for r in rows
        ]

    @app.post("/api/profiling")
    def api_profiling_create(
        category: str = Form(""),
        description: str = Form(""),
        comments: str = Form(""),
        order_index: int = Form(0),
    ):
        with db() as s:
            row = ProfilingRow(
                category=category,
                description=description,
                comments=comments,
                order_index=order_index,
            )
            s.add(row)
            s.commit()
            row_id = row.id
        return {"ok": True, "id": row_id}

    @app.post("/api/profiling/update")
    def api_profiling_update(
        id: int = Form(...),
        category: str = Form(""),
        description: str = Form(""),
        comments: str = Form(""),
        order_index: int = Form(0),
    ):
        with db() as s:
            row = s.scalar(select(ProfilingRow).where(ProfilingRow.id == id))
            if not row:
                return JSONResponse({"ok": False}, status_code=404)
            row.category = category
            row.description = description
            row.comments = comments
            row.order_index = order_index
            s.commit()
        return {"ok": True}

    @app.post("/api/profiling/delete")
    def api_profiling_delete(id: int = Form(...)):
        with db() as s:
            row = s.scalar(select(ProfilingRow).where(ProfilingRow.id == id))
            if not row:
                return JSONResponse({"ok": False}, status_code=404)
            s.delete(row)
            s.commit()
        return {"ok": True}

    @app.post("/api/profiling/reorder")
    def api_profiling_reorder(order_json: str = Form(...)):
        try:
            order = json.loads(order_json)
        except Exception:
            return JSONResponse({"ok": False}, status_code=400)
        with db() as s:
            for idx, row_id in enumerate(order):
                row = s.scalar(select(ProfilingRow).where(ProfilingRow.id == row_id))
                if row:
                    row.order_index = idx
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
            qs = request.query_params.get("hide_completed", "")
            if qs:
                hide_completed = int(qs)
            else:
                row = s.scalar(select(AppSettings).where(AppSettings.key == "services_hide_completed"))
                hide_completed = int(row.value) if row else 0
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)

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

                if hide_completed and host.complete:
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
                        "host_outputs": {},
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

                host_label = host.hostname or host.ip
                if host_label not in service_map[key]["host_outputs"]:
                    service_map[key]["host_outputs"][host_label] = {
                        "host": {"id": host.id, "ip": host.ip, "hostname": host.hostname or ""},
                        "outputs": set(),
                    }

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
                        cleaned = cleaned.replace(host.ip, "<IP>")
                        if host.hostname:
                            cleaned = cleaned.replace(host.hostname, "<HOST>")
                        service_map[key]["host_outputs"][host_label]["outputs"].add(cleaned[:800])

            rows = []
            for key, data in service_map.items():
                output_rows = []
                for label, ho in data["host_outputs"].items():
                    if ho["outputs"]:
                        output_rows.append({
                            "host": ho["host"],
                            "outputs": list(ho["outputs"]),
                        })
                if data["hosts"]:
                    rows.append(
                        {
                            "port": data["port"],
                            "proto": data["proto"],
                            "service_types": list(data["service_types"]),
                            "products": list(data["products"]),
                            "host_count": len(data["hosts"]),
                            "hosts": data["hosts"],
                            "outputs": [],
                            "host_outputs": output_rows,
                        }
                    )

            rows.sort(key=lambda x: (x["port"], x["proto"]))

        return templates.TemplateResponse(
             "services.html", {"request": request, "rows": rows, "hide_completed": hide_completed}
         )

    @app.get("/profiling", response_class=HTMLResponse)
    def profiling_page(request: Request):
        return templates.TemplateResponse(
            "profiling.html", {"request": request}
        )

    @app.get("/api/graph")
    def api_graph(only_in_scope: bool = Query(False)):
        nodes, edges = [], []
        with db() as s:
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            s_ips, s_subnets, s_domains, _, s_domain_all_subs, s_domain_subs_if_ip, s_excluded = (
                scope_sets(s, sensitive_only=True)
            )
            subs = s.execute(select(Subdomain)).scalars().all()
            hosts = s.execute(select(Host)).scalars().all()
            svcs = s.execute(select(Service)).scalars().all()
            host_domains = list_all_host_domains(s)
            subdomain_ips = list_all_subdomain_ips(s)

        def nid(prefix: str, key: str) -> str:
            return f"{prefix}:{key}"

        def add_node(n: dict):
            if only_in_scope and not n.get("in_scope", False):
                return
            nodes.append(n)

        host_dict = {h.id: h for h in hosts}

        domain_nodes = {}
        for sub in subs:
            rd = (sub.root_domain or "").strip(".").lower()
            fq = sub.fqdn
            sub_ips = subdomain_ips.get(fq, [])
            sub_in = domain_in_scope(
                fq, domains, domain_all_subs, domain_subs_if_ip, sub_ips, ips, subnets, excluded
            )
            dom_in = (
                domain_in_scope(
                    rd,
                    domains,
                    domain_all_subs,
                    domain_subs_if_ip,
                    sub_ips,
                    ips,
                    subnets,
                    excluded,
                )
                if rd
                else False
            )
            sub_sensitive = domain_in_scope(
                fq,
                s_domains,
                s_domain_all_subs,
                s_domain_subs_if_ip,
                sub_ips,
                s_ips,
                s_subnets,
                s_excluded,
            )
            dom_sensitive = (
                domain_in_scope(
                    rd,
                    s_domains,
                    s_domain_all_subs,
                    s_domain_subs_if_ip,
                    sub_ips,
                    s_ips,
                    s_subnets,
                    s_excluded,
                )
                if rd
                else False
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
        host_scope_sensitive = {}
        for h in hosts:
            hid = nid("host", h.ip)
            host_ids[h.id] = hid
            hin = ip_in_scope(h.ip, ips, subnets, excluded)
            hs = ip_in_scope(h.ip, s_ips, s_subnets, s_excluded)
            host_scope[h.id] = hin
            host_scope_sensitive[h.id] = hs
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
            hs = host_scope_sensitive.get(svc.host_id, False)
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
                    fqdn_ips = subdomain_ips.get(fqdn, [])
                    sub_in = domain_in_scope(
                        fqdn,
                        domains,
                        domain_all_subs,
                        domain_subs_if_ip,
                        fqdn_ips,
                        ips,
                        subnets,
                        excluded,
                    )
                    sub_sensitive = domain_in_scope(
                        fqdn,
                        s_domains,
                        s_domain_all_subs,
                        s_domain_subs_if_ip,
                        fqdn_ips,
                        s_ips,
                        s_subnets,
                        s_excluded,
                    )
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
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            rows = s.execute(select(Subdomain)).scalars().all()
            all_sub_ips = list_all_subdomain_ips(s)
            out = []
            for x in rows:
                ips_found = all_sub_ips.get(x.fqdn, [])
                in_dom = domain_in_scope(
                    x.fqdn,
                    domains,
                    domain_all_subs,
                    domain_subs_if_ip,
                    ips_found,
                    ips,
                    subnets,
                    excluded,
                )
                in_ip = any(ip_in_scope(ip, ips, subnets, excluded) for ip in ips_found)
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

    @app.post("/api/subdomain/scope-override")
    def api_subdomain_scope_override(fqdn: str = Form(...)):
        fq = fqdn.strip().lower().rstrip(".")
        if not fq:
            return JSONResponse({"ok": False, "error": "Invalid FQDN"}, status_code=400)
        with db() as s:
            existing = s.scalar(select(ScopeExclusion).where(ScopeExclusion.fqdn == fq))
            if existing:
                s.delete(existing)
            else:
                s.add(ScopeExclusion(fqdn=fq))
            s.commit()
        return {"ok": True}

    @app.post("/api/host/complete")
    def api_host_complete(host_id: int = Form(...), complete: int = Form(...)):
        with db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.complete = 1 if int(complete) == 1 else 0
            if h.complete == 1:
                h.inprogress = 0
            s.commit()
        return {"ok": True}

    @app.post("/api/host/inprogress")
    def api_host_inprogress(host_id: int = Form(...), inprogress: int = Form(...)):
        with db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.inprogress = 1 if int(inprogress) == 1 else 0
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

    @app.post("/api/settings")
    def api_settings_set(key: str = Form(...), value: str = Form("")):
        with db() as s:
            row = s.scalar(select(AppSettings).where(AppSettings.key == key))
            if row:
                row.value = value
            else:
                s.add(AppSettings(key=key, value=value))
            s.commit()
        return {"ok": True}

    @app.post("/api/host/tag")
    def api_host_tag(asset_id: int = Form(...), tag: str = Form("")):
        with db() as s:
            h = s.scalar(select(Host).where(Host.id == asset_id))
            if not h:
                return JSONResponse({"ok": False}, status_code=404)
            h.tag = tag
            s.commit()
        return {"ok": True}

    @app.post("/api/host/delete")
    def api_host_delete(host_id: int = Form(...)):
        with db() as s:
            h = s.scalar(select(Host).where(Host.id == host_id))
            if not h:
                return JSONResponse({"ok": False, "error": "Host not found"}, status_code=404)
            s.delete(h)
            s.commit()
        return {"ok": True}

    # Users & Credentials
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

    @app.get("/password-spray", response_class=HTMLResponse)
    def password_spray_page(request: Request):
        with db() as s:
            services = (
                s.execute(
                    select(PasswordSprayService).order_by(PasswordSprayService.name.asc())
                )
                .scalars()
                .all()
            )
            service_rows = []
            for svc in services:
                attempts = (
                    s.execute(
                        select(PasswordSprayAttempt)
                        .where(PasswordSprayAttempt.service_id == svc.id)
                        .order_by(PasswordSprayAttempt.created_at.asc())
                    )
                    .scalars()
                    .all()
                )
                service_rows.append(
                    {
                        "id": svc.id,
                        "name": svc.name,
                        "attempts": attempts,
                    }
                )
        return templates.TemplateResponse(
            "password_spray.html", {"request": request, "services": service_rows}
        )

    @app.post("/api/password-spray/service")
    def api_password_spray_service_create(name: str = Form("")):
        name = (name or "").strip()
        if not name:
            return JSONResponse({"ok": False, "error": "Service name is required"}, status_code=400)
        with db() as s:
            existing = s.scalar(select(PasswordSprayService).where(PasswordSprayService.name == name))
            if existing:
                return {"ok": True, "id": existing.id, "name": existing.name}
            svc = PasswordSprayService(name=name[:255])
            s.add(svc)
            s.commit()
            s.refresh(svc)
            return {"ok": True, "id": svc.id, "name": svc.name}

    @app.post("/api/password-spray/attempt")
    def api_password_spray_attempt_create(
        service_id: int = Form(...),
        password: str = Form(""),
        attempted_at: str = Form(""),
        notes: str = Form(""),
    ):
        pwd = (password or "").strip()
        at = (attempted_at or "").strip()
        note = (notes or "").strip()
        if not pwd and not at and not note:
            return JSONResponse({"ok": False, "error": "No attempt data provided"}, status_code=400)
        with db() as s:
            svc = s.scalar(select(PasswordSprayService).where(PasswordSprayService.id == int(service_id)))
            if not svc:
                return JSONResponse({"ok": False, "error": "Service not found"}, status_code=404)
            row = PasswordSprayAttempt(
                service_id=svc.id,
                password=pwd[:255],
                attempted_at=at[:64],
                notes=note,
            )
            s.add(row)
            s.commit()
            s.refresh(row)
            return {
                "ok": True,
                "id": row.id,
                "service_id": svc.id,
                "password": row.password,
                "attempted_at": row.attempted_at,
                "notes": row.notes,
            }

    @app.post("/api/password-spray/attempt/{attempt_id}")
    def api_password_spray_attempt_update(
        attempt_id: int,
        password: str = Form(""),
        attempted_at: str = Form(""),
        notes: str = Form(""),
    ):
        pwd = (password or "").strip()
        at = (attempted_at or "").strip()
        note = (notes or "").strip()
        with db() as s:
            row = s.scalar(
                select(PasswordSprayAttempt).where(PasswordSprayAttempt.id == attempt_id)
            )
            if not row:
                return JSONResponse(
                    {"ok": False, "error": "Attempt not found"}, status_code=404
                )
            row.password = pwd[:255]
            row.attempted_at = at[:64]
            row.notes = note
            s.commit()
            return {
                "ok": True,
                "id": row.id,
                "password": row.password,
                "attempted_at": row.attempted_at,
                "notes": row.notes,
            }

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

    @app.post("/api/creds/update")
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
        with db() as s:
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

    @app.post("/api/creds/delete")
    def api_cred_delete(cred_id: int = Form(...)):
        with db() as s:
            cred = s.scalar(select(Credential).where(Credential.id == cred_id))
            if not cred:
                return JSONResponse({"ok": False, "error": "Credential not found"}, status_code=404)
            s.delete(cred)
            s.commit()
        return {"ok": True}

    @app.get("/users", response_class=HTMLResponse)
    def users_page(request: Request):
        with db() as s:
            names = (
                s.execute(
                    select(NameItem).order_by(NameItem.last_name.asc(), NameItem.first_name.asc())
                )
                .scalars()
                .all()
            )
        compromised_ids = _topology_compromised_ids()
        compromised_name_ids = compromised_ids.get("name_ids", set()) if compromised_ids else set()
        return templates.TemplateResponse(
            "users.html", {"request": request, "names": names, "compromised_name_ids": compromised_name_ids}
            )

    @app.get("/api/names/list")
    def api_names_list():
        with db() as s:
            names = list(
                s.execute(
                    select(NameItem).order_by(NameItem.last_name.asc(), NameItem.first_name.asc())
                )
                .scalars()
                .all()
            )
        compromised_ids = _topology_compromised_ids()
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

    @app.post("/api/names/create")
    def api_name_create(
        first_name: str = Form(""),
        middle_name: str = Form(""),
        last_name: str = Form(""),
        email: str = Form(""),
        phone: str = Form(""),
        ad_username: str = Form(""),
        domain: str = Form(""),
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
        with db() as s:
            s.add(
                NameItem(
                    first_name=first_name.strip(),
                    middle_name=middle_name.strip(),
                    last_name=last_name.strip(),
                    email=email.strip(),
                    phone=phone.strip(),
                    ad_username=ad_username.strip(),
                    domain=domain.strip(),
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

    @app.post("/api/names/update")
    def api_name_update(
        name_id: int = Form(...),
        first_name: str = Form(""),
        middle_name: str = Form(""),
        last_name: str = Form(""),
        email: str = Form(""),
        phone: str = Form(""),
        ad_username: str = Form(""),
        domain: str = Form(""),
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
        with db() as s:
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

    @app.post("/api/names/update-domain")
    def api_name_update_domain(name_id: int = Form(...), domain: str = Form("")):
        with db() as s:
            name = s.scalar(select(NameItem).where(NameItem.id == name_id))
            if not name:
                return JSONResponse({"ok": False, "error": "Name not found"}, status_code=404)
            name.domain = domain.strip()
            s.commit()
        return {"ok": True}

    @app.post("/api/names/delete")
    def api_name_delete(name_id: int = Form(...)):
        with db() as s:
            name = s.scalar(select(NameItem).where(NameItem.id == name_id))
            if not name:
                return JSONResponse({"ok": False, "error": "Name not found"}, status_code=404)
            s.delete(name)
            s.commit()
        return {"ok": True}

    @app.get("/api/domain-correlations")
    def api_domain_correlations_get():
        from reconbubble.models import DomainCorrelation
        with db() as s:
            corrs = s.scalars(select(DomainCorrelation).order_by(DomainCorrelation.primary_domain)).all()
            result = {}
            for c in corrs:
                if c.primary_domain not in result:
                    result[c.primary_domain] = {"primary": c.primary_domain, "aliases": c.aliases.split(",") if c.aliases else []}
            return result

    @app.post("/api/domain-correlations/save")
    async def api_domain_correlations_save(request: Request):
        from reconbubble.models import DomainCorrelation
        data = await request.json()
        if not data:
            return JSONResponse({"ok": False, "error": "No data"}, status_code=400)
        with db() as s:
            s.execute(DomainCorrelation.__table__.delete())
            for primary, info in data.items():
                aliases = ",".join(info.get("aliases", []))
                s.add(DomainCorrelation(primary_domain=primary, aliases=aliases))
            s.commit()
        return {"ok": True}

    @app.get("/app-credentials/export/creds")
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
    @app.get("/urls")
    def urls_redirect(request: Request):
        from fastapi import Response as FResponse
        show_out = request.query_params.get("show_out", "0")
        target = f"/subdomains?show_out={show_out}"
        return FResponse(status_code=302, headers={"Location": target})

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
