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

_WEB_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888})
# Ports commonly serving HTTP(S) -- the default vhost-bruteforce socket set.
_VHOST_SOCKET_PORTS = frozenset(
    {
        80, 443, 3000, 3001, 4000, 4443, 5000, 5001, 5080, 6443,
        7000, 7001, 7443, 8000, 8001, 8002, 8008, 8009, 8010, 8025,
        8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
        8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
        8118, 8180, 8181, 8222, 8443, 8500, 8880, 8888, 8899, 9000,
        9001, 9080, 9090, 9091, 9200, 9443, 9999, 10000, 10443, 15672,
        18080, 20080,
    }
)
_WEB_SERVICE_NAME_RE = re.compile(r"(?i)(?:^|[^a-z])https?(?=$|[^a-z])")
_WEB_PRODUCT_RE = re.compile(
    r"(?i)(?:apache|httpd|net/http|waitress|gunicorn|werkzeug|nginx|caddy|envoy|\biis\b)"
)
_HTTP_STATUS_RE = re.compile(
    r"(?im)^\s*[\"']?\s*HTTP/(?:1\\?\.[01]|2)\b(?:\\x20|%20|\s)+[1-5]\d{2}\b"
)
_HTTP_HTML_RE = re.compile(r"(?i)<(!doctype\s+)?html\b")
_HTTP_CONTENT_TYPE_RE = re.compile(r"(?im)^\s*content-type\s*:")
_HTTP_HEADER_RE = re.compile(
    r"(?im)^\s*(?:server|content-length|connection|access-control-allow-origin)\s*:"
)

def _hostname_as_domain(value: str) -> str:
    return hostname_as_domain(value)

def _web_url_host_from_domain(value: str) -> str:
    host = (value or "").strip().lower().strip(".")
    if host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host

def _like_escape(value: str) -> str:
    return (value or "").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

def _web_url_host_from_url(value: str) -> str:
    try:
        host = (urlsplit(value or "").hostname or "").strip().lower().strip(".")
    except Exception:
        host = ""
    if not host:
        try:
            host = (urlsplit("http://" + (value or "")).hostname or "").strip().lower().strip(".")
        except Exception:
            host = ""
    return host

def _smb_user_label(name: NameItem) -> str:
    full = " ".join(
        part.strip()
        for part in (name.first_name, name.middle_name, name.last_name)
        if part and part.strip()
    ).strip()
    return (name.ad_username or full or name.email or f"user {name.id}").strip()

def load_scope_exclusions(s: Session) -> set[str]:
    rows = s.execute(select(ScopeExclusion)).scalars().all()
    return {r.fqdn.strip().lower().strip(".") for r in rows if r.fqdn.strip()}

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

def list_hosts_by_ip(s: Session, ip: str) -> list[dict]:
    rows = s.execute(
        select(Host).where(Host.ip == ip).order_by(Host.id.asc())
    ).scalars().all()
    return [{"id": h.id, "ip": h.ip, "hostname": h.hostname or ""} for h in rows]

def get_open_web_ports_by_ip(
    s: Session, ips: set[str] | list[str] | None = None
) -> dict[str, list[int]]:
    if ips is not None and not ips:
        return {}
    evidence_service_ids = (
        select(ServiceEvidence.service_id)
        .where(
            or_(
                ServiceEvidence.raw_output.ilike("%HTTP/1%"),
                ServiceEvidence.raw_output.ilike("%HTTP/2%"),
                ServiceEvidence.raw_output.ilike("%<html%"),
                ServiceEvidence.raw_output.ilike("%<!doctype%"),
                ServiceEvidence.raw_output.ilike("%Content-Type:%"),
                ServiceEvidence.raw_output.ilike("%Server:%"),
            )
        )
        .scalar_subquery()
    )
    query = (
        select(Host.ip, Service)
        .join(Host)
        .where(
            Service.state == "open",
            or_(
                Service.port.in_(list(_WEB_PORTS)),
                Service.service_name.ilike("%http%"),
                Service.product.ilike("%http%"),
                Service.id.in_(evidence_service_ids),
            ),
        )
    )
    if ips is not None:
        query = query.where(Host.ip.in_(list(ips)))
    result: dict[str, list[int]] = {}
    for ip, svc in s.execute(query).all():
        if (
            svc.port in _WEB_PORTS
            or _WEB_SERVICE_NAME_RE.search(svc.service_name or "")
            or _WEB_PRODUCT_RE.search(svc.product or "")
        ):
            result.setdefault(ip, []).append(svc.port)
            continue
        raw_outputs = s.execute(
            select(ServiceEvidence.raw_output).where(
                ServiceEvidence.service_id == svc.id
            )
        ).scalars().all()
        for raw in raw_outputs:
            normalized = html_lib.unescape(raw or "")
            normalized = normalized.replace("\\x20", " ").replace("%20", " ")
            normalized = normalized.replace("\\r", "\r").replace("\\n", "\n")
            if (
                _HTTP_STATUS_RE.search(normalized)
                or _HTTP_HTML_RE.search(normalized)
                or (
                    _HTTP_CONTENT_TYPE_RE.search(normalized)
                    and _HTTP_HEADER_RE.search(normalized)
                )
            ):
                result.setdefault(ip, []).append(svc.port)
                break
    return {ip: sorted(set(ports)) for ip, ports in result.items()}

def link_host_domain(s: Session, host_id: int, fqdn: str, commit: bool = True) -> None:
    fqdn = fqdn.strip().lower().rstrip(".")
    if not fqdn or not DOMAIN_RE.match(fqdn):
        return
    sub = s.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))
    if not sub:
        sub = Subdomain(fqdn=fqdn, root_domain=".".join(fqdn.split(".")[-2:]))
        s.add(sub)
        s.flush()
        s.refresh(sub)
    s.execute(
        text(
            "INSERT OR IGNORE INTO host_subdomains(host_id, subdomain_id, created_at) "
            "VALUES (:hid, :sid, :ts)"
        ),
        {"hid": host_id, "sid": sub.id, "ts": datetime.utcnow().isoformat()},
    )
    if commit:
        s.commit()
    else:
        s.flush()

