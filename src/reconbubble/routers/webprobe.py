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

    # ---- Lightweight HTTP/HTTPS protocol probes ----
    def _web_probe_public_job(job: dict) -> dict:
        return {
            "id": job["id"],
            "status": job["status"],
            "total": job["total"],
            "completed": job["completed"],
            "current_label": job["current_label"],
            "results": job["results"],
            "error": job["error"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
            "finished_at": job["finished_at"].isoformat() if job.get("finished_at") else "",
        }

    def _get_active_web_probe_job() -> dict | None:
        job_id = app.state.active_web_probe_job_id
        job = app.state.web_probe_jobs.get(job_id) if job_id else None
        if job and job["status"] in ("pending", "running"):
            return job
        return None

    def _prune_web_probe_jobs() -> None:
        now = datetime.utcnow()
        for job_id in list(app.state.web_probe_jobs):
            job = app.state.web_probe_jobs.get(job_id)
            if not job or job["status"] in ("pending", "running"):
                continue
            finished_at = job.get("finished_at")
            if not finished_at:
                continue
            if (now - finished_at).total_seconds() > 1800:
                app.state.web_probe_jobs.pop(job_id, None)

    def _is_ip_like(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except Exception:
            return False

    def _probe_http_status_once(
        addr: str, port: int, host_header: str, use_tls: bool, timeout: float = 5.0
    ) -> tuple[int, str]:
        try:
            sock = netproxy.socks5_connect(addr, port, timeout=timeout)
        except socket.timeout:
            return 0, "timeout"
        except OSError:
            return 0, "proxy-error" if netproxy.proxy_settings() else "connect-error"
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                server_hostname = None if _is_ip_like(host_header) else host_header
                try:
                    sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
                except ssl.SSLError:
                    return 0, "tls-error"
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                "User-Agent: ReconBubble/1.0\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("utf-8", "replace")
            sock.sendall(request)
            data = b""
            while b"\r\n\r\n" not in data and b"\n\n" not in data and len(data) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            status = 0
            for line in data.replace(b"\r\n", b"\n").split(b"\n"):
                m = re.match(rb"HTTP/1\.[01]\s+(\d{3})", line)
                if m:
                    status = int(m.group(1))
            if status:
                return status, ""
            return 0, "no-http-response"
        except socket.timeout:
            return 0, "timeout"
        except ssl.SSLError:
            return 0, "tls-error"
        except OSError:
            return 0, "socket-error"
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _probe_web_target_blocking(target: dict) -> dict:
        fqdn = target["fqdn"]
        port = int(target["port"])
        target_ip = target.get("target_ip", "") or ""
        host_header = target.get("host") or fqdn
        addr = target_ip or fqdn
        https_status, https_error = _probe_http_status_once(
            addr, port, host_header, True
        )
        http_status, http_error = _probe_http_status_once(
            addr, port, host_header, False
        )
        if https_status and http_status:
            scheme = "both"
        elif https_status:
            scheme = "https"
        elif http_status:
            scheme = "http"
        else:
            scheme = "none"
        error_parts = []
        if not https_status:
            error_parts.append(f"https:{https_error or 'no-response'}")
        if not http_status:
            error_parts.append(f"http:{http_error or 'no-response'}")
        error = "; ".join(error_parts)[:500]
        return {
            "fqdn": fqdn,
            "port": port,
            "target_ip": target_ip,
            "host": host_header,
            "scheme": scheme,
            "http_status": http_status,
            "https_status": https_status,
            "error": error,
        }

    def _save_web_probe_result(result: dict) -> None:
        with st.SessionLocal() as s:
            row = (
                s.execute(
                    select(WebProtocolProbe).where(
                        WebProtocolProbe.fqdn == result["fqdn"],
                        WebProtocolProbe.port == result["port"],
                        WebProtocolProbe.target_ip == result.get("target_ip", ""),
                    )
                )
                .scalars()
                .first()
            )
            now = datetime.utcnow()
            if row:
                row.scheme = result["scheme"]
                row.http_status = result["http_status"]
                row.https_status = result["https_status"]
                row.error = result["error"]
                row.created_at = now
            else:
                s.add(
                    WebProtocolProbe(
                        fqdn=result["fqdn"],
                        port=result["port"],
                        target_ip=result.get("target_ip", ""),
                        scheme=result["scheme"],
                        http_status=result["http_status"],
                        https_status=result["https_status"],
                        error=result["error"],
                        created_at=now,
                    )
                )
            s.commit()

    def _list_web_probe_targets(s: Session) -> list[dict]:
        ips, subnets, _, _, _, _, excluded = scope_sets(s)
        rows = (
            s.execute(
                select(Subdomain).order_by(
                    Subdomain.root_domain.asc(), Subdomain.fqdn.asc()
                )
            )
            .scalars()
            .all()
        )
        all_ips_map = list_all_subdomain_ips(s)
        web_ports_by_ip = get_open_web_ports_by_ip(s)
        targets: list[dict] = []
        seen: set[tuple[str, int, str]] = set()

        def add_target(fqdn: str, ip: str, port: int) -> None:
            fqdn = (fqdn or "").strip().lower().rstrip(".")
            ip = (ip or "").strip()
            try:
                port = int(port)
            except (TypeError, ValueError):
                return
            if not fqdn or not ip or not port:
                return
            key = (fqdn, port, ip)
            if key in seen:
                return
            seen.add(key)
            targets.append(
                {"fqdn": fqdn, "port": port, "target_ip": ip, "host": fqdn}
            )

        for row in rows:
            resolved = all_ips_map.get(row.fqdn, [])
            prowl = [
                ip.strip()
                for ip in (row.prowl_ips or "").split(",")
                if ip.strip()
            ]
            for ip in list(set(resolved) | set(prowl)):
                if not ip_in_scope(ip, ips, subnets, excluded):
                    continue
                for port in web_ports_by_ip.get(ip, []):
                    add_target(row.fqdn, ip, port)

        for ip, ports in web_ports_by_ip.items():
            if not ip_in_scope(ip, ips, subnets, excluded):
                continue
            for port in ports:
                add_target(ip, ip, port)

        return targets

    def _export_probe_ips_for_host(host: str, provided_ips: list[str]) -> list[str]:
        host = (host or "").strip().lower().rstrip(".")
        cleaned = list(
            dict.fromkeys(
                (ip or "").strip() for ip in (provided_ips or []) if (ip or "").strip()
            )
        )
        if not host:
            return []
        if _is_ip_like(host):
            return cleaned or [host]
        return cleaned or [""]

    def _load_web_probe_map(s: Session) -> dict[tuple[str, int], list[dict]]:
        rows = s.execute(select(WebProtocolProbe)).scalars().all()
        probes: dict[tuple[str, int], list[dict]] = {}
        for row in rows:
            host = (row.fqdn or "").strip().lower().rstrip(".")
            try:
                port = int(row.port)
            except (TypeError, ValueError):
                continue
            if not host or not port:
                continue
            probes.setdefault((host, port), []).append(
                {
                    "scheme": row.scheme or "none",
                    "http_status": row.http_status or 0,
                    "https_status": row.https_status or 0,
                    "error": row.error or "",
                    "target_ip": row.target_ip or "",
                }
            )
        return probes

    def _export_scheme_from_probe_results(results: list[dict]) -> str:
        if any(
            r.get("https_status") or r.get("scheme") in {"https", "both"}
            for r in results
        ):
            return "https"
        if any(r.get("http_status") or r.get("scheme") == "http" for r in results):
            return "http"
        return ""

    def _export_scheme_for_bare_host(
        host: str, probes: dict[tuple[str, int], list[dict]]
    ) -> str:
        if any(
            r.get("https_status") or r.get("scheme") in {"https", "both"}
            for r in probes.get((host, 443), [])
        ):
            return "https"
        if any(
            r.get("http_status") or r.get("scheme") in {"http", "both"}
            for r in probes.get((host, 80), [])
        ):
            return "http"
        return ""

    def _collect_export_probe_tasks(
        s: Session, entries: dict[tuple[str, int | None], set[str]]
    ) -> tuple[
        list[tuple[str, str, int]],
        list[tuple[str, str, int, bool, str]],
        dict[tuple[str, int], list[dict]],
    ]:
        probes = _load_web_probe_map(s)
        existing = {
            (host, port, item["target_ip"])
            for (host, port), items in probes.items()
            for item in items
        }
        explicit_tasks: list[tuple[str, str, int]] = []
        default_tasks: list[tuple[str, str, int, bool, str]] = []
        planned: set[tuple[str, int, str]] = set()
        for (host, port), provided_ips in entries.items():
            if port is None:
                continue
            probe_port = int(port)
            for ip in _export_probe_ips_for_host(host, list(provided_ips)):
                key = (host, probe_port, ip)
                if key not in existing and key not in planned:
                    explicit_tasks.append((host, ip, probe_port))
                    planned.add(key)
        for (host, port), provided_ips in entries.items():
            if port is not None:
                continue
            for probe_port, use_tls, scheme_name in ((443, True, "https"), (80, False, "http")):
                for ip in _export_probe_ips_for_host(host, list(provided_ips)):
                    key = (host, probe_port, ip)
                    if key not in existing and key not in planned:
                        default_tasks.append((host, ip, probe_port, use_tls, scheme_name))
                        planned.add(key)
        return explicit_tasks, default_tasks, probes

    def _run_export_probe_tasks(
        explicit_tasks: list[tuple[str, str, int]],
        default_tasks: list[tuple[str, str, int, bool, str]],
    ) -> None:
        if not explicit_tasks and not default_tasks:
            return

        def run_explicit(task: tuple[str, str, int]) -> None:
            host, ip, port = task
            try:
                result = _probe_web_target_blocking(
                    {"fqdn": host, "port": port, "target_ip": ip, "host": host}
                )
                _save_web_probe_result(result)
            except Exception:
                pass

        def run_default(task: tuple[str, str, int, bool, str]) -> None:
            host, ip, port, use_tls, scheme_name = task
            try:
                status, error = _probe_http_status_once(ip or host, port, host, use_tls)
                if status:
                    scheme = scheme_name
                    http_status = status if scheme_name == "http" else 0
                    https_status = status if scheme_name == "https" else 0
                    error_text = ""
                else:
                    scheme = "none"
                    http_status = 0
                    https_status = 0
                    error_text = f"{scheme_name}:{error or 'no-response'}"
                _save_web_probe_result(
                    {
                        "fqdn": host,
                        "port": port,
                        "target_ip": ip,
                        "scheme": scheme,
                        "http_status": http_status,
                        "https_status": https_status,
                        "error": error_text[:500],
                    }
                )
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(run_explicit, task) for task in explicit_tasks]
            futures.extend(executor.submit(run_default, task) for task in default_tasks)
            for future in as_completed(futures):
                future.result()

    def _export_url_for_scheme(host: str, port: int | None, scheme: str) -> str | None:
        if not host or not scheme:
            return None
        host_part = f"[{host}]" if _is_ip_like(host) and ":" in host else host
        if port is None:
            return f"{scheme}://{host_part}"
        if scheme == "https" and int(port) == 443:
            return f"https://{host_part}"
        if scheme == "http" and int(port) == 80:
            return f"http://{host_part}"
        return f"{scheme}://{host_part}:{int(port)}"

    async def _run_web_probe_job(job_id: str) -> None:
        job = app.state.web_probe_jobs.get(job_id)
        if not job:
            return
        try:
            job["status"] = "running"
            job["updated_at"] = datetime.utcnow().isoformat()
            targets = job.get("targets") or []
            job["total"] = len(targets)
            job["updated_at"] = datetime.utcnow().isoformat()

            semaphore = asyncio.Semaphore(10)

            async def process_target(target: dict) -> None:
                async with semaphore:
                    job["current_label"] = (
                        f"{target['fqdn']}:{target['port']} → {target.get('target_ip') or 'dns'}"
                    )
                    job["updated_at"] = datetime.utcnow().isoformat()
                    result = await asyncio.to_thread(_probe_web_target_blocking, target)
                    job["completed"] += 1
                    job["results"].append(result)
                    job["updated_at"] = datetime.utcnow().isoformat()
                    try:
                        _save_web_probe_result(result)
                    except Exception:
                        pass

            for i in range(0, len(targets), 50):
                await asyncio.gather(
                    *(process_target(t) for t in targets[i : i + 50])
                )

            job["status"] = "completed"
            job["error"] = ""
        except Exception as e:
            job["status"] = "failed"
            job["error"] = str(e)[:500]
        finally:
            job["finished_at"] = datetime.utcnow()
            job["updated_at"] = datetime.utcnow().isoformat()
            if app.state.active_web_probe_job_id == job_id:
                app.state.active_web_probe_job_id = None

    @router.post("/api/web-probe/jobs")
    async def api_web_probe_create_job():
        _prune_web_probe_jobs()
        async with app.state.web_probe_lock:
            active = _get_active_web_probe_job()
            if active:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": "Web protocol probe already running",
                        "active_job": _web_probe_public_job(active),
                    },
                    status_code=409,
                )
            with st.SessionLocal() as s:
                targets = _list_web_probe_targets(s)
            job_id = uuid.uuid4().hex
            now = datetime.utcnow()
            if not targets:
                job = {
                    "id": job_id,
                    "targets": [],
                    "status": "completed",
                    "total": 0,
                    "completed": 0,
                    "current_label": "No in-scope web ports found",
                    "results": [],
                    "error": "",
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                    "finished_at": now,
                }
                app.state.web_probe_jobs[job_id] = job
                return {
                    "ok": True,
                    "job": _web_probe_public_job(job),
                    "message": "No in-scope web ports found",
                }
            job = {
                "id": job_id,
                "targets": targets,
                "status": "pending",
                "total": len(targets),
                "completed": 0,
                "current_label": "Starting...",
                "results": [],
                "error": "",
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
                "finished_at": None,
            }
            app.state.web_probe_jobs[job_id] = job
            app.state.active_web_probe_job_id = job_id
        asyncio.create_task(_run_web_probe_job(job_id))
        return {"ok": True, "job": _web_probe_public_job(job)}

    @router.get("/api/web-probe/jobs/active")
    def api_web_probe_jobs_active():
        _prune_web_probe_jobs()
        current = _get_active_web_probe_job()
        last = None
        for job in app.state.web_probe_jobs.values():
            if job["status"] in ("pending", "running"):
                continue
            finished_at = job.get("finished_at")
            if not finished_at:
                continue
            if last is None or finished_at > last.get("finished_at"):
                last = job
        return {
            "ok": True,
            "active_job": _web_probe_public_job(current) if current else None,
            "last_job": _web_probe_public_job(last) if last else None,
        }

    @router.get("/api/web-probe/jobs/{job_id}")
    def api_web_probe_job_status(job_id: str):
        job = app.state.web_probe_jobs.get(job_id)
        if not job:
            return JSONResponse({"ok": False, "error": "Job not found"}, status_code=404)
        return {"ok": True, "job": _web_probe_public_job(job)}

    st._load_web_probe_map = _load_web_probe_map
    st._export_scheme_from_probe_results = _export_scheme_from_probe_results
    st._export_scheme_for_bare_host = _export_scheme_for_bare_host
    st._collect_export_probe_tasks = _collect_export_probe_tasks
    st._run_export_probe_tasks = _run_export_probe_tasks
    st._export_url_for_scheme = _export_url_for_scheme
    return router
