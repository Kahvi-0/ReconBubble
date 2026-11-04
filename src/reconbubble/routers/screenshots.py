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

    def _screenshot_browser_path() -> Path:
        env_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
        if env_path:
            return Path(env_path).expanduser().resolve()
        return st.ws.browser_dir

    def _screenshot_browser_mode() -> str:
        if os.environ.get("RECONBUBBLE_CHROMIUM_EXECUTABLE", "").strip():
            return "system-browser"
        marker = os.environ.get("RECONBUBBLE_BROWSER_MODE", "").strip()
        if marker in {"workspace", "custom", "ephemeral"}:
            return marker
        browser_path = _screenshot_browser_path()
        if browser_path == st.ws.browser_dir:
            return "workspace"
        browser_path_str = str(browser_path)
        tempdir_str = tempfile.gettempdir()
        if (
            browser_path_str.startswith(tempdir_str)
            or "/dev/shm/" in browser_path_str
            or browser_path_str.startswith("/dev/shm/")
        ):
            return "ephemeral"
        return "custom"

    def _screenshot_browser_install_command(with_deps: bool = False) -> str:
        parts = [sys.executable, "-m", "playwright", "install", "chromium"]
        if with_deps:
            parts.append("--with-deps")
        prefix = ""
        browser_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
        if browser_path:
            prefix = f"PLAYWRIGHT_BROWSERS_PATH={browser_path} "
        return prefix + " ".join(parts)

    def _screenshot_browser_uv_install_command(port: int | None = None, with_deps: bool = False) -> str:
        if os.environ.get("RECONBUBBLE_CHROMIUM_EXECUTABLE", "").strip():
            return ""
        target = _screenshot_browser_path()
        mode = _screenshot_browser_mode()
        parts = [
            "uvx",
            "--from",
            "git+https://github.com/Kahvi-0/ReconBubble",
            "reconbubble",
            "--database",
            shlex.quote(str(st.ws.db_path)),
        ]
        if (st.project_name or "").strip():
            parts.extend(["--project", shlex.quote(st.project_name.strip())])
        if mode == "ephemeral":
            parts.append("run")
            parts.extend(["--port", str(port or 5000)])
            parts.append("--ephemeral-browser")
            parts.append("--install-browser")
            if with_deps:
                parts.append("--with-deps")
        elif mode == "custom":
            parts.extend(["install-browser", "--browser-dir", shlex.quote(str(target))])
            if with_deps:
                parts.append("--with-deps")
        else:
            parts.append("install-browser")
            if with_deps:
                parts.append("--with-deps")
        return " ".join(parts)

    def _screenshot_browser_options() -> dict:
        executable = os.environ.get("RECONBUBBLE_CHROMIUM_EXECUTABLE", "").strip()
        if not executable:
            return {}
        executable_path = Path(executable).expanduser().resolve()
        if not executable_path.exists():
            raise RuntimeError(
                f"RECONBUBBLE_CHROMIUM_EXECUTABLE is set but the executable was not found: {executable_path}"
            )
        return {"executable_path": str(executable_path)}

    def _screenshot_proxy_options() -> dict:
        settings = netproxy.proxy_settings()
        if not settings:
            return {}
        proxy = {"server": f"socks5://{settings['host']}:{settings['port']}"}
        if settings["username"]:
            proxy["username"] = settings["username"]
            proxy["password"] = settings["password"]
        return {"proxy": proxy}

    def _screenshot_browser_launch_error(exc: Exception, port: int | None = None) -> RuntimeError:
        message = str(exc)
        if "Executable doesn't exist" in message or "playwright install" in message:
            uv_command = _screenshot_browser_uv_install_command(port)
            install_command = _screenshot_browser_install_command()
            command_text = uv_command or install_command
            if uv_command and install_command:
                command_text = f"{uv_command}  (direct: {install_command})"
            return RuntimeError(
                "Playwright Chromium is not installed for this ReconBubble workspace. "
                f"Run: {command_text}. Original error: {message[:250]}"
            )
        return RuntimeError(f"Failed to start Playwright Chromium: {message[:500]}")

    async def _screenshot_browser_status(port: int | None = None) -> dict:
        executable_override = os.environ.get("RECONBUBBLE_CHROMIUM_EXECUTABLE", "").strip()
        if executable_override:
            executable_path = Path(executable_override).expanduser().resolve()
            exists = executable_path.exists()
            return {
                "ok": exists,
                "mode": "system-browser",
                "browser_path": "",
                "executable_path": str(executable_path),
                "exists": exists,
                "env_executable": executable_override,
                "proxy": netproxy.describe(),
                "install_command": "",
                "install_command_uv": "",
                "error": "" if exists else f"Executable not found: {executable_path}",
            }

        browser_path = _screenshot_browser_path()
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                executable_path = Path(p.chromium.executable_path)
            exists = executable_path.exists()
            return {
                "ok": exists,
                "mode": _screenshot_browser_mode(),
                "browser_path": str(browser_path),
                "executable_path": str(executable_path),
                "exists": exists,
                "env_executable": "",
                "proxy": netproxy.describe(),
                "install_command": _screenshot_browser_install_command() if not exists else "",
                "install_command_uv": _screenshot_browser_uv_install_command(port) if not exists else "",
                "error": "" if exists else "Playwright Chromium executable is missing.",
            }
        except Exception as e:
            return {
                "ok": False,
                "mode": _screenshot_browser_mode(),
                "browser_path": str(browser_path),
                "executable_path": "",
                "exists": False,
                "env_executable": "",
                "proxy": netproxy.describe(),
                "install_command": _screenshot_browser_install_command(),
                "install_command_uv": _screenshot_browser_uv_install_command(port),
                "error": str(e)[:500],
            }

    def _clean_screenshot_targets(targets: list) -> list[dict]:
        clean_targets: list[dict] = []
        seen_targets = set()
        for target in targets or []:
            if not isinstance(target, dict):
                continue
            fqdn = str(target.get("fqdn", "")).strip().lower().rstrip(".")
            ip = str(target.get("ip", "") or "").strip()
            try:
                port = int(target.get("port", 443))
            except (TypeError, ValueError):
                continue
            if not fqdn or not port:
                continue
            key = (fqdn, port, ip)
            if key in seen_targets:
                continue
            seen_targets.add(key)
            clean_targets.append({"fqdn": fqdn, "port": port, "ip": ip})
        return clean_targets

    def _screenshot_result_label(result: dict) -> str:
        if result.get("mode") == "forced" and result.get("ip"):
            return f"{result['fqdn']}:{result['port']} [forced {result['ip']}]"
        return f"{result['fqdn']}:{result['port']} [dns]"

    def _screenshot_queue_position(job_id: str) -> int:
        try:
            return app.state.screenshot_queue_ids.index(job_id) + 1
        except ValueError:
            return 0

    def _screenshot_pending_count() -> int:
        return sum(1 for job in app.state.screenshot_jobs.values() if job["status"] == "pending")

    def _screenshot_public_job(job: dict, queue_position: int | None = None, queued_count: int | None = None) -> dict:
        if queue_position is None:
            queue_position = _screenshot_queue_position(job["id"])
        if queued_count is None:
            queued_count = _screenshot_pending_count()
        return {
            "id": job["id"],
            "status": job["status"],
            "total": job["total"],
            "completed": job["completed"],
            "ok_count": job["ok_count"],
            "failed_count": job["failed_count"],
            "current_label": job["current_label"],
            "results": job["results"],
            "error": job["error"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
            "finished_at": job["finished_at"].isoformat() if job.get("finished_at") else "",
            "queue_position": queue_position,
            "queued_count": queued_count,
        }

    def _get_active_screenshot_job() -> dict | None:
        job_id = app.state.active_screenshot_job_id
        job = app.state.screenshot_jobs.get(job_id) if job_id else None
        if job and job["status"] in ("pending", "running"):
            return job
        return None

    def _get_current_screenshot_job() -> dict | None:
        active = _get_active_screenshot_job()
        if active:
            return active
        for job_id in app.state.screenshot_queue_ids:
            job = app.state.screenshot_jobs.get(job_id)
            if job and job["status"] == "pending":
                return job
        return None

    def _prune_screenshot_jobs() -> None:
        now = datetime.utcnow()
        for job_id in list(app.state.screenshot_jobs):
            job = app.state.screenshot_jobs.get(job_id)
            if not job or job["status"] in ("pending", "running"):
                continue
            finished_at = job.get("finished_at")
            if not finished_at:
                continue
            if (now - finished_at).total_seconds() > 600:
                app.state.screenshot_jobs.pop(job_id, None)
                if job_id in app.state.screenshot_queue_ids:
                    app.state.screenshot_queue_ids.remove(job_id)

    async def _run_screenshot_capture(clean_targets: list[dict], progress_cb=None, status_cb=None) -> list[dict]:
        from playwright.async_api import async_playwright

        screenshots_dir = st.ws.uploads_dir / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            async def capture_targets(target_list: list[dict], launch_args: list[str] | None = None) -> list[dict]:
                try:
                    browser = await p.chromium.launch(
                        headless=True,
                        args=launch_args or [],
                        **_screenshot_proxy_options(),
                        **_screenshot_browser_options(),
                    )
                except Exception as e:
                    raise _screenshot_browser_launch_error(e) from e
                context = await browser.new_context(ignore_https_errors=True)
                batch_results: list[dict] = []

                for target in target_list:
                    fqdn = target["fqdn"]
                    port = target["port"]
                    ip = target.get("ip", "")
                    capture_mode = "forced" if ip else "dns"
                    if status_cb is not None:
                        status_cb(
                            _screenshot_result_label(
                                {"fqdn": fqdn, "port": port, "ip": ip, "mode": capture_mode}
                            )
                        )

                    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                    safe_fqdn = fqdn.replace(".", "-")
                    safe_ip = ip.replace(".", "-") if ip else ""
                    filename = (
                        f"{safe_fqdn}_{port}_{safe_ip}_{ts}_{uuid.uuid4().hex[:8]}_forced.png"
                        if ip
                        else f"{safe_fqdn}_{port}_{ts}_{uuid.uuid4().hex[:8]}_dns.png"
                    )
                    filepath = screenshots_dir / filename

                    success = False
                    http_status = 0
                    http_title = ""
                    http_content_length = 0
                    error = ""
                    scheme = "https"

                    for try_scheme in ["https", "http"]:
                        url = f"{try_scheme}://{fqdn}:{port}"
                        scheme = try_scheme
                        page = None
                        try:
                            page = await context.new_page()
                            resp = await page.goto(url, timeout=30000, wait_until="domcontentloaded")
                            if resp is not None:
                                http_status = resp.status
                                headers = resp.headers
                                content_length_str = headers.get("content-length", "")
                                http_content_length = int(content_length_str) if content_length_str.isdigit() else 0

                                try:
                                    http_title = await page.title()
                                except Exception:
                                    http_title = ""

                                await page.screenshot(path=str(filepath), clip={"x": 0, "y": 0, "width": 1280, "height": 720})
                                success = True
                                await page.close()
                                page = None
                                break
                        except Exception as e:
                            error = str(e)[:255]
                            if page is not None:
                                try:
                                    await page.close()
                                except Exception:
                                    pass
                            continue

                    rec = WebScreenshot(
                        fqdn=fqdn,
                        port=port,
                        scheme=scheme,
                        screenshot_path=filepath.name if success else "",
                        http_status=http_status,
                        http_title=http_title[:512] if http_title else "",
                        http_content_length=http_content_length,
                        error=error,
                        target_ip=ip,
                        capture_mode=capture_mode,
                        created_at=datetime.utcnow(),
                    )
                    with st.SessionLocal() as s:
                        s.add(rec)
                        s.commit()

                    result = {
                        "fqdn": fqdn,
                        "port": port,
                        "ip": ip,
                        "mode": capture_mode,
                        "ok": success,
                        "http_status": http_status,
                        "http_title": http_title,
                        "file": filepath.name if success else "",
                        "error": error,
                    }
                    batch_results.append(result)
                    if progress_cb is not None:
                        progress_cb(result)

                await context.close()
                await browser.close()
                return batch_results

            auto_targets = [t for t in clean_targets if not t["ip"]]
            forced_targets = [t for t in clean_targets if t["ip"]]

            results = []
            if auto_targets:
                results.extend(await capture_targets(auto_targets))

            forced_groups: dict[str, list[dict]] = {}
            for t in forced_targets:
                forced_groups.setdefault(t["ip"], []).append(t)
            for ip, group_targets in forced_groups.items():
                rules = ", ".join(
                    dict.fromkeys(
                        f"MAP {t['fqdn']}:{t['port']} {ip}" for t in group_targets
                    )
                )
                results.extend(
                    await capture_targets(group_targets, [f"--host-resolver-rules={rules}"])
                )

        return results

    async def _run_screenshot_job(job_id: str) -> None:
        job = app.state.screenshot_jobs.get(job_id)
        if not job:
            return
        try:
            job["status"] = "running"
            job["updated_at"] = datetime.utcnow().isoformat()

            def progress_cb(result: dict) -> None:
                job["completed"] += 1
                if result.get("ok"):
                    job["ok_count"] += 1
                else:
                    job["failed_count"] += 1
                job["current_label"] = _screenshot_result_label(result)
                job["results"].append(result)
                job["updated_at"] = datetime.utcnow().isoformat()

            def status_cb(label: str) -> None:
                job["current_label"] = label
                job["updated_at"] = datetime.utcnow().isoformat()

            await _run_screenshot_capture(job["targets"], progress_cb, status_cb)
            job["status"] = "completed"
            job["error"] = ""
        except Exception as e:
            job["status"] = "failed"
            job["error"] = str(e)[:500]
        finally:
            job["finished_at"] = datetime.utcnow()
            job["updated_at"] = datetime.utcnow().isoformat()
            if app.state.active_screenshot_job_id == job_id:
                app.state.active_screenshot_job_id = None

    async def _screenshot_worker() -> None:
        while True:
            job_id = await app.state.screenshot_queue.get()
            try:
                if job_id in app.state.screenshot_queue_ids:
                    app.state.screenshot_queue_ids.remove(job_id)
                job = app.state.screenshot_jobs.get(job_id)
                if not job or job["status"] != "pending":
                    continue
                app.state.active_screenshot_job_id = job_id
                job["current_label"] = "Starting..."
                job["updated_at"] = datetime.utcnow().isoformat()
                await _run_screenshot_job(job_id)
            except Exception as e:
                job = app.state.screenshot_jobs.get(job_id)
                if job:
                    job["status"] = "failed"
                    job["error"] = str(e)[:500]
                    job["finished_at"] = datetime.utcnow()
                    job["updated_at"] = datetime.utcnow().isoformat()
            finally:
                if app.state.active_screenshot_job_id == job_id:
                    app.state.active_screenshot_job_id = None
                app.state.screenshot_queue.task_done()

    def _ensure_screenshot_worker() -> None:
        task = app.state.screenshot_worker_task
        if task is not None and not task.done():
            return
        app.state.screenshot_worker_task = asyncio.create_task(_screenshot_worker())

    @router.get("/api/screenshot/browser-status")
    async def api_screenshot_browser_status(request: Request):
        return await _screenshot_browser_status(request.url.port)

    @router.post("/api/screenshot/jobs")
    async def api_screenshot_create_job(request: Request):
        body = await request.json()
        clean_targets = _clean_screenshot_targets(body.get("targets", []))
        if not clean_targets:
            return JSONResponse({"ok": False, "error": "No valid targets provided"}, status_code=400)
        _prune_screenshot_jobs()
        job_id = uuid.uuid4().hex
        now = datetime.utcnow()
        job = {
            "id": job_id,
            "targets": clean_targets,
            "status": "pending",
            "total": len(clean_targets),
            "completed": 0,
            "ok_count": 0,
            "failed_count": 0,
            "current_label": "Queued...",
            "results": [],
            "error": "",
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "finished_at": None,
        }
        app.state.screenshot_jobs[job_id] = job
        app.state.screenshot_queue_ids.append(job_id)
        await app.state.screenshot_queue.put(job_id)
        _ensure_screenshot_worker()
        return {
            "ok": True,
            "job": _screenshot_public_job(
                job,
                queue_position=len(app.state.screenshot_queue_ids),
                queued_count=_screenshot_pending_count(),
            ),
        }

    @router.get("/api/screenshot/jobs/active")
    def api_screenshot_jobs_active():
        _prune_screenshot_jobs()
        current = _get_current_screenshot_job()
        last = None
        for job in app.state.screenshot_jobs.values():
            if job["status"] in ("pending", "running"):
                continue
            finished_at = job.get("finished_at")
            if not finished_at:
                continue
            if last is None or finished_at > last.get("finished_at"):
                last = job
        queued_count = _screenshot_pending_count()
        return {
            "ok": True,
            "active_job": _screenshot_public_job(current, queued_count=queued_count) if current else None,
            "last_job": _screenshot_public_job(last, queued_count=queued_count) if last else None,
            "queued_count": queued_count,
        }

    @router.get("/api/screenshot/jobs/{job_id}")
    def api_screenshot_job_status(job_id: str):
        job = app.state.screenshot_jobs.get(job_id)
        if not job:
            return JSONResponse({"ok": False, "error": "Job not found"}, status_code=404)
        return {
            "ok": True,
            "job": _screenshot_public_job(job, queued_count=_screenshot_pending_count()),
        }

    @router.get("/api/screenshot/latest")
    def api_screenshot_latest(request: Request):
        show_out = request.query_params.get("show_out", "0") == "1"
        shot_dir = st.ws.uploads_dir / "screenshots"
        with st.db() as s:
            ips, subnets, domains, _, domain_all_subs, domain_subs_if_ip, excluded = scope_sets(s)
            rows = (
                s.query(WebScreenshot)
                .order_by(WebScreenshot.created_at.desc(), WebScreenshot.id.desc())
                .all()
            )
            latest = {}
            for r in rows:
                fqdn = (r.fqdn or "").strip().lower()
                if not fqdn or fqdn in latest:
                    continue
                path = (r.screenshot_path or "").strip()
                if not path:
                    continue
                try:
                    if not (shot_dir / path).is_file():
                        continue
                except Exception:
                    continue
                latest[fqdn] = r
            all_ips_map: dict[str, list[str]] = {}
            for k, v in list_all_subdomain_ips(s).items():
                all_ips_map.setdefault(k.lower(), v)
            prowl_map: dict[str, str] = {}
            complete_map: dict[str, int] = {}
            for x in s.execute(select(Subdomain)).scalars().all():
                prowl_map[x.fqdn.lower()] = x.prowl_ips or ""
                complete_map[x.fqdn.lower()] = getattr(x, "complete", 0) or 0
        hosts = []
        for fqdn, r in latest.items():
            resolved = all_ips_map.get(fqdn, [])
            prowl = [p.strip() for p in prowl_map.get(fqdn, "").split(",") if p.strip()]
            all_ips = list(set(resolved) | set(prowl))
            in_dom = domain_in_scope(
                fqdn, domains, domain_all_subs, domain_subs_if_ip,
                resolved, ips, subnets, excluded,
            )
            in_scope_ip_set = {ip for ip in all_ips if ip_in_scope(ip, ips, subnets, excluded)}
            in_scope = bool(in_dom or in_scope_ip_set)
            if not show_out and not in_scope:
                continue
            try:
                is_ip = ipaddress.ip_address(fqdn) is not None
            except Exception:
                is_ip = False
            scheme = (r.scheme or "https").strip().lower().rstrip(":")
            if scheme not in ("http", "https"):
                scheme = "https"
            port = r.port or 0
            default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            host_part = f"[{fqdn}]" if ":" in fqdn else fqdn
            url = f"{scheme}://{host_part}" + ("" if default_port else f":{port}")
            hosts.append(
                {
                    "fqdn": fqdn,
                    "is_ip": is_ip,
                    "in_scope": in_scope,
                    "screenshot_path": r.screenshot_path,
                    "port": r.port,
                    "scheme": r.scheme or "",
                    "http_status": r.http_status or 0,
                    "http_title": r.http_title or "",
                    "created_at": r.created_at.isoformat() if r.created_at else "",
                    "complete": complete_map.get(fqdn, 0),
                    "url": url,
                }
            )
        hosts.sort(key=lambda h: h["fqdn"])
        return {"ok": True, "hosts": hosts}

    @router.get("/api/screenshot/by-fqdn/{fqdn}")
    def api_screenshots_by_fqdn(fqdn: str):
        fqdn = fqdn.strip().lower()
        with st.SessionLocal() as s:
            rows = (
                s.query(WebScreenshot)
                .filter(WebScreenshot.fqdn == fqdn)
                .order_by(WebScreenshot.created_at.desc())
                .all()
            )
        return {
            "ok": True,
            "screenshots": [
                {
                    "id": r.id,
                    "fqdn": r.fqdn,
                    "port": r.port,
                    "scheme": r.scheme,
                    "screenshot_path": r.screenshot_path,
                    "http_status": r.http_status,
                    "http_title": r.http_title,
                    "http_content_length": r.http_content_length,
                    "error": r.error,
                    "target_ip": r.target_ip or "",
                    "capture_mode": r.capture_mode or "dns",
                    "created_at": r.created_at.isoformat() if r.created_at else "",
                }
                for r in rows
            ],
        }

    @router.get("/screenshots/{path:path}")
    async def serve_screenshot(path: str):
        filepath = st.ws.uploads_dir / "screenshots" / path
        if not filepath.exists() or not filepath.is_file():
            return JSONResponse({"error": "Not found"}, status_code=404)
        return FileResponse(filepath, media_type="image/png")

    st._get_current_screenshot_job = _get_current_screenshot_job
    st._prune_screenshot_jobs = _prune_screenshot_jobs
    return router
