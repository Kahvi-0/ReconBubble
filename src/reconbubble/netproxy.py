"""SOCKS5 proxy support for ReconBubble outbound traffic.

Set RECONBUBBLE_PROXY to a socks5:// URL (e.g. socks5://127.0.0.1:1080 or
socks5://user:pass@127.0.0.1:1080) and the following are routed through it:

- web protocol probes (raw TCP + optional TLS)
- whois port 43 lookups
- RDAP / web-source HTTPS lookups
- screenshots (Playwright chromium.launch(proxy=...))
- external CLI tools, via the standard all_proxy/https_proxy/http_proxy env
  vars mirrored by create_app (tools.py inherits os.environ)

With RECONBUBBLE_PROXY unset, every helper falls back to the plain direct
code path, so behavior is unchanged.
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
from urllib.parse import urljoin, urlsplit

ENV_VAR = "RECONBUBBLE_PROXY"


class ProxyConfigError(ValueError):
    """RECONBUBBLE_PROXY is set but malformed or unsupported."""


def parse_proxy_url(value: str) -> dict | None:
    """Parse a socks5://[user:pass@]host:port URL.

    A bare host:port is accepted and treated as socks5. Returns None when
    value is empty; raises ProxyConfigError otherwise.
    """
    value = (value or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = "socks5://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() != "socks5":
        raise ProxyConfigError(
            f"unsupported proxy scheme {parts.scheme!r} in {ENV_VAR}: "
            "only socks5:// is supported"
        )
    if not parts.hostname or not parts.port:
        raise ProxyConfigError(f"missing host:port in {ENV_VAR} value")
    return {
        "host": parts.hostname,
        "port": parts.port,
        "username": parts.username or "",
        "password": parts.password or "",
    }


def proxy_settings() -> dict | None:
    """Read and parse RECONBUBBLE_PROXY from the environment (None when unset)."""
    return parse_proxy_url(os.environ.get(ENV_VAR, ""))


def describe() -> str:
    """Masked proxy URL for status display; empty string when unset."""
    settings = proxy_settings()
    if not settings:
        return ""
    auth = f"{settings['username']}:***@" if settings["username"] else ""
    return f"socks5://{auth}{settings['host']}:{settings['port']}"


def mirror_env() -> None:
    """Mirror RECONBUBBLE_PROXY into the standard proxy env vars.

    Subprocess tools (subfinder, theHarvester, cero) inherit os.environ and
    honor all_proxy/https_proxy/http_proxy, so one env var covers them.
    """
    settings = proxy_settings()
    if not settings:
        return
    auth = f"{settings['username']}:{settings['password']}@" if settings["username"] else ""
    url = f"socks5://{auth}{settings['host']}:{settings['port']}"
    for var in (
        "all_proxy",
        "ALL_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "http_proxy",
        "HTTP_PROXY",
    ):
        os.environ[var] = url


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("proxy connection closed during SOCKS5 handshake")
        buf += chunk
    return buf


def _socks5_address(addr: str) -> tuple[int, bytes]:
    """Encode a destination address for a SOCKS5 connect request."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        try:
            raw = addr.encode("idna")
        except (UnicodeError, ValueError):
            raw = addr.encode("utf-8")
        return 0x03, bytes([len(raw)]) + raw
    if ip.version == 4:
        return 0x01, ip.packed
    return 0x04, ip.packed


def socks5_connect(
    host: str,
    port: int,
    timeout: float = 10.0,
    username: str | None = None,
    password: str | None = None,
) -> socket.socket:
    """Open a TCP connection to host:port.

    When RECONBUBBLE_PROXY is set the connection is tunneled through that
    SOCKS5 proxy (RFC 1928, plus RFC 1929 username/password auth). Otherwise
    it is a plain socket.create_connection. Returns a connected, unencrypted
    socket with the given timeout.
    """
    settings = proxy_settings()
    if not settings:
        return socket.create_connection((host, port), timeout=timeout)
    if username is None:
        username = settings["username"]
    if password is None:
        password = settings["password"]

    sock = socket.create_connection(
        (settings["host"], settings["port"]), timeout=timeout
    )
    try:
        methods = b"\x00"
        if username:
            methods += b"\x02"
        sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
        ver, method = _recv_exact(sock, 2)
        if ver != 0x05:
            raise ConnectionError(
                f"proxy is not a SOCKS5 server (version byte {ver:#x})"
            )
        if method == 0xFF:
            raise PermissionError(
                "proxy rejected every offered authentication method"
            )
        if method == 0x02:
            user = username.encode("utf-8")
            pwd = password.encode("utf-8")
            sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
            auth_ver, auth_status = _recv_exact(sock, 2)
            if auth_ver != 0x01 or auth_status != 0x00:
                raise PermissionError(
                    f"proxy authentication failed (status {auth_status:#x})"
                )
        atyp, addr_bytes = _socks5_address(host)
        sock.sendall(
            b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, "big")
        )
        ver, rep = _recv_exact(sock, 2)
        if ver != 0x05:
            raise ConnectionError(
                f"proxy sent a malformed SOCKS5 reply (version byte {ver:#x})"
            )
        if rep != 0x00:
            raise ConnectionError(
                f"proxy refused the connection (SOCKS5 reply code {rep:#x})"
            )
        rsv_atyp = _recv_exact(sock, 2)
        bnd_atyp = rsv_atyp[1]
        if bnd_atyp == 0x01:
            _recv_exact(sock, 4)
        elif bnd_atyp == 0x04:
            _recv_exact(sock, 16)
        else:  # 0x03 domain
            (domain_len,) = _recv_exact(sock, 1)
            _recv_exact(sock, domain_len)
        _recv_exact(sock, 2)
        return sock
    except BaseException:
        try:
            sock.close()
        except Exception:
            pass
        raise


def https_get(
    url: str,
    timeout: float = 10.0,
    headers: dict | None = None,
    max_bytes: int | None = None,
    max_redirects: int = 5,
) -> str:
    """GET an https:// URL and return the body as text.

    TLS is verified with the default context (matching urllib.request.urlopen),
    redirects are followed up to max_redirects, and 4xx/5xx raise. When
    RECONBUBBLE_PROXY is set the TCP connection is tunneled through it.
    """
    settings = proxy_settings()
    current = url
    for _ in range(max_redirects + 1):
        parts = urlsplit(current)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError(f"unsupported URL for proxy GET: {url}")
        host = parts.hostname
        port = parts.port or 443
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if settings:
            sock = socks5_connect(host, port, timeout=timeout)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
        try:
            wrapped = ssl.create_default_context().wrap_socket(
                sock, server_hostname=host
            )
        except BaseException:
            try:
                sock.close()
            except Exception:
                pass
            raise
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        conn.sock = wrapped
        try:
            conn.request(
                "GET", path, headers=headers or {"User-Agent": "ReconBubble/1.0"}
            )
            resp = conn.getresponse()
            body = resp.read(max_bytes) if max_bytes else resp.read()
            status = resp.status
            location = resp.getheader("Location") if status in (
                301,
                302,
                303,
                307,
                308,
            ) else None
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if status in (301, 302, 303, 307, 308):
            if not location:
                raise RuntimeError(
                    f"HTTP {status} without Location header from {host}"
                )
            current = urljoin(current, location)
            continue
        if status >= 400:
            raise RuntimeError(f"HTTP {status} from {host}")
        return body.decode("utf-8", "replace")
    raise RuntimeError(f"too many redirects fetching {url}")
