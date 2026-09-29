"""Local NSE script catalog.

Parses the nmap script directory (default /usr/share/nmap/scripts, override
with RECONBUBBLE_NSE_DIR) into an in-memory catalog used to interpret stored
scan results and to suggest NSE scripts for detected services.

Sources per script:
- script.db lines: Entry { filename = "x.nse", categories = { "vuln", "safe" } }
- .nse headers: description = [[...]], author, categories = {...}, portrule
  (shortport aliases and function bodies are resolved heuristically), and
  CVE references found in the description text.

The catalog degrades silently: if the directory or script.db is missing the
catalog is empty and suggestion features simply show nothing.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

ENV_NSE_DIR = "RECONBUBBLE_NSE_DIR"
DEFAULT_NSE_DIR = "/usr/share/nmap/scripts"

# --- shortport alias tables (mirrors nselib/shortport.lua) -----------------

LIKELY_HTTP_PORTS = {80, 443, 631, 7080, 8080, 8443, 8088, 5800, 3872, 8180, 8000}
LIKELY_HTTP_SERVICES = {
    "http", "https", "ipp", "http-alt", "https-alt", "vnc-http", "oem-agent",
    "soap", "http-proxy", "caldav", "carddav", "webdav",
}
LIKELY_SSL_PORTS = {
    261, 271, 324, 443, 465, 563, 585, 636, 853, 989, 990, 992, 993, 994, 995,
    2221, 2252, 2376, 3269, 3389, 4433, 4911, 5061, 5986, 6679, 6697, 8443,
    8883, 9001,
}
LIKELY_SSL_SERVICES = {
    "ftps", "ftps-data", "ftps-control", "https", "https-alt", "imaps", "ircs",
    "ldapssl", "ms-wbt-server", "pop3s", "sip-tls", "smtps", "telnets",
    "tor-orport",
}
LIKELY_SSH_PORTS = {22, 830, 2222, 22222, 2382, 55554}
LIKELY_SSH_SERVICES = {"ssh", "netconf-ssh"}

_ALIASES: dict[str, tuple[set[int], set[str]]] = {
    "http": (LIKELY_HTTP_PORTS, LIKELY_HTTP_SERVICES),
    "ssl": (LIKELY_SSL_PORTS, LIKELY_SSL_SERVICES),
    "ssh": (LIKELY_SSH_PORTS, LIKELY_SSH_SERVICES),
}

# nmap's IANA service name -> extra names to try in suggest(), for cases
# where the name nmap reports differs from what NSE scripts declare in
# their port rules (e.g. nmap says "netbios-ssn", NSE says "microsoft-ds").
_SERVICE_ALIASES: dict[str, set[str]] = {
    "netbios-ssn": {"smb", "microsoft-ds"},
    "netbios-ns": {"netbios"},
    "netbios-dgm": {"netbios"},
    "microsoft-ds": {"smb", "netbios-ssn"},
    "smb": {"microsoft-ds", "netbios-ssn"},
    "kerberos": {"kerberos-sec"},
    "kerberos-sec": {"kerberos"},
    "ldapssl": {"ldap"},
    "ldaps": {"ldap"},
    "smtps": {"smtp"},
    "imaps": {"imap"},
    "pop3s": {"pop3"},
    "ftps": {"ftp"},
    "https": {"http"},
    "https-alt": {"http"},
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_INT_RE = re.compile(r"\b(\d{1,5})\b")
_STR_RE = re.compile(r'"([^"]+)"')


@dataclass
class NseScript:
    name: str  # filename without .nse
    categories: set[str] = field(default_factory=set)
    description: str = ""
    author: str = ""
    cves: list[str] = field(default_factory=list)
    ports: set[int] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    usage: str = ""

    @property
    def is_safe(self) -> bool:
        return "safe" in self.categories

    @property
    def is_intrusive(self) -> bool:
        return bool(self.categories & {"intrusive", "brute", "exploit", "dos"})


def _parse_number_list(text: str) -> set[int]:
    out = set()
    for m in _INT_RE.finditer(text or ""):
        v = int(m.group(1))
        if 0 < v < 65536:
            out.add(v)
    return out


def _parse_string_list(text: str) -> set[str]:
    return {s.strip().lower() for s in _STR_RE.findall(text or "") if s.strip()}


def _parse_port_range(text: str) -> set[int]:
    """Parse an nmap-style port range like 'T:80,1-30,U:31337'."""
    ports: set[int] = set()
    for part in (text or "").replace("T:", ",").replace("U:", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                a, b = int(a), int(b)
            except ValueError:
                continue
            if 0 < a <= b < 65536 and b - a < 65536:
                ports.update(range(a, b + 1))
        else:
            try:
                v = int(part)
            except ValueError:
                continue
            if 0 < v < 65536:
                ports.add(v)
    return ports


def parse_portrule(expr: str) -> tuple[set[int], set[str]]:
    """Heuristically extract (ports, services) from a portrule expression."""
    expr = (expr or "").strip()
    if not expr:
        return set(), set()
    ports: set[int] = set()
    services: set[str] = set()

    # shortport.http / shortport.ssl / shortport.ssh
    m = re.match(r"^shortport\.(\w+)$", expr)
    if m:
        alias = m.group(1)
        if alias in _ALIASES:
            p, s = _ALIASES[alias]
            return set(p), set(s)
        return set(), set()

    # shortport.<fn>(args...)
    m = re.match(r"^shortport\.(\w+)\((.*)\)\s*$", expr, re.DOTALL)
    if m:
        fn, args = m.group(1), m.group(2)
        if fn == "portnumber":
            ports |= _parse_number_list(args)
        elif fn == "service":
            services |= _parse_string_list(args)
        elif fn in ("port_or_service", "version_port_or_service"):
            # Signature: (portnums, service, proto, state) - only the first
            # two args are ports/services; proto/state are not service names.
            pieces = _split_top_level(args)
            if pieces:
                ports |= _parse_number_list(pieces[0])
            if len(pieces) > 1:
                services |= _parse_string_list(pieces[1])
        elif fn == "port_range":
            ports |= _parse_port_range(_STR_RE.search(args).group(1) if _STR_RE.search(args) else args)
        else:
            ports |= _parse_number_list(args)
            services |= _parse_string_list(args)
        return ports, services

    # bare number or table: port = 80 / port = { 445, 139, "smb" }
    if re.match(r"^\d+$", expr) or expr.startswith("{"):
        inner = expr.strip()
        if inner.startswith("{") and inner.endswith("}"):
            inner = inner[1:-1]
        for piece in _split_top_level(inner):
            if re.search(r'"', piece):
                services |= _parse_string_list(piece)
            else:
                ports |= _parse_number_list(piece)
        return ports, services

    # portrule = function(host, port) ... end
    body = expr
    for fn in ("port_or_service", "portnumber", "service"):
        for call in re.finditer(rf"\b{fn}\s*\(([^;]{{0,400}}?)\)\s*[;)]", body, re.DOTALL):
            if fn == "portnumber":
                ports |= _parse_number_list(call.group(1))
            elif fn == "service":
                services |= _parse_string_list(call.group(1))
            else:
                pieces = _split_top_level(call.group(1))
                if pieces:
                    ports |= _parse_number_list(pieces[0])
                if len(pieces) > 1:
                    services |= _parse_string_list(pieces[1])
    # port.number == N / ~= / >= patterns
    for m in re.finditer(r"port\.number\s*[=~><]+\s*(\d+)", body):
        v = int(m.group(1))
        if 0 < v < 65536:
            ports.add(v)
    # port.service == "x" / nmap.service("x") patterns
    for m in re.finditer(r'port\.service\s*[=~]+\s*"([^"]+)"', body):
        services.add(m.group(1).lower())
    for m in re.finditer(r'nmap\.service\s*\(\s*"([^"]+)"', body):
        services.add(m.group(1).lower())
    return ports, services


def _split_top_level(text: str) -> list[str]:
    """Split 'a, b' on commas not nested inside braces/parens/brackets."""
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch in "{([":
            depth += 1
        elif ch in "})]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


@dataclass
class NseCatalog:
    nse_dir: str = ""
    scripts: dict[str, NseScript] = field(default_factory=dict)

    def get(self, name: str) -> NseScript | None:
        return self.scripts.get((name or "").strip().lower().removesuffix(".nse"))

    def by_category(self, category: str) -> list[NseScript]:
        cat = (category or "").strip().lower()
        if not cat:
            return sorted(self.scripts.values(), key=lambda s: s.name)
        return sorted(
            (s for s in self.scripts.values() if cat in s.categories),
            key=lambda s: s.name,
        )

    def suggest(self, service_name: str, port: int | None, limit: int = 8) -> list[NseScript]:
        """Suggest catalog scripts for a detected service.

        Priority: service-name match > port match > script-name prefix.
        Safe scripts (vuln/discovery + safe) rank above plain info scripts;
        intrusive/brute/exploit/dos scripts are excluded.
        """
        name = (service_name or "").strip().lower()
        if not name and port:
            # No service detected - fall back to the IANA name for the port.
            try:
                import socket
                name = socket.getservbyport(port, "tcp")
            except OSError:
                name = ""
        if name:
            names = {name} | _SERVICE_ALIASES.get(name, set())
        else:
            names = set()
        scored: list[tuple[int, NseScript]] = []
        for sc in self.scripts.values():
            if sc.is_intrusive:
                continue
            score = 0
            if names & sc.services:
                score += 4
            if port and port in sc.ports:
                score += 3
            if any(
                n and (
                    sc.name == n
                    or sc.name.startswith(n + "-")
                    or sc.name.startswith(n + "_")
                )
                for n in names
            ):
                score += 2
            if score == 0:
                continue
            if "vuln" in sc.categories and sc.is_safe:
                score += 2
            elif "discovery" in sc.categories and sc.is_safe:
                score += 1
            scored.append((score, sc))
        scored.sort(key=lambda t: (-t[0], t[1].name))
        return [sc for _, sc in scored[:limit]]


def _parse_script_header(path: Path) -> NseScript:
    name = path.stem
    try:
        head = path.read_text("utf-8", "replace")[:65536]
    except OSError:
        return NseScript(name=name)
    sc = NseScript(name=name)

    m = re.search(r"^description\s*=\s*\[\[(.*?)\]\]", head, re.DOTALL | re.MULTILINE)
    if m:
        desc = re.sub(r"\s+", " ", m.group(1)).strip()
        sc.description = desc[:1000]
        sc.cves = sorted(set(_CVE_RE.findall(m.group(1))))

    m = re.search(r"^categories\s*=\s*\{([^}]*)\}", head, re.MULTILINE)
    if m:
        sc.categories = {c.strip().strip('"') for c in m.group(1).split(",") if c.strip()}

    m = re.search(r'^author\s*=\s*(\{[^}]*\}|"[^"]*")', head, re.MULTILINE)
    if m:
        raw = m.group(1)
        sc.author = ", ".join(_STR_RE.findall(raw)) or raw.strip('"')

    # port = ... (standard NSE field); some scripts use the alias "portrule"
    m = re.search(r"^(?:port|portrule)\s*=\s*(.+)$", head, re.MULTILINE)
    if m:
        expr = m.group(1).strip()
        if expr.startswith("function"):
            # capture the whole function body
            fm = re.search(r"^(?:port|portrule)\s*=\s*function.*?\bend\b", head, re.MULTILINE | re.DOTALL)
            expr = fm.group(0) if fm else expr
        sc.ports, sc.services = parse_portrule(expr)

    m = re.search(r"--\s*@usage\s+(.+)$", head, re.MULTILINE)
    if m:
        sc.usage = m.group(1).strip()[:300]

    return sc


def load_catalog(nse_dir: str | None = None) -> NseCatalog:
    """Load (or reload) the catalog for the given (or default) NSE directory."""
    base = Path(nse_dir or os.environ.get(ENV_NSE_DIR, "").strip() or DEFAULT_NSE_DIR)
    catalog = NseCatalog(nse_dir=str(base))
    if not base.is_dir():
        return catalog
    for path in sorted(base.glob("*.nse")):
        catalog.scripts[path.stem.lower()] = _parse_script_header(path)
    db = base / "script.db"
    if db.is_file():
        entry_re = re.compile(
            r'Entry\s*\{\s*filename\s*=\s*"([^"]+)",\s*categories\s*=\s*\{([^}]*)\}\s*\}'
        )
        try:
            for line in db.read_text("utf-8", "replace").splitlines():
                m = entry_re.search(line)
                if not m:
                    continue
                filename, cats = m.group(1), m.group(2)
                sc = catalog.scripts.get(filename.lower().removesuffix(".nse"))
                if sc is None:
                    continue
                parsed = {c.strip().strip('"') for c in cats.split(",") if c.strip()}
                # script.db is authoritative for categories
                sc.categories = parsed
        except OSError:
            pass
    return catalog


_cache: dict[str, NseCatalog] = {}
_cache_key = ""


def get_catalog() -> NseCatalog:
    """Cached catalog; reloaded when the NSE directory changes (mtime)."""
    global _cache_key
    base = Path(os.environ.get(ENV_NSE_DIR, "").strip() or DEFAULT_NSE_DIR)
    try:
        key = (str(base), base.stat().st_mtime_ns if base.is_dir() else 0)
    except OSError:
        key = (str(base), 0)
    if key != _cache_key:
        _cache.clear()
        _cache_key = key
        _cache[str(base)] = load_catalog(str(base))
    return _cache.get(str(base), NseCatalog(nse_dir=str(base)))


def render_nmap_command(scripts: list[NseScript], port: int | None, target: str) -> str:
    """Render a copy-ready nmap command for the suggested scripts."""
    names = ",".join(sc.name for sc in scripts)
    if not names:
        return ""
    port_part = f" -p{port}" if port else ""
    return f"nmap -sV{port_part} --script {names} {target or '<target>'}"
