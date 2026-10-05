"""External recon tool registry and execution.

Tools are user-installed binaries (subfinder, theHarvester). ReconBubble never
downloads or installs them automatically -- the UI only shows install hints.
Execution is locked down: fixed argv templates, strict target validation,
no shell, process-group kill on timeout.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import os
import random
import re
import shutil
import signal
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import netproxy

# Strict target validation: lowercase FQDN, labels start alphanumeric,
# never begins with "-" so the target can't be parsed as an option.
TARGET_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)

# Lenient FQDN extraction for tool stdout (theHarvester mixes prose in output).
FQDN_RE = re.compile(
    r"(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b"
)

VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+){0,2})")

RAW_CAP = 20000

# Default TLS ports probed by cero (HTTPS, alt-HTTPS, and TLS mail ports).
# Note: port 80 is non-TLS, so it will not yield certificates.
_CERO_DEFAULT_PORTS = "443,8443,465,587,993,995"


@dataclass(frozen=True)
class ToolSpec:
    name: str  # stable API/UI key
    label: str
    argv: list  # template parts; {bin} and {target} are substituted
    timeout: int
    network_note: str
    install_commands: dict  # method -> shell command hint
    repo_url: str = ""  # upstream project link, shown on the /tools page
    bin_names: tuple = ()  # binary names to locate, in priority order
    builtin: bool = False  # True = implemented in-process (no external binary)
    input_mode: str = "target"  # "target" (argv {target}) or "hosts_ports" (stdin host list + ports)
    wordlist_default: str = ""  # default wordlist for {wordlist} argv slot; UI shows an editable pre-filled box


def _bin_hint(bin_dir: str) -> str:
    return (
        f"or place the binary in the workspace bin directory: {bin_dir} "
        "(ReconBubble checks there first)"
    )


def build_tools(bin_dir: str | Path) -> dict:
    bin_dir = str(bin_dir)
    return {
        "subfinder": ToolSpec(
            name="subfinder",
            label="subfinder",
            argv=["{bin}", "-d", "{target}", "-silent"],
            timeout=300,
            bin_names=("subfinder",),
            repo_url="https://github.com/projectdiscovery/subfinder",
            network_note=(
                "Passive: queries the projectdiscovery cloud API for "
                "subdomains. The target domain is sent to projectdiscovery.io."
            ),
            install_commands={
                "brew": "brew install subfinder",
                "go": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "manual": (
                    "Download a release binary from "
                    "https://github.com/projectdiscovery/subfinder/releases "
                    + _bin_hint(bin_dir)
                ),
            },
        ),
        "theharvester": ToolSpec(
            name="theharvester",
            label="theHarvester",
            argv=["{bin}", "-d", "{target}", "-b", "all"],
            timeout=300,
            # "theHarvester" is the real binary (Kali apt, pip); lowercase
            # "theharvester" is the Homebrew name, but on Kali it is a
            # deprecated no-op wrapper, so try the canonical name first.
            bin_names=("theHarvester", "theharvester"),
            repo_url="https://github.com/laramies/theHarvester",
            network_note=(
                "Passive: queries public search engines (Google, Bing, "
                "DuckDuckGo, ...), certificates, and DNS for subdomains."
            ),
            install_commands={
                "brew": "brew install theharvester",
                "apt": "sudo apt install theharvester",
                "manual": (
                    "Download a release binary from "
                    "https://github.com/laramies/theharvester/releases "
                    + _bin_hint(bin_dir)
                ),
            },
        ),
        "web_sources": ToolSpec(
            name="web_sources",
            label="Web Sources",
            argv=[],
            timeout=120,
            bin_names=(),
            builtin=True,
            install_commands={},
            network_note=(
                "Passive: queries crt.sh, crt.name, and urlscan.io for "
                "certificate records and public scan data revealing "
                "subdomains. No API key required; the target domain is sent "
                "to these public sites."
            ),
        ),
        "cero": ToolSpec(
            name="cero",
            label="Cero",
            argv=["{bin}", "-d", "-c", "1000", "-p", _CERO_DEFAULT_PORTS],
            timeout=300,
            bin_names=("cero",),
            repo_url="https://github.com/glebarez/cero",
            builtin=False,
            input_mode="hosts_ports",
            network_note=(
                "Active: connects to each selected host over TLS and scrapes "
                "the SAN domain names from its certificate. The selected "
                "hostnames/IPs/CIDRs are probed directly (no API key). "
                f"Default ports: {_CERO_DEFAULT_PORTS}."
            ),
            install_commands={
                "go": "go install github.com/glebarez/cero@latest",
                "manual": (
                    "Build from https://github.com/glebarez/cero and place the "
                    "binary in PATH " + _bin_hint(bin_dir)
                ),
            },
        ),
        "gau": ToolSpec(
            name="gau",
            label="GAU (Get All URLs)",
            argv=["{bin}", "--subs", "{target}"],
            timeout=300,
            bin_names=("gau",),
            repo_url="https://github.com/lc/gau",
            network_note=(
                "Passive: queries the Wayback Machine, Common Crawl and "
                "AlienVault OTX for known URLs of the target and its "
                "subdomains; subdomains are extracted from URL hostnames. "
                "The target domain is sent to these public services."
            ),
            install_commands={
                "brew": "brew install gau",
                "go": "go install github.com/lc/gau/v2/cmd/gau@latest",
                "manual": (
                    "Download a release binary from "
                    "https://github.com/lc/gau/releases "
                    + _bin_hint(bin_dir)
                ),
            },
        ),
        "assetfinder": ToolSpec(
            name="assetfinder",
            label="assetfinder",
            argv=["{bin}", "--subs-only", "{target}"],
            timeout=300,
            bin_names=("assetfinder",),
            repo_url="https://github.com/tomnomnom/assetfinder",
            network_note=(
                "Passive: queries certificate transparency (crt.sh, "
                "certspotter) and other public subdomain sources; the "
                "target domain is sent to these public services."
            ),
            install_commands={
                "go": "go install github.com/tomnomnom/assetfinder@latest",
                "manual": (
                    "Download a release binary from "
                    "https://github.com/tomnomnom/assetfinder/releases "
                    + _bin_hint(bin_dir)
                ),
            },
        ),
        "gobuster": ToolSpec(
            name="gobuster",
            label="gobuster (DNS)",
            argv=[
                "{bin}", "dns", "--domain", "{target}",
                "-w", "{wordlist}", "-t", "50", "-q", "--timeout", "5s",
            ],
            timeout=600,
            bin_names=("gobuster",),
            repo_url="https://github.com/OJ/gobuster",
            wordlist_default=(
                "https://raw.githubusercontent.com/Kahvi-0/SubEnoom/main/sublist.txt"
            ),
            network_note=(
                "Active: brute-forces DNS records (A/AAAA) for the target "
                "using a wordlist. The wordlist may be a local file path or "
                "an HTTP(S) URL that ReconBubble downloads to a temp file "
                "before running; the default is the SubEnoom subdomain list. "
                "The target domain is resolved by your DNS provider."
            ),
            install_commands={
                "brew": "brew install gobuster",
                "apt": "sudo apt install gobuster",
                "go": "go install github.com/OJ/gobuster/v3/cmd/gobuster@latest",
                "manual": (
                    "Download a release binary from "
                    "https://github.com/OJ/gobuster/releases "
                    + _bin_hint(bin_dir)
                ),
            },
        ),
        "gobuster_vhost": ToolSpec(
            name="gobuster_vhost",
            label="gobuster (VHost)",
            # No argv template: vhost runs are built per-socket in
            # run_vhost_socket (one gobuster invocation per ip:port).
            argv=[],
            timeout=600,
            bin_names=("gobuster",),
            repo_url="https://github.com/OJ/gobuster",
            input_mode="sockets",
            wordlist_default=(
                "https://raw.githubusercontent.com/Kahvi-0/SubEnoom/main/sublist.txt"
            ),
            network_note=(
                "Active: brute-forces virtual hostnames against selected "
                "ip:port sockets from your scan results (useful for services "
                "without public DNS). By default it replays every subdomain "
                "you have already discovered in the database against each "
                "socket; you can swap in a custom wordlist (file path or "
                "URL) instead. The socket list defaults to open TCP services "
                "on common HTTP ports. Each socket gets a baseline signature "
                "(random Host probes); gobuster candidates matching it are "
                "dropped, and every remaining hit is verified against a "
                "random-Host response before import."
            ),
            install_commands={
                "brew": "brew install gobuster",
                "apt": "sudo apt install gobuster",
                "go": "go install github.com/OJ/gobuster/v3/cmd/gobuster@latest",
                "manual": (
                    "Download a release binary from "
                    "https://github.com/OJ/gobuster/releases "
                    + _bin_hint(bin_dir)
                ),
            },
        ),
        "waybackurls": ToolSpec(
            name="waybackurls",
            label="waybackurls",
            # Subdomains are included by default; the only flag is -no-subs.
            argv=["{bin}", "{target}"],
            timeout=300,
            bin_names=("waybackurls",),
            repo_url="https://github.com/tomnomnom/waybackurls",
            network_note=(
                "Passive: queries the Wayback Machine CDX API for all "
                "archived URLs of the target and its subdomains; subdomains "
                "are extracted from URL hostnames. The target domain is "
                "sent to web.archive.org."
            ),
            install_commands={
                "brew": "brew install waybackurls",
                "go": "go install github.com/tomnomnom/waybackurls@latest",
                "manual": (
                    "Download a release binary from "
                    "https://github.com/tomnomnom/waybackurls/releases "
                    + _bin_hint(bin_dir)
                ),
            },
        ),
        "dnsx_reverse": ToolSpec(
            name="dnsx_reverse",
            label="dnsx (Reverse DNS)",
            # No argv template: the run is built per-job in run_rev_dns
            # (one dnsx -ptr call over all selected IPs via stdin).
            argv=[],
            timeout=300,
            bin_names=("dnsx",),
            repo_url="https://github.com/projectdiscovery/dnsx",
            input_mode="ips",
            network_note=(
                "Active: queries PTR (reverse DNS) records for each selected "
                "IP with `dnsx -ptr` against a set of public resolvers "
                "(built-in: Cloudflare, Google, Quad9, OpenDNS, AdGuard, "
                "Hetzner; override with your own comma-separated list). "
                "Found FQDNs are imported as discovered subdomains; IPs "
                "without a PTR record yield nothing."
            ),
            install_commands={
                "brew": "brew install dnsx",
                "go": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
                "manual": (
                    "Download a release binary from "
                    "https://github.com/projectdiscovery/dnsx/releases "
                    + _bin_hint(bin_dir)
                ),
            },
        ),
    }


def _extra_bin_dirs() -> list[Path]:
    """Common user-install locations for binaries (e.g. `go install`).

    Probed only after the workspace bin dir and PATH, so these locations
    never shadow a binary found in either of those scopes.
    """
    seen: set[Path] = set()
    dirs: list[Path] = []
    home = Path.home()
    gopath = os.environ.get("GOPATH", "").strip()
    candidates = (
        home / "go" / "bin",
        Path(gopath).expanduser() / "bin" if gopath else None,
        home / "bin",
    )
    for d in candidates:
        if d is None:
            continue
        try:
            d = d.expanduser().resolve()
        except OSError:
            continue
        if d in seen:
            continue
        seen.add(d)
        if d.is_dir():
            dirs.append(d)
    return dirs


def find_tool(name: str, spec: ToolSpec, bin_dir: Path | None = None) -> Path | None:
    """Locate the tool binary: workspace bin dir first, then PATH, then
    common user-install locations (e.g. `go install` into ~/go/bin).

    Tries every known binary name (spec.bin_names, in priority order) in each
    scope, so a user-provided binary in bin_dir always wins over system PATH.
    """
    names = spec.bin_names or (spec.name,)
    if bin_dir:
        for n in names:
            candidate = bin_dir / n
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    for n in names:
        found = shutil.which(n)
        if found:
            return Path(found)
    for d in _extra_bin_dirs():
        for n in names:
            candidate = d / n
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    return None


_version_cache: dict = {}


def tool_version(path: Path) -> str:
    """Best-effort version string, cached per binary path + mtime."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return ""
    key = str(path)
    cached = _version_cache.get(key)
    if cached and cached[0] == mtime:
        return cached[1]
    version = ""
    for flag in ("-version", "--version"):
        try:
            r = subprocess.run(
                [str(path), flag],
                capture_output=True,
                text=True,
                timeout=10,
                start_new_session=True,
            )
        except Exception:
            continue
        out = (r.stdout or "") + (r.stderr or "")
        m = VERSION_RE.search(out)
        if m:
            version = m.group(1)
            break
    _version_cache[key] = (mtime, version)
    return version


def validate_target(target: str) -> str:
    t = (target or "").strip().lower().strip(".")
    if not t:
        raise ValueError("target is required")
    if len(t) > 253:
        raise ValueError("target too long (max 253 chars)")
    if not TARGET_RE.match(t):
        raise ValueError("invalid target: expected a domain like example.com")
    return t


def validate_wordlist(value: str) -> str:
    """Validate a wordlist reference: an http(s) URL or an existing local file.

    The value becomes a single argv element (no shell), so the checks here
    are for typos and missing files. URL wordlists are downloaded to a temp
    file by _materialize_wordlist before the tool runs (gobuster only reads
    local files).
    """
    v = (value or "").strip()
    if not v:
        raise ValueError("wordlist is required: enter a URL or a local file path")
    if len(v) > 2048:
        raise ValueError("wordlist reference too long (max 2048 chars)")
    if re.search(r"[\s;&|`$<>()]", v):
        raise ValueError("wordlist may not contain whitespace or shell metacharacters")
    if v.lower().startswith(("http://", "https://")):
        return v
    p = Path(v).expanduser()
    if not p.is_file():
        raise ValueError(f"wordlist file not found: {p}")
    return str(p)


# URL wordlists: the tool binaries read local files only, so HTTP(S)
# wordlists are downloaded to a temp file first. Downloads are cached per
# URL for a short TTL so a multi-target job fetches the list once.
_WORDLIST_MAX_BYTES = 20 * 1024 * 1024
_WORDLIST_URL_TTL = 3600.0
_WORDLIST_CACHE: dict[str, tuple[str, float]] = {}
_WORDLIST_CACHE_LOCK = threading.Lock()


def _materialize_wordlist(url: str) -> str:
    """Download a wordlist URL to a temp file and return its local path.

    Honors RECONBUBBLE_PROXY for https URLs (see netproxy). Raises
    ValueError when the download fails or the payload is unusable.
    """
    now = time.monotonic()
    with _WORDLIST_CACHE_LOCK:
        hit = _WORDLIST_CACHE.get(url)
        if hit and now - hit[1] < _WORDLIST_URL_TTL and Path(hit[0]).is_file():
            return hit[0]
        stale = hit[0] if hit else None
    try:
        if netproxy.proxy_settings() and url.lower().startswith("https://"):
            text = netproxy.https_get(
                url,
                timeout=60,
                headers={"User-Agent": "Mozilla/5.0 (ReconBubble)"},
                max_bytes=_WORDLIST_MAX_BYTES,
            )
            data = text.encode("utf-8")
        else:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (ReconBubble)"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read(_WORDLIST_MAX_BYTES + 1)
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(
            f"could not download wordlist {url}: {str(e).strip()[:200]}"
        )
    if len(data) > _WORDLIST_MAX_BYTES:
        raise ValueError("wordlist too large (max 20 MB)")
    if not data.strip():
        raise ValueError(f"wordlist download was empty: {url}")
    if data.lstrip()[:1] == b"<":
        raise ValueError(f"wordlist download looks like an HTML page: {url}")
    fd, path = tempfile.mkstemp(prefix="reconbubble_wordlist_", suffix=".txt")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    with _WORDLIST_CACHE_LOCK:
        _WORDLIST_CACHE[url] = (path, now)
    if stale:
        try:
            os.unlink(stale)
        except OSError:
            pass
    return path


def extract_fqdns(output: str, target: str) -> list:
    """Unique FQDNs from tool output that equal or are under the target."""
    found = []
    seen = set()
    suffix = "." + target
    for line in (output or "").splitlines():
        for m in FQDN_RE.finditer(line):
            cand = m.group(1).lower().rstrip(".")
            if (cand == target or cand.endswith(suffix)) and cand not in seen:
                seen.add(cand)
                found.append(cand)
    return found


# ---- API key support -------------------------------------------------------
#
# subfinder: custom provider config via SUBFINDER_PROVIDER_CONFIG env var.
# theHarvester: no env var for keys -- it reads $HOME/.theHarvester/api-keys.yaml
# first, so we run it with an isolated HOME containing a generated file.

# Fallback lists, used when the installed tools can't be introspected.
# (Match subfinder v2.14.0 / theHarvester 4.x as shipped on common distros.)
# subfinder: only providers whose KeyRequirement is Required/Optional accept
# keys; the rest (crtsh, digitorus, ...) ignore any key given to them.
_SUBFINDER_DEFAULT_PROVIDERS = (
    "alienvault", "bevigil", "bufferover", "builtwith", "c99",
    "censys", "certspotter", "chaos", "chinaz", "digitalyama",
    "dnsdb", "dnsdumpster", "dnsrepo", "domainsproject", "driftnet",
    "fofa", "fullhunt", "github", "hackertarget", "intelx",
    "leakix", "merklemap", "netlas", "onyphe", "profundis",
    "pugrecon", "quake", "reconeer", "redhuntlabs", "robtex",
    "rsecloud", "securitytrails", "shodan", "submd", "threatbook",
    "urlscan", "virustotal", "whoisxmlapi", "windvane", "zoomeyeapi",
)

_THEHARVESTER_DEFAULT_SOURCES = {
    "bevigil": ["key"],
    "bing": ["key"],
    "bufferoverun": ["key"],
    "builtwith": ["key"],
    "censys": ["id", "secret"],
    "criminalip": ["key"],
    "dehashed": ["key"],
    "dnsdumpster": ["key"],
    "fullhunt": ["key"],
    "github": ["key"],
    "haveibeenpwned": ["key"],
    "hunter": ["key"],
    "hunterhow": ["key"],
    "intelx": ["key"],
    "leaklookup": ["key"],
    "netlas": ["key"],
    "onyphe": ["key"],
    "pentestTools": ["key"],
    "projectDiscovery": ["key"],
    "rocketreach": ["key"],
    "securityscorecard": ["key"],
    "securityTrails": ["key"],
    "shodan": ["key"],
    "tomba": ["key", "secret"],
    "venacus": ["key"],
    "virustotal": ["key"],
    "whoisxml": ["key"],
    "zoomeye": ["key"],
}


def _load_yaml_dict(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(errors="ignore")) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _theharvester_template_candidates() -> list:
    cands = [
        Path.home() / ".theHarvester" / "api-keys.yaml",
        Path("/etc/theHarvester/api-keys.yaml"),
    ]
    try:
        import theHarvester

        pkg = Path(theHarvester.__file__).parent
        cands += [pkg / "data" / "api-keys.yaml", pkg / "api-keys.yaml"]
    except Exception:
        pass
    return cands


def theharvester_key_sources() -> dict:
    """{source: [fields]} for the installed theHarvester (fallback: built-in)."""
    for p in _theharvester_template_candidates():
        try:
            if not p.is_file():
                continue
            ak = _load_yaml_dict(p).get("apikeys")
            if isinstance(ak, dict) and ak:
                out = {}
                for k, v in ak.items():
                    fields = sorted(str(f) for f in (v or {}).keys()) if isinstance(v, dict) else []
                    out[str(k)] = fields or ["key"]
                # Keep any built-in sources the installed template lacks.
                for k, v in _THEHARVESTER_DEFAULT_SOURCES.items():
                    out.setdefault(str(k), list(v))
                return out
        except Exception:
            continue
    return {k: list(v) for k, v in _THEHARVESTER_DEFAULT_SOURCES.items()}


_subfinder_ls_cache: set | None = None


def _subfinder_ls_key_providers() -> set:
    """Providers the installed subfinder accepts keys for (via `subfinder -ls`).

    Lines ending in '*' (required key) or '~' (optional key). Cached per
    process; empty set when subfinder is missing or fails (caller falls
    back to the built-in list).
    """
    global _subfinder_ls_cache
    if _subfinder_ls_cache is not None:
        return _subfinder_ls_cache
    names: set = set()
    exe = shutil.which("subfinder")
    if exe:
        try:
            out = subprocess.run(
                [exe, "-ls", "-duc", "-nc"],
                capture_output=True, text=True, timeout=15,
            ).stdout
            for line in out.splitlines():
                parts = line.strip().rsplit(" ", 1)
                if len(parts) == 2 and parts[1] in ("*", "~") and parts[0]:
                    names.add(parts[0].strip().lower())
        except Exception:
            names = set()
    _subfinder_ls_cache = names
    return names


def subfinder_provider_names() -> list:
    """Provider names that accept API keys in the installed subfinder.

    Prefers live `subfinder -ls` output (so it tracks the installed
    version); falls back to the built-in v2.14.0 list, and always unions
    in the user's provider config so custom providers keep working.
    """
    names = set(_subfinder_ls_key_providers() or _SUBFINDER_DEFAULT_PROVIDERS)
    p = Path.home() / ".config" / "subfinder" / "provider-config.yaml"
    if p.is_file():
        for k in _load_yaml_dict(p).keys():
            k = str(k).strip().lower()
            if k:
                names.add(k)
    return sorted(names)


def tool_key_registry() -> dict:
    """tool -> {key_name: [fields]} (legacy per-tool view; kept for compat)."""
    return {
        "subfinder": {n: ["key"] for n in subfinder_provider_names()},
        "theharvester": theharvester_key_sources(),
    }


# ---- Service-based API keys -----------------------------------------------
#
# A "service" is a credential provider (shodan, censys, ...). One set of values
# is stored per service and fanned out to every tool that consumes it, in that
# tool's own source name and field layout. Most services need a single "key";
# a few need more (censys, tomba) and may map differently per tool.
#
# Catalog entry: {fields: [..], tools: {tool: {source, map}}}. `map` is
# {service_field: tool_field}; for single-key services it is the identity map.

def _svc(fields, *tool_specs) -> dict:
    """Build one catalog entry.

    Each tool_spec is either "tool:source" (identity field map, for single-key
    services) or a (tool, source, {service_field: tool_field}) tuple.
    """
    tools = {}
    for spec in tool_specs:
        if isinstance(spec, str):
            tool, source = spec.split(":", 1)
            tools[tool] = {"source": source, "map": {f: f for f in fields}}
        else:
            tool, source, fmap = spec
            tools[tool] = {"source": source, "map": dict(fmap)}
    return {"fields": [str(f) for f in fields], "tools": tools}


# (canonical service, [fields], *tool_specs)
_SERVICE_TABLE = [
    # shared single-key services
    ("shodan", ["key"], "subfinder:shodan", "theharvester:shodan"),
    ("virustotal", ["key"], "subfinder:virustotal", "theharvester:virustotal"),
    ("github", ["key"], "subfinder:github", "theharvester:github"),
    ("bevigil", ["key"], "subfinder:bevigil", "theharvester:bevigil"),
    ("builtwith", ["key"], "subfinder:builtwith", "theharvester:builtwith"),
    ("fullhunt", ["key"], "subfinder:fullhunt", "theharvester:fullhunt"),
    ("netlas", ["key"], "subfinder:netlas", "theharvester:netlas"),
    ("onyphe", ["key"], "subfinder:onyphe", "theharvester:onyphe"),
    ("intelx", ["key"], "subfinder:intelx", "theharvester:intelx"),
    ("dnsdumpster", ["key"], "subfinder:dnsdumpster", "theharvester:dnsdumpster"),
    ("securitytrails", ["key"], "subfinder:securitytrails", "theharvester:securityTrails"),
    ("bufferover", ["key"], "subfinder:bufferover", "theharvester:bufferoverun"),
    ("whoisxml", ["key"], "subfinder:whoisxmlapi", "theharvester:whoisxml"),
    ("zoomeye", ["key"], "subfinder:zoomeyeapi", "theharvester:zoomeye"),
    # shared, per-tool field layout differs
    ("censys", ["id", "secret", "pattern"],
     ("subfinder", "censys", {"pattern": "key"}),
     ("theharvester", "censys", {"id": "id", "secret": "secret"})),
    # subfinder-only
    ("alienvault", ["key"], "subfinder:alienvault"),
    ("c99", ["key"], "subfinder:c99"),
    ("certspotter", ["key"], "subfinder:certspotter"),
    ("chaos", ["key"], "subfinder:chaos"),
    ("chinaz", ["key"], "subfinder:chinaz"),
    ("digitalyama", ["key"], "subfinder:digitalyama"),
    ("dnsdb", ["key"], "subfinder:dnsdb"),
    ("dnsrepo", ["key"], "subfinder:dnsrepo"),
    ("domainsproject", ["key"], "subfinder:domainsproject"),
    ("driftnet", ["key"], "subfinder:driftnet"),
    ("fofa", ["key"], "subfinder:fofa"),
    ("hackertarget", ["key"], "subfinder:hackertarget"),
    ("leakix", ["key"], "subfinder:leakix"),
    ("merklemap", ["key"], "subfinder:merklemap"),
    ("profundis", ["key"], "subfinder:profundis"),
    ("pugrecon", ["key"], "subfinder:pugrecon"),
    ("quake", ["key"], "subfinder:quake"),
    ("reconeer", ["key"], "subfinder:reconeer"),
    ("redhuntlabs", ["key"], "subfinder:redhuntlabs"),
    ("robtex", ["key"], "subfinder:robtex"),
    ("rsecloud", ["key"], "subfinder:rsecloud"),
    ("submd", ["key"], "subfinder:submd"),
    ("threatbook", ["key"], "subfinder:threatbook"),
    ("urlscan", ["key"], "subfinder:urlscan"),
    ("windvane", ["key"], "subfinder:windvane"),
    # theHarvester-only
    ("bing", ["key"], "theharvester:bing"),
    ("criminalip", ["key"], "theharvester:criminalip"),
    ("dehashed", ["key"], "theharvester:dehashed"),
    ("haveibeenpwned", ["key"], "theharvester:haveibeenpwned"),
    ("hunter", ["key"], "theharvester:hunter"),
    ("hunterhow", ["key"], "theharvester:hunterhow"),
    ("leaklookup", ["key"], "theharvester:leaklookup"),
    ("pentesttools", ["key"], "theharvester:pentestTools"),
    ("projectdiscovery", ["key"], "theharvester:projectDiscovery"),
    ("rocketreach", ["key"], "theharvester:rocketreach"),
    ("securityscorecard", ["key"], "theharvester:securityscorecard"),
    ("tomba", ["key", "secret"],
     ("theharvester", "tomba", {"key": "key", "secret": "secret"})),
    ("venacus", ["key"], "theharvester:venacus"),
]

SERVICE_CATALOG = {
    name: _svc(fields, *specs) for name, fields, *specs in _SERVICE_TABLE
}

# Reverse lookups: source name in a tool -> (service, {tool_field: service_field})
_reverse_map_cache: dict = {}


def _reverse_map(tool: str) -> dict:
    if tool not in _reverse_map_cache:
        rev: dict = {}
        for service, entry in SERVICE_CATALOG.items():
            t = entry["tools"].get(tool)
            if not t:
                continue
            inv = {tf: sf for sf, tf in t["map"].items()}
            rev[t["source"]] = (service, inv)
        _reverse_map_cache[tool] = rev
    return _reverse_map_cache[tool]


def keys_for_tool(tool: str, service_keys: dict) -> dict:
    """Map stored service keys to one tool's {source: {field: value}}.

    service_keys: {service: {field: value}}. Returns the shape build_tool_env
    expects, dropping services the tool doesn't use or with no stored values.
    """
    out: dict = {}
    for service, fields in (service_keys or {}).items():
        entry = SERVICE_CATALOG.get(str(service))
        if not entry:
            continue
        tmap = entry["tools"].get(tool)
        if not tmap:
            continue
        mapped = {}
        for svc_field, tool_field in tmap["map"].items():
            v = (fields or {}).get(svc_field)
            if v:
                mapped[str(tool_field)] = str(v)
        if mapped:
            out[tmap["source"]] = mapped
    return out


def service_key_registry() -> dict:
    """service -> {fields, tools: {tool: source}} for the API-keys UI."""
    return {
        name: {
            "fields": entry["fields"],
            "tools": {tool: t["source"] for tool, t in entry["tools"].items()},
        }
        for name, entry in sorted(SERVICE_CATALOG.items())
    }


def parse_tool_config(content: str) -> dict:
    """Parse a pasted tool config file into {service: {field: value}}.

    Auto-detects the format:
      * theHarvester api-keys.yaml: top-level `apikeys:` -> {source: {field: value}}
      * subfinder provider-config.yaml: flat {source: [value, ...]}

    Returns {tool, services, skipped} where skipped lists source names present
    in the file but not in the catalog (no canonical service to fill).
    """
    try:
        data = yaml.safe_load(content)
    except Exception as e:
        raise ValueError(f"not valid YAML: {e}")
    if not isinstance(data, dict) or not data:
        raise ValueError("expected a non-empty YAML mapping")
    if isinstance(data.get("apikeys"), dict):
        tool, sources = "theharvester", data["apikeys"]
    else:
        tool, sources = "subfinder", data
    if not isinstance(sources, dict) or not sources:
        raise ValueError(f"no {tool} sources found in the config")

    rev = _reverse_map(tool)
    services: dict = {}
    skipped: list = []
    for source, raw in sources.items():
        if tool == "theharvester":
            if not isinstance(raw, dict):
                continue
            nonempty = {
                str(f): str(v) for f, v in raw.items()
                if v not in (None, "")
            }
            if not nonempty:
                continue
            hit = rev.get(str(source))
            if not hit:
                skipped.append(str(source))
                continue
            service, inv = hit
            svc_fields = {inv[tf]: v for tf, v in nonempty.items() if tf in inv}
        else:  # subfinder: positional list of values
            if isinstance(raw, str):
                raw = [raw]
            if not isinstance(raw, list):
                continue
            vals = [str(v) for v in raw if v not in (None, "")]
            if not vals:
                continue
            hit = rev.get(str(source).strip().lower())
            if not hit:
                skipped.append(str(source))
                continue
            service, inv = hit
            svc_fields = {}
            for i, v in enumerate(vals):
                items = list(inv.items())
                if i < len(items):
                    svc_fields[items[i][1]] = v
        if svc_fields:
            services[service] = svc_fields
    return {"tool": tool, "services": services, "skipped": skipped}


def _cleanup_tmp(paths: list) -> None:
    for p in paths:
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.exists():
                p.unlink()
        except Exception:
            pass


def build_tool_env(spec: ToolSpec, keys: dict) -> tuple:
    """Build extra env vars + temp config files for a tool run.

    keys: {key_name: {field: value}}. Returns (env_overrides, tmp_roots) where
    tmp_roots are paths to delete after the run (files or directories).
    """
    extra_env: dict = {}
    tmp_roots: list = []
    keys = {
        name: {f: v for f, v in (fields or {}).items() if v}
        for name, fields in (keys or {}).items()
    }
    if not keys:
        return extra_env, tmp_roots
    if spec.name == "subfinder":
        base: dict = {}
        user_cfg = Path.home() / ".config" / "subfinder" / "provider-config.yaml"
        if user_cfg.is_file():
            for k, v in _load_yaml_dict(user_cfg).items():
                if v is None:
                    base[str(k)] = []
                elif isinstance(v, list):
                    base[str(k)] = [str(x) for x in v if x is not None]
                else:
                    base[str(k)] = [str(v)]
        for name in subfinder_provider_names():
            base.setdefault(name, [])
        for name, fields in keys.items():
            vals = [str(v) for v in fields.values()]
            if vals:
                base[name] = vals
        fd, cfg = tempfile.mkstemp(suffix=".yaml", prefix="subfinder_provider_")
        os.close(fd)
        Path(cfg).write_text(yaml.safe_dump(base, sort_keys=True), encoding="utf-8")
        os.chmod(cfg, 0o600)
        extra_env["SUBFINDER_PROVIDER_CONFIG"] = cfg
        tmp_roots.append(Path(cfg))
    elif spec.name == "theharvester":
        template: dict = {}
        for p in _theharvester_template_candidates():
            try:
                if p.is_file():
                    ak = _load_yaml_dict(p).get("apikeys")
                    if isinstance(ak, dict) and ak:
                        template = ak
                        break
            except Exception:
                continue
        merged = {}
        for k, v in template.items():
            merged[str(k)] = dict(v) if isinstance(v, dict) else {}
        for name, fields in keys.items():
            slot = merged.setdefault(str(name), {})
            for f, v in fields.items():
                slot[str(f)] = str(v)
        home = Path(tempfile.mkdtemp(prefix="tharv_home_"))
        cfgdir = home / ".theHarvester"
        cfgdir.mkdir()
        (cfgdir / "api-keys.yaml").write_text(
            yaml.safe_dump({"apikeys": merged}, sort_keys=True), encoding="utf-8"
        )
        os.chmod(cfgdir / "api-keys.yaml", 0o600)
        # Preserve a user's proxy config so isolated HOME doesn't lose it.
        try:
            user_proxies = Path.home() / ".theHarvester" / "proxies.yaml"
            if user_proxies.is_file():
                shutil.copy2(user_proxies, cfgdir / "proxies.yaml")
        except Exception:
            pass
        extra_env["HOME"] = str(home)
        tmp_roots.append(home)
    return extra_env, tmp_roots


def tool_config_preview(spec: ToolSpec, keys: dict) -> dict:
    """The config file the tool would read at a run, with `keys` applied.

    Uses the exact code path of a real run (build_tool_env), reads back the
    generated file, then cleans up. When no keys are stored, returns the
    default file the tool reads instead.

    Returns {path, content, generated}: `path` is the canonical location the
    tool reads from (a temp file is written there at run time when
    `generated` is true).
    """
    env, tmp_roots = build_tool_env(spec, keys)
    try:
        if spec.name == "subfinder":
            default = Path.home() / ".config" / "subfinder" / "provider-config.yaml"
            p = Path(env.get("SUBFINDER_PROVIDER_CONFIG") or "")
            if p.is_file():
                return {
                    "path": str(default),
                    "content": p.read_text(errors="ignore"),
                    "generated": True,
                }
            return {
                "path": str(default),
                "content": default.read_text(errors="ignore") if default.is_file() else "",
                "generated": False,
            }
        default = Path.home() / ".theHarvester" / "api-keys.yaml"
        home = tmp_roots[0] if tmp_roots else None
        if home is not None:
            p = home / ".theHarvester" / "api-keys.yaml"
            return {
                "path": str(default),
                "content": p.read_text(errors="ignore"),
                "generated": True,
            }
        for cand in _theharvester_template_candidates():
            if cand.is_file():
                return {
                    "path": str(cand),
                    "content": cand.read_text(errors="ignore"),
                    "generated": False,
                }
        return {"path": str(default), "content": "", "generated": False}
    finally:
        _cleanup_tmp(tmp_roots)


def _kill_process_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_tool(
    spec: ToolSpec,
    target: str,
    bin_dir: Path | None = None,
    keys: dict | None = None,
    wordlist: str | None = None,
) -> dict:
    """Run a registered tool against a validated target (blocking).

    keys: optional {key_name: {field: value}} API keys, injected via the
    tool's config mechanism (see build_tool_env).
    wordlist: optional wordlist reference (http(s) URL or local path) for
    the {wordlist} argv slot; falls back to spec.wordlist_default.

    Returns {ok, fqdns, raw, raw_error, exit_code, error}.
    """
    target = validate_target(target)
    bin_path = find_tool(spec.name, spec, bin_dir)
    if not bin_path:
        return {"ok": False, "error": f"{spec.label} is not installed"}
    wordlist_value = ""
    if any("{wordlist}" in part for part in spec.argv):
        try:
            wordlist_value = validate_wordlist(wordlist or spec.wordlist_default)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        if wordlist_value.lower().startswith(("http://", "https://")):
            try:
                wordlist_value = _materialize_wordlist(wordlist_value)
            except ValueError as e:
                return {"ok": False, "error": str(e)}
    argv = [
        part.format(bin=str(bin_path), target=target, wordlist=wordlist_value)
        for part in spec.argv
    ]
    extra_env, tmp_roots = build_tool_env(spec, keys or {})
    env = dict(os.environ)
    env.update(extra_env)
    try:
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                start_new_session=True,
            )
        except Exception as e:
            return {"ok": False, "error": f"failed to start {spec.label}: {e}"}
        timed_out = False
        try:
            out, err = proc.communicate(timeout=spec.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(proc)
            try:
                out, err = proc.communicate(timeout=10)
            except Exception:
                out, err = "", ""
        # Extract from the full stream (URL-listing tools like gau can emit
        # far more than RAW_CAP of output); only the stored raw is capped.
        fqdns = extract_fqdns(out or "", target)
        out = (out or "")[:RAW_CAP]
        err = (err or "")[:RAW_CAP]
        if timed_out:
            return {
                "ok": False,
                "error": f"{spec.label} timed out after {spec.timeout}s",
                "fqdns": fqdns,
                "raw": out,
                "raw_error": err,
                "exit_code": None,
            }
        if proc.returncode != 0 and not fqdns:
            return {
                "ok": False,
                "error": f"{spec.label} exited with code {proc.returncode}: "
                         f"{err.strip()[:500] or 'no output'}",
                "fqdns": [],
                "raw": out,
                "raw_error": err,
                "exit_code": proc.returncode,
            }
        return {
            "ok": True,
            "fqdns": fqdns,
            "raw": out,
            "raw_error": err,
            "exit_code": proc.returncode,
            "error": "",
        }
    finally:
        _cleanup_tmp(tmp_roots)


def run_cero(spec: ToolSpec, hosts: list, ports: str, bin_dir: Path | None = None) -> dict:
    """Run cero over a list of hosts (domains/IPs/CIDRs) fed via stdin.

    cero reads hosts from stdin and scrapes SAN domain names from each host's
    TLS certificate on the given ports. Returns the same shape as run_tool.
    """
    hosts = [h for h in (hosts or []) if h]
    if not hosts:
        return {"ok": False, "error": "no hosts to probe"}
    ports = (ports or "").strip() or _CERO_DEFAULT_PORTS
    bin_path = find_tool(spec.name, spec, bin_dir)
    if not bin_path:
        return {"ok": False, "error": f"{spec.label} is not installed"}
    argv = [str(bin_path), "-d", "-c", "1000", "-p", ports]
    stdin_data = "\n".join(hosts) + "\n"
    try:
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except Exception as e:
            return {"ok": False, "error": f"failed to start {spec.label}: {e}"}
        timed_out = False
        try:
            out, err = proc.communicate(input=stdin_data, timeout=spec.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(proc)
            try:
                out, err = proc.communicate(timeout=10)
            except Exception:
                out, err = "", ""
        # Parse the full stream (certs with many SANs can exceed RAW_CAP);
        # only the stored raw is capped.
        full = out or ""
        out = full[:RAW_CAP]
        err = (err or "")[:RAW_CAP]
        # With -d, cero prints one clean domain per line on stdout; parse leniently.
        seen: set = set()
        fqdns: list = []
        for line in full.splitlines():
            for m in FQDN_RE.finditer(line):
                cand = m.group(1).lower().rstrip(".")
                if cand not in seen:
                    seen.add(cand)
                    fqdns.append(cand)
        if timed_out:
            return {
                "ok": False,
                "error": f"{spec.label} timed out after {spec.timeout}s",
                "fqdns": fqdns,
                "raw": out,
                "raw_error": err,
                "exit_code": None,
            }
        if proc.returncode != 0 and not fqdns:
            return {
                "ok": False,
                "error": f"{spec.label} exited with code {proc.returncode}: "
                         f"{err.strip()[:500] or 'no output'}",
                "fqdns": [],
                "raw": out,
                "raw_error": err,
                "exit_code": proc.returncode,
            }
        return {
            "ok": True,
            "fqdns": fqdns,
            "raw": out,
            "raw_error": err,
            "exit_code": proc.returncode,
            "error": "",
        }
    except Exception as e:
        return {
            "ok": False,
            "error": f"{spec.label} failed: {e}",
            "fqdns": [],
            "raw": "",
            "raw_error": "",
            "exit_code": None,
        }


# ---- VHost brute-force (gobuster vhost against ip:port sockets) -----------
#
# Some services sit on ip:port sockets without public DNS. gobuster's vhost
# mode brute-forces virtual hostnames against a single HTTP(S) endpoint. We
# run one gobuster pass per socket with four layers of filtering:
#   1. baseline: probe the socket with random Host headers and take the
#      dominant (status, size) signature -- the catch-all response;
#   2. gobuster's own baseline comparison (its -q candidates already differ
#      from the IP-hosted response);
#   3. in-process filter: drop candidates whose (status, size) matches our
#      baseline signature (catch-all responses gobuster's baseline missed);
#   4. verification: GET / with Host=candidate vs Host=random; identical
#      status + body SHA-256 means catch-all, drop.
# Result lines are "<fqdn> <ip:port> <status> <size>" (FQDN first) so
# import_subdomains and the discoveries artifact parser accept them.

_VHOST_HTTPS_PORTS = frozenset({443, 8443, 9443, 10443})
_VHOST_PER_SOCKET_TIMEOUT = 240  # seconds; generous for large wordlists
_VHOST_BASELINE_PROBES = 5
_VHOST_PROBE_TIMEOUT = 5.0
_VHOST_PROBE_READ_CAP = 512 * 1024
_VHOST_EXCLUDE_STATUS = "500,502,503,504"
# Verified against gobuster 3.8.2 -q output: "<name> Status: 200 [Size: 242]"
_VHOST_LINE_RE = re.compile(
    r"^(?P<name>\S+)\s+Status:\s+(?P<status>\d{3})\s+\[Size:\s+(?P<size>\d+)\]"
)


def _vhost_empty(error: str = "") -> dict:
    return {
        "ok": False,
        "lines": [],
        "raw": "",
        "raw_error": "",
        "exit_code": None,
        "error": error,
    }


def validate_socket(value: str) -> str:
    """Validate and normalize an 'ip:port' socket (IPv4 or IPv6).

    Accepts '1.2.3.4:8080', '::1:80', or '[::1]:80'. Returns the canonical
    'ip:port' form.
    """
    v = (value or "").strip().lower()
    if not v:
        raise ValueError("socket is required")
    if len(v) > 256:
        raise ValueError("socket too long (max 256 chars)")
    if re.search(r"[\s;&|`$<>()]", v):
        raise ValueError("socket may not contain whitespace or shell metacharacters")
    if v.startswith("["):
        m = re.fullmatch(r"\[([0-9a-f:.]+)\]:(\d{1,5})", v)
        if not m:
            raise ValueError(f"invalid socket (expected [ip]:port): {value!r}")
        ip, port_s = m.group(1), m.group(2)
    else:
        if ":" not in v:
            raise ValueError(f"invalid socket (expected ip:port): {value!r}")
        ip, port_s = v.rsplit(":", 1)
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"invalid IP address in socket: {value!r}")
    try:
        port = int(port_s)
    except ValueError:
        raise ValueError(f"invalid port in socket: {value!r}")
    if not (0 < port < 65536):
        raise ValueError(f"port out of range (1-65535): {value!r}")
    return f"{ip_obj}:{port}"


def _vhost_scheme_for_port(port: int) -> str:
    return "https" if port in _VHOST_HTTPS_PORTS else "http"


def _http_probe(ip: str, port: int, host_header: str, path: str = "/"):
    """One unverified GET with a spoofed Host header. No redirects.

    Mirrors gobuster's -k flag: TLS certificate verification is disabled.
    Returns (status, body_size, body_bytes) or None when the probe fails.
    Bodies longer than _VHOST_PROBE_READ_CAP are truncated (size is the
    number of bytes read, capped at _VHOST_PROBE_READ_CAP + 1).
    """
    conn = None
    try:
        if _vhost_scheme_for_port(port) == "https":
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(
                ip, port, timeout=_VHOST_PROBE_TIMEOUT, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=_VHOST_PROBE_TIMEOUT)
        conn.request(
            "GET",
            path,
            headers={
                "Host": host_header,
                "User-Agent": "Mozilla/5.0 (ReconBubble vhost probe)",
                "Accept": "*/*",
            },
        )
        resp = conn.getresponse()
        body = resp.read(_VHOST_PROBE_READ_CAP + 1)
        return resp.status, len(body), body
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _vhost_baseline(ip: str, port: int):
    """Probe the socket with random Host headers; return the dominant
    (status, size) signature (the catch-all response), or None when no
    probe connected."""
    sigs = []
    for i in range(_VHOST_BASELINE_PROBES):
        r = _http_probe(ip, port, f"probe{i}.reconbubble.invalid")
        if r:
            sigs.append((r[0], r[1]))
    if not sigs:
        return None
    return Counter(sigs).most_common(1)[0][0]


def run_vhost_socket(spec: ToolSpec, sock: str, wordlist_file: str,
                     bin_dir: Path | None = None) -> dict:
    """Brute-force vhost names against a single ip:port socket.

    Returns {ok, lines, raw, raw_error, exit_code, error}; each line in
    `lines` is "<fqdn> <ip:port> <status> <size>" for a verified hit.
    """
    try:
        sock = validate_socket(sock)
    except ValueError as e:
        return _vhost_empty(f"invalid socket: {e}")
    ip, port_s = sock.rsplit(":", 1)
    port = int(port_s)
    bin_path = find_tool("gobuster", spec, bin_dir)
    if not bin_path:
        return _vhost_empty("gobuster is not installed")
    if not Path(wordlist_file).is_file():
        return _vhost_empty(f"wordlist file not found: {wordlist_file}")

    base_sig = _vhost_baseline(ip, port)
    if base_sig is None:
        return _vhost_empty(
            f"socket {sock} did not answer any HTTP probe "
            f"({len(_VHOST_BASELINE_PROBES)} random-Host attempts, "
            f"{_VHOST_PROBE_TIMEOUT:.0f}s timeout)"
        )

    url_host = f"[{ip}]" if ":" in ip else ip
    url = f"{_vhost_scheme_for_port(port)}://{url_host}:{port}"
    argv = [
        str(bin_path), "vhost",
        "-u", url,
        "-w", str(wordlist_file),
        "-t", "50",
        "--timeout", "5s",
        "--exclude-status", _VHOST_EXCLUDE_STATUS,
        "-q", "--ne", "--np", "-k",
    ]
    try:
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except Exception as e:
            return _vhost_empty(f"failed to start gobuster: {e}")
        timed_out = False
        try:
            out, err = proc.communicate(timeout=_VHOST_PER_SOCKET_TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(proc)
            try:
                out, err = proc.communicate(timeout=10)
            except Exception:
                out, err = "", ""
        out = out or ""
        err = (err or "")[:RAW_CAP]

        # Parse candidates from the -q stream; fall back to a bare first
        # token when a line does not match the verified format.
        cands: list = []
        seen: set = set()
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _VHOST_LINE_RE.match(line)
            if m:
                name = m.group("name").lower().rstrip(".")
                status, size = int(m.group("status")), int(m.group("size"))
            else:
                tok = line.split()[0].lower().rstrip(".")
                if not FQDN_RE.fullmatch(tok):
                    continue
                name, status, size = tok, None, None
            if name in seen:
                continue
            seen.add(name)
            cands.append([name, status, size])

        # Drop candidates whose (status, size) matches the baseline
        # signature: catch-all responses gobuster's baseline missed.
        survivors = [
            c for c in cands
            if c[1] is None or (c[1], c[2]) != base_sig
        ]

        # Verification pass: candidate vs random Host must differ in
        # status or body hash, otherwise it is a catch-all.
        lines: list = []
        for name, _status, _size in survivors:
            cand = _http_probe(ip, port, name)
            if cand is None:
                continue  # no longer answering
            c_status, c_size, c_body = cand
            rnd = _http_probe(
                ip, port, f"rand{random.randint(0, 2**31 - 1)}.reconbubble.invalid"
            )
            if rnd is not None:
                r_status, _r_size, r_body = rnd
                if (
                    c_status == r_status
                    and hashlib.sha256(c_body).hexdigest()
                    == hashlib.sha256(r_body).hexdigest()
                ):
                    continue  # identical to the catch-all response
            elif (c_status, c_size) == base_sig:
                continue  # random probe failed; matches baseline signature
            lines.append(f"{name} {sock} {c_status} {c_size}")

        if timed_out:
            err_msg = (
                f"gobuster vhost timed out after {_VHOST_PER_SOCKET_TIMEOUT}s "
                f"(kept {len(lines)} verified hits)"
            )
        elif proc.returncode != 0 and not cands:
            err_msg = (
                f"gobuster exited with code {proc.returncode}: "
                f"{err.strip()[:300] or 'no output'}"
            )
        else:
            err_msg = ""
        return {
            "ok": not err_msg,
            "lines": lines,
            "raw": out[:RAW_CAP],
            "raw_error": err,
            "exit_code": None if timed_out else proc.returncode,
            "error": err_msg,
        }
    except Exception as e:
        return _vhost_empty(f"gobuster vhost failed: {e}")


# ---- Reverse DNS (dnsx -ptr over selected IPs) ------------------------------
#
# The old subenum workflow ran, per in-scope IP, `dnsx -ptr` against a set of
# public resolvers and imported whatever FQDNs came back. We replicate that
# with a single dnsx call: all IPs go in via stdin, all resolvers via -r, and
# the -resp output lines ("<ip> [PTR] [fqdn]", ANSI-coloured) are parsed into
# "<fqdn> <ip>" artifact lines (FQDN first, for import_subdomains).

REVDNS_RESOLVERS = (
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "8.8.8.8", "8.8.4.4",            # Google
    "9.9.9.9",                       # Quad9
    "149.112.112.112",               # OpenDNS (Cisco)
    "208.67.222.222", "208.67.220.220",  # OpenDNS (Cisco)
    "94.140.14.14", "94.140.15.15",   # AdGuard
    "8.26.56.26",                    # Hetzner
)
REVDNS_MAX_IPS = 100

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_PTR_LINE_RE = re.compile(r"^(?P<ip>\S+)\s+\[PTR\]\s+\[(?P<fqdn>[^\]]+)\]")


def validate_ip(value: str) -> str:
    """Validate a single IP literal (IPv4 or IPv6) and return its canonical form.

    Domains, CIDR ranges, and anything containing whitespace or shell
    metacharacters are rejected.
    """
    v = (value or "").strip()
    if not v:
        raise ValueError("IP is required")
    if len(v) > 64:
        raise ValueError("IP too long (max 64 chars)")
    if re.search(r"[\s;&|`$<>()]", v):
        raise ValueError("IP may not contain whitespace or shell metacharacters")
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise ValueError(
            "invalid IP address (expected an IPv4/IPv6 literal, not a domain "
            f"or CIDR): {value!r}"
        )


def validate_resolvers(value: str) -> str:
    """Validate a comma-separated resolver list and return its canonical form.

    Blank input means "use the built-in resolver set" (REVDNS_RESOLVERS).
    """
    v = (value or "").strip()
    if not v:
        return ",".join(REVDNS_RESOLVERS)
    if len(v) > 512:
        raise ValueError("resolver list too long (max 512 chars)")
    out: list = []
    seen: set = set()
    for tok in v.split(","):
        ip = validate_ip(tok)
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    if not out:
        raise ValueError("resolver list is empty")
    return ",".join(out)


def _revdns_empty(error: str = "") -> dict:
    return {
        "ok": False,
        "lines": [],
        "raw": "",
        "raw_error": "",
        "exit_code": None,
        "error": error,
    }


def run_rev_dns(spec: ToolSpec, ips: list, resolvers: str, bin_dir: Path | None = None) -> dict:
    """Run dnsx -ptr over a list of IPs fed via stdin.

    All IPs are queried in one process against the given resolver list. Result
    lines are "<fqdn> <ip>" (FQDN first, for import_subdomains); IPs without a
    PTR record produce no line. Returns the same shape as run_vhost_socket
    ({ok, lines, raw, raw_error, exit_code, error}).
    """
    ips = [i for i in (ips or []) if i]
    if not ips:
        return _revdns_empty("no IPs to query")
    resolvers = (resolvers or "").strip() or ",".join(REVDNS_RESOLVERS)
    bin_path = find_tool(spec.name, spec, bin_dir)
    if not bin_path:
        return _revdns_empty(f"{spec.label} is not installed")
    argv = [str(bin_path), "-ptr", "-resp", "-silent", "-r", resolvers]
    stdin_data = "\n".join(ips) + "\n"
    try:
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except Exception as e:
            return _revdns_empty(f"failed to start {spec.label}: {e}")
        timed_out = False
        try:
            out, err = proc.communicate(input=stdin_data, timeout=spec.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(proc)
            try:
                out, err = proc.communicate(timeout=10)
            except Exception:
                out, err = "", ""
        err = (err or "")[:RAW_CAP]
        # dnsx -resp prints "<ip> [PTR] [fqdn]" wrapped in ANSI colour codes.
        clean = _ANSI_RE.sub("", out or "")
        lines: list = []
        seen: set = set()
        for line in clean.splitlines():
            m = _PTR_LINE_RE.match(line.strip())
            if not m:
                continue
            name = m.group("fqdn").strip().lower().rstrip(".")
            if not FQDN_RE.fullmatch(name):
                continue
            entry = f"{name} {m.group('ip')}"
            if entry in seen:
                continue
            seen.add(entry)
            lines.append(entry)
        if timed_out:
            return {
                "ok": False,
                "lines": lines,
                "raw": clean[:RAW_CAP],
                "raw_error": err,
                "exit_code": None,
                "error": (
                    f"{spec.label} timed out after {spec.timeout}s "
                    f"(kept {len(lines)} hits)"
                ),
            }
        if proc.returncode != 0 and not lines:
            return {
                "ok": False,
                "lines": [],
                "raw": clean[:RAW_CAP],
                "raw_error": err,
                "exit_code": proc.returncode,
                "error": (
                    f"{spec.label} exited with code {proc.returncode}: "
                    f"{err.strip()[:500] or 'no output'}"
                ),
            }
        return {
            "ok": True,
            "lines": lines,
            "raw": clean[:RAW_CAP],
            "raw_error": err,
            "exit_code": proc.returncode,
            "error": "",
        }
    except Exception as e:
        return _revdns_empty(f"{spec.label} failed: {e}")


# ---- Built-in (no external binary) tools -----------------------------------
#
# Some "tools" are implemented in-process rather than as user-installed
# binaries. They still return the same {ok, fqdns, raw, raw_error, exit_code,
# error} shape so the job runner, artifact storage, and Discovery Log treat
# them exactly like binary tools.

_WEB_SOURCE_TIMEOUT = 30  # seconds, per source
_WEB_SOURCE_READ_CAP = 2_000_000  # bytes read per source body


def run_web_sources(target: str) -> dict:
    """Built-in passive lookup of crt.sh, crt.name, and urlscan.io.

    Each source is fetched separately and its body passed through extract_fqdns
    (which pulls any FQDN equal-to/under the target out of JSON or HTML alike),
    so one source failing or returning a large body does not truncate or hide
    the others.
    """
    target = validate_target(target)
    sources = {
        "crt.name": f"https://crt.name/v1/search?apex={target}",
        "urlscan.io": (
            f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=10000"
        ),
        "crt.sh": f"https://crt.sh/?q=%25.{target}",
    }
    raw_parts: list = []
    err_parts: list = []
    all_found: list = []
    any_success = False
    for name, url in sources.items():
        try:
            if netproxy.proxy_settings():
                text = netproxy.https_get(
                    url,
                    timeout=_WEB_SOURCE_TIMEOUT,
                    headers={"User-Agent": "Mozilla/5.0 (ReconBubble)"},
                    max_bytes=_WEB_SOURCE_READ_CAP,
                )
            else:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "Mozilla/5.0 (ReconBubble)"}
                )
                with urllib.request.urlopen(
                    req, timeout=_WEB_SOURCE_TIMEOUT
                ) as resp:
                    text = resp.read(_WEB_SOURCE_READ_CAP).decode("utf-8", "ignore")
            found = extract_fqdns(text, target)
            all_found.extend(found)
            any_success = True
            listing = "".join(f"  {f}\n" for f in found) if found else "  (none)\n"
            raw_parts.append(
                f"== {name} == {len(found)} extracted\n{listing}{text[:RAW_CAP]}"
            )
        except Exception as e:
            err_parts.append(f"{name}: {str(e).strip()[:300]}")
    seen: set = set()
    fqdns = [f for f in all_found if not (f in seen or seen.add(f))]
    if fqdns:
        return {
            "ok": True,
            "fqdns": fqdns,
            "raw": "\n\n".join(raw_parts),
            "raw_error": "\n".join(err_parts),
            "exit_code": 0,
            "error": "; ".join(err_parts)[:500] if err_parts else "",
        }
    if any_success:
        # Sources responded but found nothing: a valid empty result, not an error.
        return {
            "ok": True,
            "fqdns": [],
            "raw": "\n\n".join(raw_parts),
            "raw_error": "\n".join(err_parts),
            "exit_code": 0,
            "error": "",
        }
    return {
        "ok": False,
        "fqdns": [],
        "raw": "",
        "raw_error": "\n".join(err_parts),
        "exit_code": None,
        "error": "all web sources failed: " + "; ".join(err_parts)[:400],
    }


def run_builtin(spec: ToolSpec, target: str) -> dict:
    """Dispatch a builtin tool. Returns the same shape as run_tool."""
    if spec.name == "web_sources":
        return run_web_sources(target)
    raise ValueError(f"unknown builtin tool: {spec.name}")
