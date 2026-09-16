"""External recon tool registry and execution.

Tools are user-installed binaries (subfinder, theHarvester). ReconBubble never
downloads or installs them automatically -- the UI only shows install hints.
Execution is locked down: fixed argv templates, strict target validation,
no shell, process-group kill on timeout.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yaml

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
    bin_names: tuple = ()  # binary names to locate, in priority order
    builtin: bool = False  # True = implemented in-process (no external binary)
    input_mode: str = "target"  # "target" (argv {target}) or "hosts_ports" (stdin host list + ports)


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
                    "binary in PATH" + _bin_hint(bin_dir)
                ),
            },
        ),
    }


def find_tool(name: str, spec: ToolSpec, bin_dir: Path | None = None) -> Path | None:
    """Locate the tool binary: workspace bin dir first, then PATH.

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
) -> dict:
    """Run a registered tool against a validated target (blocking).

    keys: optional {key_name: {field: value}} API keys, injected via the
    tool's config mechanism (see build_tool_env).

    Returns {ok, fqdns, raw, raw_error, exit_code, error}.
    """
    target = validate_target(target)
    bin_path = find_tool(spec.name, spec, bin_dir)
    if not bin_path:
        return {"ok": False, "error": f"{spec.label} is not installed"}
    argv = [part.format(bin=str(bin_path), target=target) for part in spec.argv]
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
        out = (out or "")[:RAW_CAP]
        err = (err or "")[:RAW_CAP]
        fqdns = extract_fqdns(out, target)
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
        out = (out or "")[:RAW_CAP]
        err = (err or "")[:RAW_CAP]
        # With -d, cero prints one clean domain per line on stdout; parse leniently.
        seen: set = set()
        fqdns: list = []
        for line in out.splitlines():
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
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (ReconBubble)"}
            )
            with urllib.request.urlopen(req, timeout=_WEB_SOURCE_TIMEOUT) as resp:
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
