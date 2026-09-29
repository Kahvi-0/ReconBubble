"""NSE <script> element parsing and finding derivation from Nmap XML.

Two layers:

- Pure functions: parse_script_element / derive_findings / find_cves.
  No DB or nmap dependency, unit-testable.
- DB glue: upsert_script_result / analyze_nmap_root / reanalyze_artifact.
  Shared between parsers.import_nmap_xml (import time) and the
  `reconbubble nse reanalyze` CLI (backfilling existing artifacts).

Findings are derived entirely offline from the stored scan data:
vulns.Report Risk factors, known script output formats, and a keyword
fallback. No NVD/CVSS or other external lookups.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import Host, NseResult, Service, ServiceFinding

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def find_cves(text: str) -> list[str]:
    """Return sorted unique CVE ids found in the given text."""
    return sorted(set(_CVE_RE.findall(text or "")))


# --- XML parsing -----------------------------------------------------------

def _parse_children(nodes) -> dict | list:
    """Parse a list of child nodes into a dict or list.

    Supports both XML serializations nmap has emitted:
    - current (nmap >= ~7.93, per nmap.dtd): <table [key=...]> containers
      holding nested <table>s and <elem [key=...]> leaves;
    - legacy: <element type="table|string|..."> wrappers.

    Keyed children become dict entries; keyless children become array
    items. If only keyless children are present the result is a list.
    """
    d: dict = {}
    arr: list = []
    for node in nodes:
        if node.tag == "table":
            val = _parse_children(list(node))
            key = node.get("key")
        elif node.tag in ("element", "elem"):
            val = _parse_element(node)
            key = node.get("key")
        else:
            continue
        if key is None:
            arr.append(val)
        else:
            d[key] = val
    return d if d else arr


def _parse_element(el):
    t = (el.get("type") or "string").lower()
    if t in ("table", "array"):
        # Real nmap XML wraps children in <table>; be lenient about both.
        tbl = el.find("table")
        if tbl is not None:
            return _parse_children(list(tbl))
        return _parse_children(list(el))
    if t == "boolean":
        return (el.text or "").strip().lower() == "true"
    if t == "number":
        txt = (el.text or "").strip()
        try:
            return int(txt)
        except ValueError:
            try:
                return float(txt)
            except ValueError:
                return txt
    return el.text or ""


def parse_script_element(el) -> dict:
    """Parse one <script> element into {'name', 'output', 'data'}."""
    return {
        "name": (el.get("id") or "").strip(),
        "output": el.get("output") or "",
        "data": _parse_children(list(el)),
    }


# --- Finding derivation ----------------------------------------------------

def _finding(kind: str, severity: str, title: str, detail: str = "", cves=()) -> dict:
    return {
        "kind": kind,
        "severity": severity if severity in SEVERITY_RANK else "info",
        "title": (title or "").strip()[:255],
        "detail": (detail or "").strip()[:4000],
        "cves": list(dict.fromkeys(cves or [])),
    }


def _risk_to_severity(risk: str) -> str:
    return {"high": "high", "medium": "medium", "low": "low"}.get(
        (risk or "").strip().lower(), "high"
    )


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _scores_to_severity(scores) -> str:
    """Map CVSS base scores (from the table's `scores` field) to severity.

    Handles both bare numbers and the "10.0 (HIGH) (AV:N/...)" strings
    that vulns.Report stores for CVSSv2/v3.
    """
    if not isinstance(scores, dict):
        return ""
    for key in ("CVSS3", "CVSS3 base", "CVSS2", "CVSS2 base", "CVSSv3", "CVSSv2"):
        val = scores.get(key)
        if val is None:
            continue
        m = re.match(r"\s*(\d+(?:\.\d+)?)", str(val))
        if not m:
            continue
        return _score_to_severity(float(m.group(1)))
    return ""


def _lenient_get(d: dict, keys: tuple) -> object:
    """First value in d matching any of the candidate key spellings."""
    for k in keys:
        if k in d:
            return d[k]
    lowered = {str(k).strip().lower(): v for k, v in d.items()}
    for k in keys:
        v = lowered.get(k.strip().lower())
        if v is not None:
            return v
    return None


def _vulns_report_findings(data, output: str) -> list[dict]:
    """Findings for scripts that report through vulns.Report (table form).

    Real nmap XML shape: data is keyed by vulnerability ID, e.g.
    {"CVE-2017-0143": {title, state, ids: ["CVE:CVE-2017-0143"], scores,
    description, refs, ...}}. Key spelling is matched leniently
    (state/State, ids/IDs, ...) and state values like "LIKELY VULNERABLE"
    or "VULNERABLE (DoS)" count as vulnerable.
    """
    if isinstance(data, dict):
        items = list(data.items())
    elif isinstance(data, list):
        items = [(None, v) for v in data]
    else:
        return []
    out = []
    for key, val in items:
        if not isinstance(val, dict):
            continue
        state = str(_lenient_get(val, ("state", "State")) or "").strip()
        low = state.lower()
        if "vulnerable" not in low or "not vulnerable" in low:
            continue
        sev = ""
        risk = _lenient_get(val, ("risk_factor", "Risk factor"))
        if risk:
            sev = _risk_to_severity(str(risk))
        else:
            # nmap's rendered verdict (always present in the output text when
            # the script set a risk factor) wins over raw CVSS numbers: a
            # script may carry CVSSv2 10.0 while nmap prints "Risk factor: High".
            m = re.search(r"Risk factor:\s*(High|Medium|Low)", output or "", re.I)
            if m:
                sev = _risk_to_severity(m.group(1))
            else:
                sev = _scores_to_severity(_lenient_get(val, ("scores", "Scores")))
        if not sev:
            sev = "high"
        cves: list[str] = []
        ids = _lenient_get(val, ("ids", "IDs"))
        if isinstance(ids, dict):
            for v in ids.values():
                cves.extend(find_cves(str(v)))
        elif isinstance(ids, (list, str)):
            cves.extend(find_cves(str(ids)))
        if key is not None:
            cves.extend(find_cves(str(key)))
        cves.extend(find_cves(output))
        title = str(_lenient_get(val, ("title", "Title")) or "").strip()
        if not title:
            desc = _lenient_get(val, ("description", "Description"))
            if isinstance(desc, (list, tuple)):
                desc = " ".join(str(x) for x in desc)
            elif isinstance(desc, dict):
                desc = " ".join(str(x) for x in desc.values())
            desc = str(desc or "").strip()
            title = desc.splitlines()[0].strip() if desc else str(key or "")
        out.append(_finding("vulnerability", sev, title, output, cves))
    return out


# vulns.Report text fields (order matters only for readability)
_TEXT_LABELS = (
    "Target:", "Port:", "Reported by scripts:", "Description:",
    "Risk factor:", "IDs:", "VULNERABLE:", "NOT VULNERABLE:",
)
_STATE_RE = re.compile(
    r"State:\s*((?:LIKELY\s+)?VULNERABLE(?:\s*\([^)]*\))?|NOT\s+VULNERABLE)",
    re.I,
)


def _vulns_text_findings(output: str, script_name: str = "") -> list[dict]:
    """Parse vulns.Report-style text (e.g. the `vulns` aggregator).

    The aggregator serializes its result as a plain text array, so its XML
    element has no usable per-ID table. Each block looks like:

        <Title>
          State: VULNERABLE
          IDs:  CVE:CVE-2017-0143
          Risk factor: High
          Description: ...

    XML 1.0 normalizes newlines inside the output attribute to spaces, so
    this is deliberately line-agnostic (windowed regexes, not line scans);
    it works on raw multi-line text and on normalized single-line text.
    """
    findings: list[dict] = []
    if not output:
        return findings
    for m in _STATE_RE.finditer(output):
        state = m.group(1)
        low = state.lower()
        if "vulnerable" not in low or "not vulnerable" in low:
            continue
        # Block window: from after "State:" to the next "State:" (capped).
        nxt = output.find("State:", m.end())
        end = nxt if nxt != -1 and nxt - m.end() < 600 else min(len(output), m.end() + 600)
        after = output[m.end():end]
        rm = re.search(r"Risk factor:\s*(High|Medium|Low)\b", after, re.I)
        risk = rm.group(1) if rm else ""
        im = re.search(
            r"IDs:\s*(.+?)(?=\s*(?:Risk factor:|Description:|References:)|$)",
            after, re.I | re.S)
        ids_text = im.group(1) if im else ""
        # Title: text between the last known field label and "State:".
        before = output[:m.start()]
        cut, cut_len = -1, 0
        for lab in _TEXT_LABELS:
            idx = before.rfind(lab)
            if idx > cut:
                cut, cut_len = idx, len(lab)
        title = before[cut + cut_len:m.start()].strip() if cut != -1 else ""
        title = re.sub(r"^\d+/\S+\s+", "", title)  # drop "445/smb" remnants
        cves = list(dict.fromkeys(
            find_cves(ids_text) + find_cves(title) + find_cves(after)
        ))
        findings.append(_finding(
            "vulnerability",
            _risk_to_severity(risk) if risk else "high",
            title or script_name,
            output,
            cves,
        ))
    return findings


def _ext_ftp_anon(name, data, output):
    if re.search(r"anonymous ftp (login )?allowed", output, re.I):
        return [_finding(
            "misconfiguration", "medium", "FTP allows anonymous access",
            "Anonymous FTP login is enabled, allowing anyone to authenticate without credentials and read or upload files.",
            find_cves(output))]
    return []


def _ext_telnet_encryption(name, data, output):
    if re.search(r"does not support encryption", output, re.I):
        return [_finding(
            "misconfiguration", "high", "Telnet permits unencrypted logins",
            "The Telnet service does not support encryption; credentials and data are transmitted in cleartext. Replace Telnet with SSH.",
            find_cves(output))]
    return []


def _ext_sshv1(name, data, output):
    if re.search(r"supports\s+sshv1", output, re.I):
        return [_finding(
            "misconfiguration", "medium", "SSHv1 protocol enabled",
            "SSHv1 has known weaknesses and should be disabled; only SSHv2 should be permitted.",
            find_cves(output))]
    return []


def _weak_cipher_names(data: dict) -> list[str]:
    weak = []
    for proto, ciphers in data.items():
        if proto in ("POODLE", "CCS") or not isinstance(ciphers, dict):
            continue
        for cname, cinfo in ciphers.items():
            ks = cinfo.get("KeySize") if isinstance(cinfo, dict) else None
            try:
                ks = int(ks) if ks is not None else 0
            except (TypeError, ValueError):
                ks = 0
            if ks and ks <= 64:
                weak.append(cname)
                continue
            if re.search(r"(RC4|_DES|3DES|EXPORT|NULL|ANON|MD5)", cname, re.I):
                weak.append(cname)
    return weak


def _ext_ssl_enum_ciphers(name, data, output):
    if not isinstance(data, dict):
        return []
    out = []
    if data.get("SSLv2"):
        out.append(_finding(
            "vulnerability", "high", "SSLv2 protocol enabled",
            "SSLv2 is obsolete and cryptographically broken. Disable it and allow only modern TLS versions.",
            find_cves(output)))
    if data.get("SSLv3") or data.get("POODLE"):
        cves = ["CVE-2014-3566"]
        cves.extend(find_cves(output))
        out.append(_finding(
            "vulnerability", "high", "SSLv3 enabled (POODLE risk)",
            "SSLv3 is deprecated (RFC 7568) and vulnerable to POODLE padding-oracle attacks.",
            cves))
    if data.get("CCS"):
        cves = ["CVE-2014-0224"]
        cves.extend(find_cves(output))
        out.append(_finding(
            "vulnerability", "high", "TLS CCS injection vulnerability",
            "The TLS server appears vulnerable to the CCS injection attack, which can reveal plaintext.",
            cves))
    deprecated = [p for p in ("TLSv1", "TLSv1.1") if data.get(p)]
    if deprecated:
        out.append(_finding(
            "misconfiguration", "info",
            "Deprecated TLS protocol(s) enabled: " + ", ".join(deprecated),
            "TLSv1 and TLSv1.1 are deprecated by RFC 8996 and should be disabled where clients permit."))
    weak = _weak_cipher_names(data)
    if weak:
        out.append(_finding(
            "misconfiguration", "low", "Weak TLS ciphers enabled",
            "Weak or legacy ciphers are enabled: " + ", ".join(weak[:10])))
    return out


def _ext_http_security_headers(name, data, output):
    if not isinstance(data, dict):
        return []
    checks = (
        ("Strict_Transport_Security", "Strict-Transport-Security (HSTS)"),
        ("X_Frame_Options", "X-Frame-Options"),
        ("X_Content_Type_Options", "X-Content-Type-Options"),
        ("Content_Security_Policy", "Content-Security-Policy"),
    )
    missing = []
    for key, label in checks:
        val = data.get(key)
        if val is None:
            missing.append(label)
            continue
        if isinstance(val, (list, tuple)) and any(
            re.search(r"not (defined|configured)", str(v), re.I) for v in val
        ):
            missing.append(label)
    if missing:
        return [_finding(
            "misconfiguration", "low",
            "Missing HTTP security headers: " + ", ".join(missing),
            "Recommended security headers are not set, leaving clients exposed to clickjacking, MIME sniffing and related attacks.")]
    return []


def _ext_smb_enum_shares(name, data, output):
    if not isinstance(data, dict):
        return []
    out = []
    for share, info in data.items():
        if not isinstance(info, dict):
            continue
        acc = str(info.get("Anonymous access") or info.get("Access") or "").strip().upper()
        if acc in ("READ/WRITE", "WRITE"):
            out.append(_finding(
                "misconfiguration", "high",
                f"SMB share '{share}' is anonymously writable",
                f"Anonymous access to share '{share}' is {acc}. Anyone who can reach the host can write files to this share, which can be used to plant malware or deface content."))
        elif acc == "READ":
            out.append(_finding(
                "misconfiguration", "low",
                f"SMB share '{share}' is anonymously readable",
                f"Anonymous access to share '{share}' is READ, exposing its contents to unauthenticated users."))
    return out


def _ext_dns_zone_transfer(name, data, output):
    if re.search(r"needs a .* argument|failed to connect", output, re.I):
        return []
    if not (output or "").strip():
        return []
    return [_finding(
        "misconfiguration", "medium", "DNS zone transfer allowed",
        "The DNS server answered an AXFR request, allowing its full zone contents to be enumerated by anyone.",
        find_cves(output))]


def _ext_smtp_open_relay(name, data, output):
    if re.search(r"server is an open relay", output, re.I):
        return [_finding(
            "misconfiguration", "high", "SMTP open relay",
            "The mail server accepts relayed mail for arbitrary recipients, which can be abused to send spam from this host.",
            find_cves(output))]
    return []


def _ext_http_passwd(name, data, output):
    if re.search(r"directory traversal found", output, re.I):
        return [_finding(
            "vulnerability", "high", "HTTP server allows directory traversal to .htpasswd",
            "The web server does not sanitize null bytes, allowing .htpasswd (and possibly other protected files) to be read via directory traversal.",
            find_cves(output))]
    return []


def _ext_empty_password(name, data, output):
    if re.search(r"account has empty password|<empty> => login success", output, re.I):
        return [_finding(
            "misconfiguration", "critical", "Database allows login with an empty password",
            "A database account can be used without a password, giving full database access to anyone who can reach the service.",
            find_cves(output))]
    return []


def _ext_smb_protocols(name, data, output):
    if re.search(r"protocol:\s*smbv1\s*-\s*\[x\]", output, re.I):
        return [_finding(
            "misconfiguration", "medium", "SMBv1 protocol enabled",
            "SMBv1 has known vulnerabilities (e.g. EternalBlue) and should be disabled in favor of SMBv2/v3.",
            find_cves(output))]
    return []


def _ext_smb2_security_mode(name, data, output):
    if re.search(r"message signing is disabled", output, re.I):
        return [_finding(
            "misconfiguration", "low", "SMB message signing disabled",
            "SMB message signing is disabled, allowing connection spoofing and relay attacks on the SMB service.",
            find_cves(output))]
    return []


def _ext_rdp_enum_encryption(name, data, output):
    layer = data.get("Security layer") if isinstance(data, dict) else None
    if isinstance(layer, (list, tuple)):
        for entry in layer:
            if re.match(r"cleartext\s*:\s*success", str(entry), re.I):
                return [_finding(
                    "misconfiguration", "medium",
                    "RDP allows cleartext (unencrypted) connections",
                    "The RDP service accepts the ClearText security layer, transmitting session data without encryption. Require TLS or NLA.")]
    return []


def _ext_http_server_header(name, data, output):
    servers = data.get("Server") if isinstance(data, dict) else None
    if isinstance(servers, str):
        servers = [servers]
    if isinstance(servers, (list, tuple)):
        vers = [s for s in servers if isinstance(s, str) and re.search(r"[\s/]", s)]
        if vers:
            return [_finding(
                "info", "low", "Web server discloses product/version",
                "The Server header reveals implementation details that can help attackers target known vulnerabilities: "
                + ", ".join(vers[:3]))]
    return []


def _ext_ssl_cert_intaddr(name, data, output):
    if not isinstance(data, dict):
        return []
    leaked = []
    for fld, addrs in data.items():
        if isinstance(addrs, (list, tuple)):
            for a in addrs:
                if isinstance(a, str) and _IP_RE.match(a.strip()):
                    leaked.append(f"{fld}: {a.strip()}")
        elif isinstance(addrs, str) and _IP_RE.match(addrs.strip()):
            leaked.append(f"{fld}: {addrs.strip()}")
    if leaked:
        return [_finding(
            "info", "low", "SSL certificate leaks internal addresses",
            "Private IP addresses appear in the certificate: " + "; ".join(leaked[:5])
            + ". This discodes internal network details.")]
    return []


_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$")


def _cpe_label(cpe: str) -> str:
    """Short human label from a CPE part (skips cpe/2.3/type prefix, wildcards)."""
    parts = [p.strip().lstrip("/") for p in str(cpe).split(":") if p.strip()]
    if parts and parts[0].lower() == "cpe":
        parts = parts[1:]
    while parts and re.fullmatch(r"(\d+\.)*\d+", parts[0]):
        parts = parts[1:]  # CPE format version, e.g. "2.3"
    if parts and re.fullmatch(r"[a-z*]", parts[0], re.I):
        parts = parts[1:]  # target type: a/o/h
    return " ".join(p for p in parts if p != "*") or str(cpe)


def _ext_vulners(name, data, output):
    """`vulners`: CPE-keyed advisory table with per-entry CVSS scores.

    Data shape: {cpe: [{id, cvss, type, is_exploit}, ...], ...}. Emits a
    single summary finding built from the highest-scoring CVE entries; the
    scores come from the scan output itself (offline interpretation, no
    live database lookup).
    """
    if not isinstance(data, dict):
        return []
    cves: list[tuple[float, str, bool]] = []
    total = 0
    labels: list[str] = []
    for cpe, rows in data.items():
        if not isinstance(rows, list):
            continue
        total += len(rows)
        label = _cpe_label(cpe)
        if label and label not in labels:
            labels.append(label)
        for row in rows:
            if not isinstance(row, dict):
                continue
            rid = str(_lenient_get(row, ("id", "ID")) or "").strip()
            if not _CVE_ID_RE.match(rid):
                continue
            m = re.match(
                r"\s*(\d+(?:\.\d+)?)",
                str(_lenient_get(row, ("cvss", "CVSS", "score", "Score")) or ""))
            if not m:
                continue
            exploit = str(_lenient_get(row, ("is_exploit", "IsExploit")) or "").strip().lower() == "true"
            cves.append((float(m.group(1)), rid, exploit))
    if not cves:
        return []
    cves.sort(key=lambda t: -t[0])
    top_score, top_cve, top_exploit = cves[0]
    top_ids = list(dict.fromkeys(rid for _, rid, _ in cves[:5]))
    title = (f"{labels[0] if labels else name}: {len(cves)} CVEs reported "
             f"(top {top_cve}, CVSS {top_score:g})")
    detail = (
        f"Third-party vulners lookup matched {total} advisory entries for "
        f"{' / '.join(labels[:2]) or name}; {len(cves)} carry CVE identifiers. "
        f"Highest-scoring: {', '.join(top_ids)}.")
    if top_exploit:
        detail += f" A public exploit is available for {top_cve}."
    detail += " Scores are as printed in the scan output (no live database lookup performed)."
    return [_finding("vulnerability", _score_to_severity(top_score), title, detail, top_ids)]


_EXTRACTORS = {
    "ftp-anon": _ext_ftp_anon,
    "telnet-encryption": _ext_telnet_encryption,
    "sshv1": _ext_sshv1,
    "ssl-enum-ciphers": _ext_ssl_enum_ciphers,
    "http-security-headers": _ext_http_security_headers,
    "smb-enum-shares": _ext_smb_enum_shares,
    "dns-zone-transfer": _ext_dns_zone_transfer,
    "smtp-open-relay": _ext_smtp_open_relay,
    "http-passwd": _ext_http_passwd,
    "mysql-empty-password": _ext_empty_password,
    "ms-sql-empty-password": _ext_empty_password,
    "smb-protocols": _ext_smb_protocols,
    "smb2-security-mode": _ext_smb2_security_mode,
    "rdp-enum-encryption": _ext_rdp_enum_encryption,
    "http-server-header": _ext_http_server_header,
    "ssl-cert-intaddr": _ext_ssl_cert_intaddr,
    "vulners": _ext_vulners,
}


_FALLBACKS = (
    (re.compile(r"\bopen relay\b", re.I), "misconfiguration", "medium",
     "Possible open relay detected",
     "Script output indicates the service may act as an open relay."),
    (re.compile(r"zone transfer (allowed|succeeded)", re.I), "misconfiguration", "medium",
     "DNS zone transfer allowed",
     "The DNS server allowed a zone transfer; zone contents can be enumerated."),
    (re.compile(r"world[- ]writable", re.I), "misconfiguration", "medium",
     "World-writable resource detected",
     "Script output indicates a world-writable resource that unauthenticated users can modify."),
    (re.compile(r"empty password|no password (required|set)", re.I), "misconfiguration", "medium",
     "Empty password / missing authentication detected",
     "Script output indicates a service that accepts an empty password."),
    (re.compile(r"anonymous (access|login|ftp)", re.I), "misconfiguration", "low",
     "Anonymous access detected",
     "Script output indicates the service allows anonymous access."),
    (re.compile(r"cleartext", re.I), "info", "low",
     "Cleartext credentials or data permitted",
     "Script output indicates credentials or data may be sent in cleartext."),
)


def _keyword_fallback(output: str) -> list[dict]:
    if not (output or "").strip():
        return []
    findings = []
    for rx, kind, sev, title, detail in _FALLBACKS:
        if rx.search(output):
            findings.append(_finding(kind, sev, title, detail))
    out_low = output.lower()
    if re.search(r"\bvulnerable\b", out_low) and not re.search(r"\bnot\s+vulnerable\b", out_low):
        findings.append(_finding(
            "vulnerability", "medium", "Script reports a vulnerability",
            "Script output contains 'vulnerable' and could not be matched to a specific check.",
            find_cves(output)))
    return findings[:3]


def derive_findings(script_name: str, data, output: str) -> list[dict]:
    """Derive findings for one script result.

    Order: vulns.Report tables (authoritative) > vulns text blocks (e.g.
    the `vulns` aggregator, which has no usable table) > targeted extractor
    for the script name > generic keyword fallback. Returns [] when nothing
    notable.
    """
    name = (script_name or "").strip().lower()
    findings = _vulns_report_findings(data, output)
    if not findings:
        findings = _vulns_text_findings(output, script_name)
    if not findings:
        ext = _EXTRACTORS.get(name)
        if ext is not None:
            try:
                findings = ext(name, data, output) or []
            except Exception:
                findings = []
    if not findings:
        findings = _keyword_fallback(output)
    return findings


# --- DB glue ---------------------------------------------------------------

def upsert_script_result(session: Session, host_id: int, service_id: int | None,
                         artifact_id: int, el) -> int:
    """Parse one <script> element and upsert its NseResult + findings rows.

    service_id set = port-level <script>; service_id None + host_id set =
    host-level <hostscript> result. Returns 1 when a named script was
    processed, 0 otherwise.
    """
    name = (el.get("id") or "").strip()
    if not name:
        return 0
    parsed = parse_script_element(el)
    data = parsed["data"]
    data_json = json.dumps(data, ensure_ascii=False, default=str)
    output = parsed["output"]

    if service_id is not None:
        existing = session.scalar(
            select(NseResult).where(
                NseResult.service_id == service_id,
                NseResult.script_name == name,
            )
        )
        finding_filters = [
            ServiceFinding.service_id == service_id,
            ServiceFinding.script_name == name,
        ]
    else:
        existing = session.scalar(
            select(NseResult).where(
                NseResult.host_id == host_id,
                NseResult.service_id.is_(None),
                NseResult.script_name == name,
            )
        )
        finding_filters = [
            ServiceFinding.host_id == host_id,
            ServiceFinding.service_id.is_(None),
            ServiceFinding.script_name == name,
        ]

    if existing is not None:
        existing.output = output
        existing.data_json = data_json
        existing.artifact_id = artifact_id
    else:
        session.add(NseResult(
            service_id=service_id,
            host_id=host_id,
            artifact_id=artifact_id,
            script_name=name,
            output=output,
            data_json=data_json,
        ))
    session.execute(delete(ServiceFinding).where(*finding_filters))
    for f in derive_findings(name, data, output):
        session.add(ServiceFinding(
            service_id=service_id,
            host_id=host_id,
            script_name=name,
            kind=f["kind"],
            severity=f["severity"],
            title=f["title"],
            detail=f["detail"],
            cves=",".join(f["cves"]),
        ))
    return 1


def analyze_nmap_root(session: Session, artifact, root) -> int:
    """Process every named <script> element under hosts of a parsed nmap root.

    Port scripts attach to the matching Service row; <hostscript> results
    attach to the host (service_id NULL). Hosts and services must already
    exist (import_nmap_xml runs this after creating them). Returns the
    number of named scripts processed.
    """
    count = 0
    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr", "")
        if not ip:
            continue
        db_host = session.scalar(select(Host).where(Host.ip == ip))
        if db_host is None:
            continue
        for p in host.findall("ports/port"):
            try:
                portid = int(p.get("portid", "0") or 0)
            except ValueError:
                continue
            proto = p.get("protocol", "tcp")
            db_svc = session.scalar(
                select(Service).where(
                    Service.host_id == db_host.id,
                    Service.port == portid,
                    Service.proto == proto,
                )
            )
            if db_svc is None:
                continue
            for script in p.findall("script"):
                count += upsert_script_result(session, db_host.id, db_svc.id, artifact.id, script)
        for hscript in host.findall("hostscript"):
            for script in hscript.findall("script"):
                count += upsert_script_result(session, db_host.id, None, artifact.id, script)
    return count


def reanalyze_artifact(session: Session, artifact, path) -> int:
    """Re-derive NSE results and findings from a stored nmap_xml artifact file.

    Clears the artifact's existing NseResult rows (and the findings they
    produced) and re-parses the file. Used to backfill projects imported
    before NSE analysis existed, or after catalog/derivation changes.
    Returns the number of script results stored.
    """
    p = Path(path)
    if not p.is_file():
        return 0
    existing = session.execute(
        select(NseResult).where(NseResult.artifact_id == artifact.id)
    ).scalars().all()
    sids = sorted({r.service_id for r in existing if r.service_id is not None})
    hids = sorted({r.host_id for r in existing if r.host_id is not None})
    names = {r.script_name for r in existing}
    if sids:
        session.execute(delete(ServiceFinding).where(
            ServiceFinding.service_id.in_(sids),
            ServiceFinding.script_name.in_(names),
        ))
    if hids:
        session.execute(delete(ServiceFinding).where(
            ServiceFinding.host_id.in_(hids),
            ServiceFinding.service_id.is_(None),
            ServiceFinding.script_name.in_(names),
        ))
    session.execute(delete(NseResult).where(NseResult.artifact_id == artifact.id))
    session.flush()
    try:
        root = ET.parse(p).getroot()
    except ET.ParseError:
        from .parsers import _salvage_truncated_nmap_root
        root = _salvage_truncated_nmap_root(p)
    if root is None or root.tag != "nmaprun":
        return 0
    return analyze_nmap_root(session, artifact, root)
