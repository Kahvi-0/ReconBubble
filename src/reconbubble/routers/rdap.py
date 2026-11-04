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

    @router.get("/api/rdap/{domain}")
    def api_rdap(domain: str):
        import urllib.request, json, socket

        def _fetch(url: str, timeout: float = 10.0) -> str:
            """HTTPS GET with verified TLS; tunnels via RECONBUBBLE_PROXY when set."""
            if netproxy.proxy_settings():
                return netproxy.https_get(
                    url, timeout=timeout, headers={"User-Agent": "ReconBubble/1.0"}
                )
            req = urllib.request.Request(url, headers={"User-Agent": "ReconBubble/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="ignore")

        domain = domain.lower().strip()

        out = {"domainName": domain}
        error_msg = ""

        # Try whois first (port 43)
        try:
            s = netproxy.socks5_connect("whois.iana.org", 43, timeout=10.0)
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
                    raw = _fetch(url)
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
                raw = _fetch(url)
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
        with st.db() as s:
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
    return router
