from __future__ import annotations
from pathlib import Path
import re, json, mimetypes, subprocess, socket
from datetime import datetime
from xml.etree import ElementTree as ET
from sqlalchemy.orm import Session
from sqlalchemy import select, text as sql_text
from .models import Artifact, Host, Service, ServiceEvidence, Subdomain, Email, Document, ValidUser, Credential, SocialMedia, WebUrl
from .workspace import sha256_file

def resolve_ips(fqdn: str) -> list[str]:
    fqdn = fqdn.strip().rstrip(".")
    out = set()
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(fqdn, None, family=fam, type=socket.SOCK_STREAM)
            except Exception:
                continue
            for info in infos:
                ip = info[4][0]
                if ip:
                    out.add(ip)
    except Exception:
        pass
    return sorted(out)

def link_host_domain(session: Session, host_id: int, fqdn: str) -> None:
    fqdn = fqdn.strip().lower().rstrip(".")
    if not fqdn or not DOMAIN_RE.match(fqdn):
        return
    sub = session.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))
    if not sub:
        sub = Subdomain(fqdn=fqdn, root_domain=root_domain_guess(fqdn))
        session.add(sub); session.commit(); session.refresh(sub)
    session.execute(sql_text(
        "INSERT OR IGNORE INTO host_subdomains(host_id, subdomain_id, created_at) "
        "VALUES (:hid, :sid, :ts)"
    ), {"hid": host_id, "sid": sub.id, "ts": datetime.utcnow().isoformat()})
    session.commit()

DOMAIN_RE = re.compile(r"(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.?$")

def root_domain_guess(fqdn: str) -> str:
    parts = fqdn.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn.strip(".")

def upsert_artifact(session: Session, type_: str, stored_path: Path) -> Artifact:
    h = sha256_file(stored_path)
    art = Artifact(type=type_, filename=stored_path.name, stored_path=str(stored_path), sha256=h)
    session.add(art); session.commit(); session.refresh(art)
    return art


def upsert_host(session: Session, ip: str, hostname: str = "", os_guess: str = "") -> Host:
    """Create host if needed; otherwise merge fields. Host uniqueness is by IP."""
    ip = (ip or "").strip()
    hostname = (hostname or "").strip()
    os_guess = (os_guess or "").strip()
    if not ip:
        raise ValueError("ip is required")
    db_host = session.scalar(select(Host).where(Host.ip == ip))
    if not db_host:
        db_host = Host(ip=ip, hostname=hostname, os_guess=os_guess)
        session.add(db_host)
        session.commit()
        session.refresh(db_host)
        return db_host

    # Merge only if we have new info
    if hostname and not db_host.hostname:
        db_host.hostname = hostname
    if os_guess and not db_host.os_guess:
        db_host.os_guess = os_guess
    session.commit()
    return db_host

def import_subdomains(session: Session, artifact: Artifact, path: Path) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"): continue
        s = s.split()[0].strip().rstrip(".")
        if not DOMAIN_RE.match(s): continue
        if session.scalar(select(Subdomain).where(Subdomain.fqdn == s)): continue
        sub_obj = Subdomain(fqdn=s, root_domain=root_domain_guess(s)); session.add(sub_obj); count += 1
        session.commit(); session.refresh(sub_obj)
        for ip in resolve_ips(s):
            try:
                h = upsert_host(session, ip, "", "")
                link_host_domain(session, h.id, s)
            except Exception:
                continue
    session.commit(); return count

def import_emails(session: Session, artifact: Artifact, path: Path) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"): continue
        s = s.split()[0].strip().strip(",;")
        if "@" not in s: continue
        local, dom = s.split("@", 1)
        dom = dom.strip().lower().strip(".")
        s = f"{local}@{dom}"
        if session.scalar(select(Email).where(Email.email == s)): continue
        session.add(Email(email=s, domain=dom)); count += 1
    session.commit(); return count

def import_nmap_xml(session: Session, artifact: Artifact, path: Path) -> dict:
    try:
        tree = ET.parse(path); root = tree.getroot()
    except ET.ParseError as e:
        raise ValueError(
            "Invalid Nmap XML upload. Make sure you ran nmap with -oX scan.xml (or -oA name and upload the .xml) "
            "and upload the XML file (it should start with <nmaprun>)."
        ) from e
    host_count = service_count = evidence_count = 0
    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None: continue
        ip = addr.get("addr",""); 
        if not ip: continue
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None: hostname = hn.get("name","") or ""
        os_guess = ""
        osmatch = host.find("os/osmatch")
        if osmatch is not None: os_guess = osmatch.get("name","") or ""

        db_host = session.scalar(select(Host).where(Host.ip == ip))
        if not db_host:
            db_host = Host(ip=ip, hostname=hostname, os_guess=os_guess)
            session.add(db_host); session.commit(); session.refresh(db_host); host_count += 1
        else:
            if hostname and not db_host.hostname: db_host.hostname = hostname
            if os_guess and not db_host.os_guess: db_host.os_guess = os_guess
            session.commit()

        # Link host to subdomains based on hostname
        if hostname:
            try:
                # Try to find matching subdomain by hostname
                sub = session.scalar(select(Subdomain).where(Subdomain.fqdn == hostname.lower()))
                if sub:
                    exists = session.execute(
                        sql_text("SELECT 1 FROM host_subdomains WHERE host_id = :hid AND subdomain_id = :sid"),
                        {"hid": db_host.id, "sid": sub.id}
                    ).fetchone()
                    if not exists:
                        session.execute(
                            sql_text("INSERT INTO host_subdomains (host_id, subdomain_id) VALUES (:hid, :sid)"),
                            {"hid": db_host.id, "sid": sub.id}
                        )
                        session.commit()
                
                # Also try to find subdomain by root domain
                parts = hostname.lower().split(".")
                if len(parts) > 1:
                    root_domain = ".".join(parts[-2:])
                    subs = session.execute(
                        sql_text("SELECT id, fqdn FROM subdomains WHERE root_domain = :rd"),
                        {"rd": root_domain}
                    ).fetchall()
                    for sub_id, sub_fqdn in subs:
                        exists = session.execute(
                            sql_text("SELECT 1 FROM host_subdomains WHERE host_id = :hid AND subdomain_id = :sid"),
                            {"hid": db_host.id, "sid": sub_id}
                        ).fetchone()
                        if not exists:
                            session.execute(
                                sql_text("INSERT INTO host_subdomains (host_id, subdomain_id) VALUES (:hid, :sid)"),
                                {"hid": db_host.id, "sid": sub_id}
                            )
                    session.commit()
            except Exception as e:
                print(f"[Nmap] Error linking host {ip} to subdomains: {e}")

        for p in host.findall("ports/port"):
            proto = p.get("protocol","tcp")
            portid = int(p.get("portid","0") or 0)
            st = p.find("state"); state_s = st.get("state","unknown") if st is not None else "unknown"
            svc = p.find("service")
            service_name = svc.get("name","") if svc is not None else ""
            product = svc.get("product","") if svc is not None else ""
            version = svc.get("version","") if svc is not None else ""
            extrainfo = svc.get("extrainfo","") if svc is not None else ""

            db_svc = session.scalar(select(Service).where(Service.host_id==db_host.id, Service.port==portid, Service.proto==proto))
            if not db_svc:
                db_svc = Service(host_id=db_host.id, port=portid, proto=proto, state=state_s,
                                 service_name=service_name, product=product, version=version, extra_info=extrainfo)
                session.add(db_svc); session.commit(); session.refresh(db_svc); service_count += 1
            else:
                db_svc.state = state_s or db_svc.state
                if service_name and not db_svc.service_name: db_svc.service_name = service_name
                if product and not db_svc.product: db_svc.product = product
                if version and not db_svc.version: db_svc.version = version
                if extrainfo and not db_svc.extra_info: db_svc.extra_info = extrainfo
                session.commit()

            outputs = []
            for script in p.findall("script"):
                sid = script.get("id",""); out = script.get("output","") or ""
                if sid or out: outputs.append(f"[{sid}] {out}".strip())

            header = f"{db_host.ip} {portid}/{proto} {state_s} {service_name} {product} {version} {extrainfo}".strip()
            raw = header + ("\n" + "\n".join(outputs) if outputs else "")
            if raw.strip():
                session.add(ServiceEvidence(service_id=db_svc.id, artifact_id=artifact.id, raw_output=raw))
                session.commit(); evidence_count += 1
    return {"hosts_added": host_count, "services_added": service_count, "evidence_added": evidence_count}

def import_document(session: Session, artifact: Artifact, path: Path) -> int:
    sha = sha256_file(path)
    mime, _ = mimetypes.guess_type(path.name)
    mime = mime or "application/octet-stream"
    size = path.stat().st_size
    title = path.stem

    # Start with exiftool metadata (safe)
    try:
        meta = exiftool_json(path) or {}
    except Exception as e:
        meta = {"exiftool_error": str(e)}

    try:
        if path.suffix.lower() == ".pdf":
            from PyPDF2 import PdfReader
            r = PdfReader(str(path))
            info = r.metadata
            if info:
                meta.update({k.strip("/"): str(v) for k, v in info.items() if v is not None})
                if meta.get("Title"):
                    title = meta["Title"]

        elif path.suffix.lower() == ".docx":
            import docx
            d = docx.Document(str(path))
            cp = d.core_properties
            meta.update({
                "author": cp.author or "",
                "created": cp.created.isoformat() if cp.created else "",
                "modified": cp.modified.isoformat() if cp.modified else "",
                "title": cp.title or "",
            })
            if cp.title:
                title = cp.title

    except Exception as e:
        meta["metadata_error"] = str(e)

    # Create the Document row so we can store both meta_json + exif_json
    doc = Document(
        artifact_id=artifact.id,
        title=title[:255],
        mime=mime[:128],
        size_bytes=size,
        sha256=sha,
        meta_json=json.dumps(meta, ensure_ascii=False),
        exif_json=json.dumps(meta, ensure_ascii=False),  # full exiftool+enriched metadata
    )

    session.add(doc)
    session.commit()
    return 1
    
def exiftool_json(path: Path, timeout: int = 10) -> dict:
    """
    Run exiftool and return parsed JSON metadata.
    Returns {} if exiftool isn't installed or errors.
    """
    try:
        proc = subprocess.run(
            ["exiftool", "-j", "-n", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        # exiftool not installed
        return {}
    except subprocess.TimeoutExpired:
        return {"_error": "exiftool timeout"}

    if proc.returncode != 0:
        return {"_error": proc.stderr.strip() or "exiftool failed"}

    try:
        data = json.loads(proc.stdout)
        # exiftool returns a list of dicts
        return data[0] if isinstance(data, list) and data else {}
    except Exception:
        return {"_error": "failed to parse exiftool output"}

def import_valid_users(session: Session, artifact: Artifact, path: Path) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"): continue
        s = s.split()[0].strip()
        if not s: continue
        if session.scalar(select(ValidUser).where(ValidUser.username == s)): continue
        session.add(ValidUser(username=s, source=artifact.filename)); count += 1
    session.commit(); return count

def import_credentials(session: Session, artifact: Artifact, path: Path) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"): continue
        if ":" not in s: continue
        user, pass_ = s.split(":", 1)
        user = user.strip(); pass_ = pass_.strip()
        if not user: continue
        session.add(Credential(username=user, password=pass_, service="")); count += 1
    session.commit(); return count

def import_web_urls(session: Session, artifact: Artifact, path: Path) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        url = line.strip()
        if not url or url.startswith("#"): continue
        url = url.split()[0].strip().rstrip("/")
        if not url: continue
        try:
            existing = session.scalar(select(WebUrl).where(WebUrl.url == url))
            if existing: continue
        except Exception:
            pass
        domain = ""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
        except Exception:
            pass
        try:
            session.add(WebUrl(url=url, domain=domain))
            session.flush()
            count += 1
        except Exception as e:
            print(f"[URLs] Error adding {url}: {e}")
            session.rollback()
            continue
    session.commit()
    return count

def import_prowl_phase1(session: Session, artifact: Artifact, path: Path) -> int:
    import json
    from sqlalchemy import text
    count = 0
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format in Prowler file: {e}")
    except Exception as e:
        raise ValueError(f"Error reading Prowler file: {e}")
    
    if not isinstance(data, dict):
        raise ValueError("Prowler JSON must be a dictionary with 'domains' key")
    
    domains_data = data.get("domains", {})
    if not domains_data:
        raise ValueError("No 'domains' found in Prowler JSON file")
    
    total = len(domains_data)
    print(f"[Prowler] Importing {total} domains...")
    
    try:
        for i, (fqdn, info) in enumerate(domains_data.items()):
            if i > 0 and i % 50 == 0:
                print(f"[Prowler] Processed {i}/{total}...")
            
            fqdn = fqdn.lower().strip().rstrip(".")
            if not fqdn:
                continue
            
            # Extract root domain
            parts = fqdn.split(".")
            if len(parts) > 1:
                root_domain = ".".join(parts[-2:])
            else:
                root_domain = fqdn
            
            # Get Prowler info - deduplicate IPs
            prowl_ips_raw = info.get("ips", [])
            prowl_ips_list = list(set([ip for ip in prowl_ips_raw if ip])) if prowl_ips_raw else []
            prowl_ips = ",".join(prowl_ips_list)
            prowl_registrar = info.get("registrar", "")
            prowl_netblocks_raw = info.get("netblocks", [])
            prowl_netblocks_list = list(set([nb for nb in prowl_netblocks_raw if nb])) if prowl_netblocks_raw else []
            prowl_netblocks = ",".join(prowl_netblocks_list)
            
            # Check if subdomain exists
            sub = session.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))
            if sub:
                sub.prowl_ips = prowl_ips
                sub.prowl_registrar = prowl_registrar
                sub.prowl_netblocks = prowl_netblocks
                count += 1
            else:
                sub = Subdomain(
                    fqdn=fqdn,
                    root_domain=root_domain,
                    prowl_ips=prowl_ips,
                    prowl_registrar=prowl_registrar,
                    prowl_netblocks=prowl_netblocks,
                )
                session.add(sub)
                session.flush()
                count += 1
            
            # Add IPs as hosts and link to subdomain - deduplicate
            all_ips = set(info.get("ips", []))
            
            # Also resolve IPs via DNS
            try:
                resolved = resolve_ips(fqdn)
                for ip in resolved:
                    if ip:
                        all_ips.add(ip)
            except Exception as e:
                print(f"[Prowler] DNS resolution error for {fqdn}: {e}")
            
            for ip in all_ips:
                try:
                    host = session.scalar(select(Host).where(Host.ip == ip))
                    if not host:
                        host = Host(ip=ip)
                        session.add(host)
                        session.flush()
                    
                    # Link host to subdomain
                    exists = session.execute(
                        sql_text("SELECT 1 FROM host_subdomains WHERE host_id = :hid AND subdomain_id = :sid"),
                        {"hid": host.id, "sid": sub.id}
                    ).fetchone()
                    if not exists:
                        session.execute(
                            sql_text("INSERT INTO host_subdomains (host_id, subdomain_id) VALUES (:hid, :sid)"),
                            {"hid": host.id, "sid": sub.id}
                        )
                except Exception as e:
                    print(f"[Prowler] Error linking host {ip}: {e}")
                    continue
        
        session.commit()
        print(f"[Prowler] Import complete: {count} domains processed")
        return count
    except Exception as e:
        session.rollback()
        raise ValueError(f"Prowler import failed: {e}")

def import_zone_transfers(session: Session, artifact: Artifact, path: Path) -> int:
    import json
    from sqlalchemy import text
    count = 0
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format in zone transfer file: {e}")
    except Exception as e:
        raise ValueError(f"Error reading zone transfer file: {e}")
    
    if not isinstance(data, dict):
        raise ValueError("Zone transfer JSON must be a dictionary with 'results' key")
    
    results = data.get("results", [])
    if not results:
        raise ValueError("No 'results' found in zone transfer JSON file")
    
    print(f"[Zone Transfer] Importing {len(results)} domain results...")
    
    for item in results:
        domain = item.get("domain", "")
        if not domain:
            continue
        
        nameservers = item.get("nameservers", {})
        for ns, status in nameservers.items():
            # Check if already exists
            existing = session.execute(text(
                "SELECT id FROM dns_zone_transfers WHERE domain = :d AND nameserver = :ns"
            ), {"d": domain, "ns": ns}).fetchone()
            
            if not existing:
                from datetime import datetime
                session.execute(text(
                    "INSERT INTO dns_zone_transfers (domain, nameserver, status, created_at) VALUES (:d, :ns, :st, :ts)"
                ), {"d": domain, "ns": ns, "st": status, "ts": datetime.utcnow()})
                count += 1
    
    session.commit()
    print(f"[Zone Transfer] Import complete: {count} records")
    return count

def import_smtp(session: Session, artifact: Artifact, path: Path) -> int:
    import json
    from sqlalchemy import text
    from datetime import datetime
    count = 0
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format in SMTP file: {e}")
    except Exception as e:
        raise ValueError(f"Error reading SMTP file: {e}")
    
    if not isinstance(data, dict):
        raise ValueError("SMTP JSON must be a dictionary with 'results' key")
    
    results = data.get("results", [])
    if not results:
        raise ValueError("No 'results' found in SMTP JSON file")
    
    print(f"[SMTP] Importing {len(results)} SMTP scan results...")
    
    for item in results:
        mx_host = item.get("mx_host", "")
        if not mx_host:
            continue
        
        vrfy = item.get("vrfy", "")
        expn = item.get("expn", "")
        rcpt = item.get("rcpt", "")
        
        # Check if already exists
        existing = session.execute(text(
            "SELECT id FROM smtp_scans WHERE mx_host = :mx"
        ), {"mx": mx_host}).fetchone()
        
        if not existing:
            session.execute(text(
                "INSERT INTO smtp_scans (mx_host, vrfy, expn, rcpt, created_at) VALUES (:mx, :vrfy, :expn, :rcpt, :ts)"
            ), {"mx": mx_host, "vrfy": vrfy, "expn": expn, "rcpt": rcpt, "ts": datetime.utcnow()})
            count += 1
    
    session.commit()
    print(f"[SMTP] Import complete: {count} records")
    return count
