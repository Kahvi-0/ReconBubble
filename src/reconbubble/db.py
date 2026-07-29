from __future__ import annotations
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase


class Base(DeclarativeBase):
    pass


def make_engine(db_path: Path):
    url = f"sqlite:///{db_path.as_posix()}"
    return create_engine(url, future=True, echo=False)


def make_session(engine):
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def _has_column(conn, table: str, col: str) -> bool:
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == col for r in rows)


def _column_type(conn, table: str, col: str) -> str | None:
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    for r in rows:
        if r[1] == col:
            return r[2]
    return None


def migrate_sqlite(engine) -> None:
    """Tiny, safe migrations for the MVP."""
    with engine.begin() as conn:
        # scope_items: add apply_all_subdomains column if missing
        try:
            if conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='scope_items'"
                )
            ).fetchone():
                if not _has_column(conn, "scope_items", "apply_all_subdomains"):
                    conn.execute(
                        text(
                            "ALTER TABLE scope_items ADD COLUMN apply_all_subdomains INTEGER DEFAULT 0"
                        )
                    )
                if not _has_column(
                    conn, "scope_items", "apply_subdomains_with_in_scope_ip"
                ):
                    conn.execute(
                        text(
                            "ALTER TABLE scope_items ADD COLUMN apply_subdomains_with_in_scope_ip INTEGER DEFAULT 0"
                        )
                    )
                if not _has_column(conn, "scope_items", "sensitive"):
                    conn.execute(
                        text(
                            "ALTER TABLE scope_items ADD COLUMN sensitive INTEGER DEFAULT 0"
                        )
                    )
        except Exception:
            pass

        # hosts: add complete, waf, and tag columns if missing
        try:
            if conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'"
                )
            ).fetchone():
                if not _has_column(conn, "hosts", "complete"):
                    conn.execute(
                        text("ALTER TABLE hosts ADD COLUMN complete INTEGER DEFAULT 0")
                    )
                if not _has_column(conn, "hosts", "inprogress"):
                    conn.execute(
                        text("ALTER TABLE hosts ADD COLUMN inprogress INTEGER DEFAULT 0")
                    )
                if not _has_column(conn, "hosts", "waf"):
                    conn.execute(
                        text("ALTER TABLE hosts ADD COLUMN waf INTEGER DEFAULT 0")
                    )
                if not _has_column(conn, "hosts", "tag"):
                    conn.execute(
                        text("ALTER TABLE hosts ADD COLUMN tag VARCHAR(64) DEFAULT ''")
                    )
                try:
                    conn.execute(
                        text("CREATE INDEX IF NOT EXISTS idx_hosts_tag ON hosts(tag)")
                    )
                except Exception:
                    pass
        except Exception:
            pass

        # subdomains: add prowl columns if missing
        try:
            if conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='subdomains'"
                )
            ).fetchone():
                if not _has_column(conn, "subdomains", "prowl_ips"):
                    conn.execute(
                        text(
                            "ALTER TABLE subdomains ADD COLUMN prowl_ips TEXT DEFAULT ''"
                        )
                    )
                if not _has_column(conn, "subdomains", "prowl_registrar"):
                    conn.execute(
                        text(
                            "ALTER TABLE subdomains ADD COLUMN prowl_registrar VARCHAR(255) DEFAULT ''"
                        )
                    )
                if not _has_column(conn, "subdomains", "prowl_netblocks"):
                    conn.execute(
                        text(
                            "ALTER TABLE subdomains ADD COLUMN prowl_netblocks TEXT DEFAULT ''"
                        )
                    )
        except Exception:
            pass

        # Create new tables if they don't exist
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS host_subdomains (
          host_id INTEGER NOT NULL,
          subdomain_id INTEGER NOT NULL,
          created_at DATETIME,
          PRIMARY KEY (host_id, subdomain_id)
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_host_subdomains_host_id ON host_subdomains(host_id)"
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_host_subdomains_subdomain_id ON host_subdomains(subdomain_id)"
            )
        )

        # valid_users table
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS valid_users (
          id INTEGER PRIMARY KEY,
          username VARCHAR(255) NOT NULL UNIQUE,
          source VARCHAR(64) DEFAULT '',
          notes TEXT DEFAULT '',
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_valid_users_username ON valid_users(username)"
            )
        )

        # credentials: add url column if missing
        try:
            if conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'"
                )
            ).fetchone():
                if not _has_column(conn, "credentials", "url"):
                    conn.execute(
                        text(
                            "ALTER TABLE credentials ADD COLUMN url VARCHAR(512) DEFAULT ''"
                        )
                    )
        except Exception:
            pass

        # credentials table
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS credentials (
          id INTEGER PRIMARY KEY,
          username VARCHAR(255),
          password VARCHAR(255),
          service VARCHAR(128) DEFAULT '',
          url VARCHAR(512) DEFAULT '',
          notes TEXT DEFAULT '',
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_credentials_service ON credentials(service)"
            )
        )

        # social_media table
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS social_media (
          id INTEGER PRIMARY KEY,
          platform VARCHAR(64),
          handle VARCHAR(255),
          url VARCHAR(512) DEFAULT '',
          display_name VARCHAR(255) DEFAULT '',
          bio TEXT DEFAULT '',
          notes TEXT DEFAULT '',
          artifact_id INTEGER,
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_social_media_platform ON social_media(platform)"
            )
        )

        # web_urls table
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS web_urls (
          id INTEGER PRIMARY KEY,
          url VARCHAR(2048) NOT NULL UNIQUE,
          domain VARCHAR(255),
          title VARCHAR(512) DEFAULT '',
          status_code INTEGER DEFAULT 0,
          notes TEXT DEFAULT '',
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_web_urls_domain ON web_urls(domain)")
        )

        # domain_info table for RDAP data
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS domain_info (
          id INTEGER PRIMARY KEY,
          domain VARCHAR(255) NOT NULL UNIQUE,
          registrar VARCHAR(255) DEFAULT '',
          creation_date VARCHAR(64) DEFAULT '',
          expiration_date VARCHAR(64) DEFAULT '',
          name_servers TEXT DEFAULT '',
          status TEXT DEFAULT '',
          rdap_error TEXT DEFAULT '',
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_domain_info_domain ON domain_info(domain)"
            )
        )

        # Add new RDAP columns if missing
        try:
            for col, typ in [
                ("registrar_email", "VARCHAR(255)"),
                ("registrar_org", "VARCHAR(255)"),
                ("updated_date", "VARCHAR(64)"),
                ("dnssec", "VARCHAR(64)"),
                ("registrant", "VARCHAR(255)"),
                ("registrant_email", "VARCHAR(255)"),
                ("admin_contact", "VARCHAR(255)"),
                ("admin_email", "VARCHAR(255)"),
                ("tech_contact", "VARCHAR(255)"),
                ("tech_email", "VARCHAR(255)"),
            ]:
                if not _has_column(conn, "domain_info", col):
                    conn.execute(
                        text(
                            f"ALTER TABLE domain_info ADD COLUMN {col} {typ} DEFAULT ''"
                        )
                    )
        except Exception:
            pass

        # dns_zone_transfers table
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS dns_zone_transfers (
          id INTEGER PRIMARY KEY,
          domain VARCHAR(255),
          nameserver VARCHAR(255),
          status VARCHAR(64) DEFAULT '',
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_dns_zone_transfers_domain ON dns_zone_transfers(domain)"
            )
        )

        # smtp_scans table
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS smtp_scans (
          id INTEGER PRIMARY KEY,
          mx_host VARCHAR(255),
          vrfy VARCHAR(64) DEFAULT '',
          expn VARCHAR(64) DEFAULT '',
          rcpt VARCHAR(64) DEFAULT '',
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_smtp_scans_mx_host ON smtp_scans(mx_host)"
            )
        )

        # cloud_items table - add columns if missing
        try:
            if conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='cloud_items'"
                )
            ).fetchone():
                for col, typ in [
                    ("tenant_id", "VARCHAR(128)"),
                    ("app_id", "VARCHAR(128)"),
                    ("primary_domain", "VARCHAR(255)"),
                    ("source_file", "VARCHAR(255)"),
                ]:
                    if not _has_column(conn, "cloud_items", col):
                        conn.execute(
                            text(
                                f"ALTER TABLE cloud_items ADD COLUMN {col} {typ} DEFAULT ''"
                            )
                        )
        except Exception:
            pass

        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS cloud_items (
          id INTEGER PRIMARY KEY,
          provider VARCHAR(64),
          name VARCHAR(255) DEFAULT '',
          tenant_id VARCHAR(128) DEFAULT '',
          app_id VARCHAR(128) DEFAULT '',
          primary_domain VARCHAR(255) DEFAULT '',
          source_file VARCHAR(255) DEFAULT '',
          data_json TEXT DEFAULT '',
          notes TEXT DEFAULT '',
          created_at DATETIME
        )
        """)
        )

        # checklist table
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS checklist (
          id INTEGER PRIMARY KEY,
          item_key VARCHAR(64) NOT NULL UNIQUE,
          done INTEGER DEFAULT 0
        )
        """)
        )

        # checklist_maps table - stores editable mind map definitions
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS checklist_maps (
          id INTEGER PRIMARY KEY,
          map_name VARCHAR(64) NOT NULL UNIQUE,
          title VARCHAR(255) DEFAULT '',
          phase_label VARCHAR(128) DEFAULT '',
          data_json TEXT DEFAULT '{}',
          updated_at DATETIME
        )
        """)
        )

        # checklist_notes table
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS checklist_notes (
          id INTEGER PRIMARY KEY,
          item_key VARCHAR(128) NOT NULL UNIQUE,
          note TEXT DEFAULT ''
        )
        """)
        )

        # port_research table - research URLs and info for common ports/services
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS port_research (
          id INTEGER PRIMARY KEY,
          port INTEGER NOT NULL,
          service VARCHAR(64) DEFAULT '',
          research_url VARCHAR(512) DEFAULT '',
          research_notes TEXT DEFAULT '',
          UNIQUE(port, service)
        )
        """)
        )

        # password spray tracking tables
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS password_spray_services (
          id INTEGER PRIMARY KEY,
          name VARCHAR(255) NOT NULL UNIQUE,
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_password_spray_services_name ON password_spray_services(name)"
            )
        )
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS password_spray_attempts (
          id INTEGER PRIMARY KEY,
          service_id INTEGER NOT NULL,
          password VARCHAR(255) DEFAULT '',
          attempted_at VARCHAR(64) DEFAULT '',
          notes TEXT DEFAULT '',
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_password_spray_attempts_service_id ON password_spray_attempts(service_id)"
            )
        )

        # active directory credential tracking
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS ad_credentials (
          id INTEGER PRIMARY KEY,
          cred_type VARCHAR(32) NOT NULL,
          domain VARCHAR(255) DEFAULT '',
          username VARCHAR(255) DEFAULT '',
          password VARCHAR(255) DEFAULT '',
          hostname VARCHAR(255) DEFAULT '',
          dump_text TEXT DEFAULT '',
          notes TEXT DEFAULT '',
          created_at DATETIME
        )
        """)
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_ad_credentials_type ON ad_credentials(cred_type)"
            )
        )

        # profiling_rows table - editable profiling items
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS profiling_rows (
          id INTEGER PRIMARY KEY,
          category VARCHAR(256) DEFAULT '',
          description TEXT DEFAULT '',
          comments TEXT DEFAULT '',
          order_index INTEGER DEFAULT 0,
          created_at DATETIME
        )
        """)
        )

        # Seed default profiling rows if table is empty
        count = conn.execute(text("SELECT COUNT(*) FROM profiling_rows")).scalar()
        if count == 0:
            defaults = [
                ("Operating Systems", "[ 1.1.1.1 - Microsoft Server 2000 ]", "End-of-life OS; known CVEs with no vendor patches available.", 0),
                ("Exposed Services", "", "This service was exposed on an Internet-facing system.", 1),
                ("Exposed Files", "", "The configuration file was directly accessible from the Internet.", 2),
                ("Exposed Transports", "", "Internal or legacy transport protocols were reachable externally.", 3),
                ("Configuration Information", "", "System or application configuration details were discoverable.", 4),
                ("Unencrypted Protocols", "", "Cleartext protocols such as HTTP, FTP, or Telnet were in use.", 5),
                ("Domain Registrars", "", "Domain registrar and WHOIS details were publicly accessible.", 6),
                ("Application Virtual Hosts", "", "Internal or staging virtual hosts were resolvable externally.", 7),
                ("Web Management Interfaces", "", "Administrative web interfaces were exposed without adequate protection.", 8),
                ("Exposed Database Details", "[Database version, driver, or error messages were visible in responses.]", "", 9),
            ]
            for cat, desc, comm, idx in defaults:
                conn.execute(
                    text(
                        "INSERT INTO profiling_rows (category, description, comments, order_index, created_at) VALUES (:cat, :desc, :comm, :idx, datetime('now'))"
                    ),
                    {"cat": cat, "desc": desc, "comm": comm, "idx": idx},
                )

        # app_settings table - key-value prefs
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS app_settings (
          id INTEGER PRIMARY KEY,
          key VARCHAR(128) NOT NULL UNIQUE,
          value TEXT DEFAULT ''
        )
        """)
        )

        # domain_correlations table - track domain aliases
        conn.execute(
            text("""
        CREATE TABLE IF NOT EXISTS domain_correlations (
          id INTEGER PRIMARY KEY,
          primary_domain VARCHAR(255) NOT NULL UNIQUE,
          aliases TEXT DEFAULT ''
        )
        """)
        )

        # name_items: add domain column if missing
        try:
            if conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='name_items'"
                )
            ).fetchone():
                if not _has_column(conn, "name_items", "domain"):
                    conn.execute(
                        text(
                            "ALTER TABLE name_items ADD COLUMN domain VARCHAR(255) DEFAULT ''"
                        )
                    )
                if not _has_column(conn, "name_items", "password"):
                    conn.execute(
                        text(
                            "ALTER TABLE name_items ADD COLUMN password VARCHAR(255) DEFAULT ''"
                        )
                    )
                if not _has_column(conn, "name_items", "ntlm_hash"):
                    conn.execute(
                        text(
                            "ALTER TABLE name_items ADD COLUMN ntlm_hash VARCHAR(255) DEFAULT ''"
                        )
                    )
                if not _has_column(conn, "name_items", "ntlm_v1"):
                    conn.execute(
                        text(
                            "ALTER TABLE name_items ADD COLUMN ntlm_v1 VARCHAR(255) DEFAULT ''"
                        )
                    )
                if not _has_column(conn, "name_items", "ntlm_v2"):
                    conn.execute(
                        text(
                            "ALTER TABLE name_items ADD COLUMN ntlm_v2 VARCHAR(255) DEFAULT ''"
                        )
                    )
                if not _has_column(conn, "name_items", "dcc2"):
                    conn.execute(
                        text(
                            "ALTER TABLE name_items ADD COLUMN dcc2 TEXT DEFAULT ''"
                        )
                    )
                if not _has_column(conn, "name_items", "kerberos_asrep"):
                    conn.execute(
                        text(
                            "ALTER TABLE name_items ADD COLUMN kerberos_asrep VARCHAR(255) DEFAULT ''"
                        )
                    )
            if not _has_column(conn, "name_items", "kerberos_tgs"):
                conn.execute(
                    text(
                        "ALTER TABLE name_items ADD COLUMN kerberos_tgs VARCHAR(255) DEFAULT ''"
                    )
                )
            if not _has_column(conn, "name_items", "kerberos_key_aes128"):
                conn.execute(
                    text(
                        "ALTER TABLE name_items ADD COLUMN kerberos_key_aes128 VARCHAR(255) DEFAULT ''"
                    )
                )
            if not _has_column(conn, "name_items", "kerberos_key_aes256"):
                conn.execute(
                    text(
                        "ALTER TABLE name_items ADD COLUMN kerberos_key_aes256 VARCHAR(255) DEFAULT ''"
                    )
                )

            # Ensure kerberos_tgs, kerberos_asrep, ntlm_v2 are TEXT (hashes exceed 255)
            for _col_name in ("kerberos_tgs", "kerberos_asrep", "ntlm_v2"):
                if _has_column(conn, "name_items", _col_name):
                    ct = _column_type(conn, "name_items", _col_name)
                    if ct and "TEXT" not in ct.upper():
                        try:
                            conn.execute(text(f"ALTER TABLE name_items RENAME TO name_items_old"))
                            conn.execute(text("""
                                CREATE TABLE name_items (
                                    id INTEGER PRIMARY KEY,
                                    first_name VARCHAR(255),
                                    middle_name VARCHAR(255),
                                    last_name VARCHAR(255),
                                    email VARCHAR(255),
                                    phone VARCHAR(64),
                                    ad_username VARCHAR(255),
                                    domain VARCHAR(255),
                                    password VARCHAR(255),
                                    ntlm_hash VARCHAR(255),
                                    ntlm_v1 VARCHAR(255),
                                    ntlm_v2 TEXT DEFAULT '',
                                    dcc2 TEXT DEFAULT '',
                                    kerberos_asrep TEXT DEFAULT '',
                                    kerberos_tgs TEXT DEFAULT '',
                                    kerberos_key_aes128 VARCHAR(255) DEFAULT '',
                                    kerberos_key_aes256 VARCHAR(255) DEFAULT '',
                                    tags VARCHAR(512),
                                    topology_node_id VARCHAR(255),
                                    created_at DATETIME
                                )
                            """))
                            conn.execute(text("""
                                INSERT INTO name_items (id, first_name, middle_name, last_name, email, phone,
                                    ad_username, domain, password, ntlm_hash, ntlm_v1, ntlm_v2, dcc2,
                                    kerberos_asrep, kerberos_tgs, kerberos_key_aes128, kerberos_key_aes256, tags, topology_node_id, created_at)
                                SELECT id, first_name, middle_name, last_name, email, phone,
                                    ad_username, domain, password, ntlm_hash, ntlm_v1, ntlm_v2, COALESCE(dcc2, ''),
                                    kerberos_asrep, kerberos_tgs, COALESCE(kerberos_key_aes128, ''), COALESCE(kerberos_key_aes256, ''), tags, topology_node_id, created_at
                                FROM name_items_old
                            """))
                            conn.execute(text("DROP TABLE name_items_old"))
                        except Exception:
                            pass
        except Exception:
            pass

        # name_items: add cracked/plaintext tracking columns if missing
        try:
            if conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='name_items'"
                )
            ).fetchone():
                for _col in (
                    "password_plaintext",
                    "ntlm_hash_cracked",
                    "ntlm_v1_cracked",
                    "ntlm_v2_cracked",
                    "dcc2_cracked",
                    "kerberos_asrep_cracked",
                    "kerberos_tgs_cracked",
                    "kerberos_key_aes128_cracked",
                    "kerberos_key_aes256_cracked",
                ):
                    if not _has_column(conn, "name_items", _col):
                        conn.execute(
                            text(
                                f"ALTER TABLE name_items ADD COLUMN {_col} INTEGER DEFAULT 0"
                            )
                        )
        except Exception:
            pass
    conn.commit()
