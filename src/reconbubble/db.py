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

def migrate_sqlite(engine) -> None:
    """Tiny, safe migrations for the MVP."""
    with engine.begin() as conn:
        # scope_items: add apply_all_subdomains column if missing
        try:
            if conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='scope_items'")).fetchone():
                if not _has_column(conn, "scope_items", "apply_all_subdomains"):
                    conn.execute(text("ALTER TABLE scope_items ADD COLUMN apply_all_subdomains INTEGER DEFAULT 0"))
        except Exception:
            pass

        # hosts: add complete and waf columns if missing
        try:
            if conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'")).fetchone():
                if not _has_column(conn, "hosts", "complete"):
                    conn.execute(text("ALTER TABLE hosts ADD COLUMN complete INTEGER DEFAULT 0"))
                if not _has_column(conn, "hosts", "waf"):
                    conn.execute(text("ALTER TABLE hosts ADD COLUMN waf INTEGER DEFAULT 0"))
        except Exception:
            pass

        # subdomains: add prowl columns if missing
        try:
            if conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='subdomains'")).fetchone():
                if not _has_column(conn, "subdomains", "prowl_ips"):
                    conn.execute(text("ALTER TABLE subdomains ADD COLUMN prowl_ips TEXT DEFAULT ''"))
                if not _has_column(conn, "subdomains", "prowl_registrar"):
                    conn.execute(text("ALTER TABLE subdomains ADD COLUMN prowl_registrar VARCHAR(255) DEFAULT ''"))
                if not _has_column(conn, "subdomains", "prowl_netblocks"):
                    conn.execute(text("ALTER TABLE subdomains ADD COLUMN prowl_netblocks TEXT DEFAULT ''"))
        except Exception:
            pass

        # Create new tables if they don't exist
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS host_subdomains (
          host_id INTEGER NOT NULL,
          subdomain_id INTEGER NOT NULL,
          created_at DATETIME,
          PRIMARY KEY (host_id, subdomain_id)
        )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_host_subdomains_host_id ON host_subdomains(host_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_host_subdomains_subdomain_id ON host_subdomains(subdomain_id)"))

        # valid_users table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS valid_users (
          id INTEGER PRIMARY KEY,
          username VARCHAR(255) NOT NULL UNIQUE,
          source VARCHAR(64) DEFAULT '',
          notes TEXT DEFAULT '',
          created_at DATETIME
        )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_valid_users_username ON valid_users(username)"))

        # credentials table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS credentials (
          id INTEGER PRIMARY KEY,
          username VARCHAR(255),
          password VARCHAR(255),
          service VARCHAR(128) DEFAULT '',
          notes TEXT DEFAULT '',
          created_at DATETIME
        )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_credentials_service ON credentials(service)"))

        # social_media table
        conn.execute(text("""
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
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_social_media_platform ON social_media(platform)"))

        # web_urls table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS web_urls (
          id INTEGER PRIMARY KEY,
          url VARCHAR(2048) NOT NULL UNIQUE,
          domain VARCHAR(255),
          title VARCHAR(512) DEFAULT '',
          status_code INTEGER DEFAULT 0,
          notes TEXT DEFAULT '',
          created_at DATETIME
        )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_web_urls_domain ON web_urls(domain)"))

        # domain_info table for RDAP data
        conn.execute(text("""
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
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_domain_info_domain ON domain_info(domain)"))

        # dns_zone_transfers table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS dns_zone_transfers (
          id INTEGER PRIMARY KEY,
          domain VARCHAR(255),
          nameserver VARCHAR(255),
          status VARCHAR(64) DEFAULT '',
          created_at DATETIME
        )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_dns_zone_transfers_domain ON dns_zone_transfers(domain)"))

        # smtp_scans table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS smtp_scans (
          id INTEGER PRIMARY KEY,
          mx_host VARCHAR(255),
          vrfy VARCHAR(64) DEFAULT '',
          expn VARCHAR(64) DEFAULT '',
          rcpt VARCHAR(64) DEFAULT '',
          created_at DATETIME
        )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_smtp_scans_mx_host ON smtp_scans(mx_host)"))
