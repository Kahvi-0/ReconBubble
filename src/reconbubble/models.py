from __future__ import annotations
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, UniqueConstraint
from datetime import datetime
from .db import Base

class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    filename: Mapped[str] = mapped_column(String(260))
    stored_path: Mapped[str] = mapped_column(String(520))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class ScopeItem(Base):
    __tablename__ = "scope_items"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_scope_kind_value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # ip, subnet, domain, email_domain
    value: Mapped[str] = mapped_column(String(255), index=True)
    in_scope: Mapped[int] = mapped_column(Integer, default=1, index=True)
    note: Mapped[str] = mapped_column(String(255), default="")
    apply_all_subdomains: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class Subdomain(Base):
    __tablename__ = "subdomains"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fqdn: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    root_domain: Mapped[str] = mapped_column(String(255), index=True, default="")
    prowl_ips: Mapped[str] = mapped_column(Text, default="")
    prowl_registrar: Mapped[str] = mapped_column(String(255), default="")
    prowl_netblocks: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class Email(Base):
    __tablename__ = "emails"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class Host(Base):
    __tablename__ = "hosts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="", index=True)
    os_guess: Mapped[str] = mapped_column(String(255), default="")
    done: Mapped[int] = mapped_column(Integer, default=0)
    complete: Mapped[int] = mapped_column(Integer, default=0)
    waf: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    services: Mapped[list["Service"]] = relationship(back_populates="host", cascade="all, delete-orphan")

class Service(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("host_id", "port", "proto", name="uq_service_host_port_proto"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    proto: Mapped[str] = mapped_column(String(8), default="tcp", index=True)
    state: Mapped[str] = mapped_column(String(16), default="open", index=True)
    service_name: Mapped[str] = mapped_column(String(64), default="", index=True)
    product: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(255), default="")
    extra_info: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    host: Mapped["Host"] = relationship(back_populates="services")
    evidence: Mapped[list["ServiceEvidence"]] = relationship(back_populates="service", cascade="all, delete-orphan")

class ServiceEvidence(Base):
    __tablename__ = "service_evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    artifact_id: Mapped[int] = mapped_column(ForeignKey("artifacts.id"), index=True)
    raw_output: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    service: Mapped["Service"] = relationship(back_populates="evidence")

class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    artifact_id: Mapped[int] = mapped_column(ForeignKey("artifacts.id"), index=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    mime: Mapped[str] = mapped_column(String(128), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    meta_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    exif_json: Mapped[str] = mapped_column(Text, default="")

class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    object_type: Mapped[str] = mapped_column(String(32), index=True)
    object_id: Mapped[int] = mapped_column(Integer, index=True, default=0)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    tags: Mapped[str] = mapped_column(String(255), default="")
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class CloudItem(Base):
    __tablename__ = "cloud_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), default="", index=True)
    data_json: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class ValidUser(Base):
    __tablename__ = "valid_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(64), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(255), index=True)
    password: Mapped[str] = mapped_column(String(255))
    service: Mapped[str] = mapped_column(String(128), default="", index=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class SocialMedia(Base):
    __tablename__ = "social_media"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    platform: Mapped[str] = mapped_column(String(64), index=True)
    handle: Mapped[str] = mapped_column(String(255), index=True)
    url: Mapped[str] = mapped_column(String(512), default="")
    display_name: Mapped[str] = mapped_column(String(255), default="")
    bio: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    artifact_id: Mapped[int] = mapped_column(ForeignKey("artifacts.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class DomainInfo(Base):
    __tablename__ = "domain_info"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    registrar: Mapped[str] = mapped_column(String(255), default="")
    creation_date: Mapped[str] = mapped_column(String(64), default="")
    expiration_date: Mapped[str] = mapped_column(String(64), default="")
    name_servers: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(Text, default="")
    rdap_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class WebUrl(Base):
    __tablename__ = "web_urls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url: Mapped[str] = mapped_column(String(2048), unique=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class DnsZoneTransfer(Base):
    __tablename__ = "dns_zone_transfers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    nameserver: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

class SmtpScan(Base):
    __tablename__ = "smtp_scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mx_host: Mapped[str] = mapped_column(String(255), index=True)
    vrfy: Mapped[str] = mapped_column(String(64), default="")
    expn: Mapped[str] = mapped_column(String(64), default="")
    rcpt: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
