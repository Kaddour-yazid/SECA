from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    sex = Column(String, nullable=True)
    department = Column(String, nullable=True)
    group_name = Column(String, nullable=True)
    role = Column(String, default="user")  # "admin" or "user"
    is_admin = Column(Boolean, default=False)
    admin_department = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    scans = relationship("Scan", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    otp_requests = relationship("EmailOtp", back_populates="user")
    ip_assignments = relationship("UserIpAssignment", back_populates="user")
    gateway_events = relationship("GatewayTrafficEvent", back_populates="user")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    scan_type = Column(String)
    target = Column(String)
    status = Column(String)
    threat_score = Column(Integer)
    details = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="scans")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="audit_logs")


class AppHistoryEvent(Base):
    __tablename__ = "app_history_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    category = Column(String, index=True, nullable=False, default="audit")
    title = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    source_table = Column(String, nullable=True, index=True)
    source_id = Column(Integer, nullable=True, index=True)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class PhishTankEntry(Base):
    __tablename__ = "phishtank_entries"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    phish_id = Column(String)
    verified = Column(Boolean, default=False)
    submission_time = Column(DateTime)
    last_checked = Column(DateTime, default=datetime.utcnow)


class ThreatUrl(Base):
    """
    Threat feed entries stored in PostgreSQL.
    URLs are stored encrypted; lookups are done by SHA-256 hash.
    """
    __tablename__ = "threat_urls"
    id = Column(Integer, primary_key=True, index=True)
    url_hash = Column(String(64), unique=True, index=True, nullable=False)
    url_encrypted = Column(Text, nullable=False)
    domain = Column(String, index=True, nullable=True)
    domain_hash = Column(String(64), index=True, nullable=True)
    threat_type = Column(String, nullable=True)
    source = Column(String, nullable=True)
    verified = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ProxyBlockRule(Base):
    __tablename__ = "proxy_block_rules"

    id = Column(Integer, primary_key=True, index=True)
    pattern = Column(String, unique=True, index=True, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DesktopDevice(Base):
    __tablename__ = "desktop_devices"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, unique=True, index=True, nullable=False)
    hostname = Column(String, nullable=True)
    platform = Column(String, nullable=True)
    app_version = Column(String, nullable=True)
    local_ips = Column(Text, nullable=True)
    last_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    last_department = Column(String, nullable=True)
    last_group_name = Column(String, nullable=True)
    proxy_host = Column(String, nullable=True)
    proxy_port = Column(Integer, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


class DesktopSession(Base):
    __tablename__ = "desktop_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    device_id = Column(String, nullable=False, index=True)
    hostname = Column(String, nullable=True)
    platform = Column(String, nullable=True)
    app_version = Column(String, nullable=True)
    department = Column(String, nullable=True)
    group_name = Column(String, nullable=True)
    proxy_host = Column(String, nullable=True)
    proxy_port = Column(Integer, nullable=True)
    local_ips = Column(Text, nullable=True)
    online = Column(Boolean, default=True, nullable=False)
    disconnect_reason = Column(String, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    last_heartbeat_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)


class UserIpAssignment(Base):
    __tablename__ = "user_ip_assignments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    device_id = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True)
    hostname = Column(String, nullable=True)
    department = Column(String, nullable=True)
    group_name = Column(String, nullable=True)
    attribution_source = Column(String, nullable=False, default="desktop-session")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="ip_assignments")


class GatewayTrafficEvent(Base):
    __tablename__ = "gateway_traffic_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    user_email = Column(String, nullable=True, index=True)
    user_name = Column(String, nullable=True)
    department = Column(String, nullable=True, index=True)
    group_name = Column(String, nullable=True, index=True)
    device_id = Column(String, nullable=True, index=True)
    hostname = Column(String, nullable=True)
    client_ip = Column(String, nullable=False, index=True)
    method = Column(String, nullable=True)
    protocol = Column(String, nullable=True)
    host = Column(String, nullable=True, index=True)
    port = Column(Integer, nullable=True)
    blocked = Column(Boolean, default=False, nullable=False, index=True)
    target = Column(Text, nullable=True)
    scan_url = Column(Text, nullable=True)
    static_status = Column(String, nullable=True)
    static_threat_score = Column(Integer, nullable=True)
    static_match_type = Column(String, nullable=True)
    static_source = Column(String, nullable=True)
    block_reason = Column(String, nullable=True)
    attribution_source = Column(String, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", back_populates="gateway_events")


class GroupProxyAssignment(Base):
    __tablename__ = "group_proxy_assignments"

    id = Column(Integer, primary_key=True, index=True)
    department = Column(String, index=True, nullable=False)
    group_name = Column(String, index=True, nullable=False)
    proxy_host = Column(String, nullable=False)
    proxy_port = Column(Integer, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ExternalReputationCache(Base):
    __tablename__ = "external_reputation_cache"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, index=True, nullable=False)
    lookup_key = Column(String, index=True, nullable=False)
    status = Column(String, nullable=False, default="miss")
    payload = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EmailOtp(Base):
    __tablename__ = "email_otps"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    email = Column(String, index=True, nullable=False)
    purpose = Column(String, index=True, nullable=False)
    code_hash = Column(String, nullable=False)
    password_hash = Column(String, nullable=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    sex = Column(String, nullable=True)
    department = Column(String, nullable=True)
    group_name = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    consumed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="otp_requests")
