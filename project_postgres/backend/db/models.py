from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String, default="user")  # "admin" or "user"
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    scans = relationship("Scan", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")

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
