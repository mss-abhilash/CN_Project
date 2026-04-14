"""
Database models for the IoT Secure Home authentication system.
Uses SQLAlchemy ORM with SQLite backend.
"""

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text,
    ForeignKey, create_engine
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime, timezone

Base = declarative_base()


class User(Base):
    """
    User table storing credentials, TOTP secrets, and account state.

    Schema:
    -------
    id              : int (PK, auto-increment)
    username        : str (unique, indexed, max 50 chars)
    email           : str (unique, indexed, max 120 chars)
    hashed_password : str (bcrypt hash)
    totp_secret     : str (base32 encoded, generated at registration)
    is_verified     : bool (True after first successful TOTP verification)
    is_active       : bool (False if locked out by brute-force protection)
    failed_attempts : int (consecutive failed login attempts, resets on success)
    locked_until    : datetime (account lock expiry timestamp)
    created_at      : datetime (UTC timestamp)
    last_login      : datetime (UTC timestamp of last successful 2FA login)
    """
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username        = Column(String(50), unique=True, index=True, nullable=False)
    email           = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    totp_secret     = Column(String(32), nullable=False)
    is_verified     = Column(Boolean, default=False)  # TOTP setup completed
    is_active       = Column(Boolean, default=True)
    failed_attempts = Column(Integer, default=0)
    locked_until    = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login      = Column(DateTime, nullable=True)

    # Relationship to VPN peers
    vpn_peers = relationship("VPNPeer", back_populates="owner", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"


class LoginAuditLog(Base):
    """
    Immutable audit trail for every authentication attempt.
    Used for monitoring and forensic analysis.
    """
    __tablename__ = "login_audit_log"

    id         = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username   = Column(String(50), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    phase      = Column(String(10), nullable=False)  # "password" or "totp"
    success    = Column(Boolean, nullable=False)
    reason     = Column(Text, nullable=True)          # failure reason if any
    timestamp  = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<LoginAudit(user='{self.username}', phase='{self.phase}', ok={self.success})>"


class VPNPeer(Base):
    """
    WireGuard VPN peer configuration.
    Each peer is bound to an authenticated user (owner).

    Schema:
    -------
    id              : int (PK)
    peer_name       : str (unique identifier, e.g. 'iot-thermostat-001')
    owner_id        : int (FK → users.id)
    public_key      : str (Curve25519 public key, base64)
    private_key_enc : str (encrypted private key — stored encrypted at rest)
    preshared_key   : str (256-bit PSK, base64)
    assigned_ip     : str (VPN tunnel IP, e.g. '10.0.0.5')
    device_type     : str (thermostat, camera, lock, etc.)
    is_active       : bool (False = revoked)
    created_at      : datetime
    revoked_at      : datetime (set when deactivated)
    """
    __tablename__ = "vpn_peers"

    id              = Column(Integer, primary_key=True, index=True, autoincrement=True)
    peer_name       = Column(String(100), unique=True, index=True, nullable=False)
    owner_id        = Column(Integer, ForeignKey("users.id"), nullable=False)
    public_key      = Column(String(64), nullable=False)
    private_key_enc = Column(Text, nullable=False)           # Encrypted at rest
    preshared_key   = Column(String(64), nullable=False)
    assigned_ip     = Column(String(15), unique=True, nullable=False)
    device_type     = Column(String(50), default="generic")
    is_active       = Column(Boolean, default=True)
    created_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    revoked_at      = Column(DateTime, nullable=True)

    # Relationship back to owner
    owner = relationship("User", back_populates="vpn_peers")

    def __repr__(self):
        return f"<VPNPeer(name='{self.peer_name}', ip='{self.assigned_ip}', active={self.is_active})>"
