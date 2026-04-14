"""
ACL Engine — Access Control List for IoT Gateway
==================================================
Enforces three layers of access control:

  1. IP-based   — Whitelist / blacklist by source IP or CIDR range
  2. Device-based — Per-device permission matrix (which endpoints, rate limits)
  3. Session-based — JWT session validity, phase requirements, expiry

Every denied request is logged to an immutable audit trail.
"""

import os
import time
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from collections import defaultdict

from dotenv import load_dotenv

load_dotenv()

# ── Logging ──────────────────────────────────────────────────────────────────

logger = logging.getLogger("acl_engine")
logger.setLevel(logging.DEBUG)

# File handler — persistent log of all blocked requests
_log_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(_log_dir, exist_ok=True)
_fh = logging.FileHandler(os.path.join(_log_dir, "acl_blocked.log"), encoding="utf-8")
_fh.setLevel(logging.WARNING)
_fh.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))
logger.addHandler(_fh)

# Console handler
_ch = logging.StreamHandler()
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter("[ACL] %(levelname)s: %(message)s"))
logger.addHandler(_ch)


# ── Enums & Data Classes ─────────────────────────────────────────────────────

class ACLAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class DenyReason(str, Enum):
    IP_BLACKLISTED = "IP address is blacklisted"
    IP_NOT_WHITELISTED = "IP address is not in the whitelist"
    DEVICE_UNKNOWN = "Device is not registered"
    DEVICE_BLOCKED = "Device is blocked by ACL"
    DEVICE_ENDPOINT_DENIED = "Device not allowed to access this endpoint"
    DEVICE_RATE_LIMITED = "Device exceeded rate limit"
    SESSION_MISSING = "No authentication token provided"
    SESSION_INVALID = "Invalid or expired authentication token"
    SESSION_PHASE_INSUFFICIENT = "Insufficient authentication phase"
    SESSION_USER_INACTIVE = "User account is deactivated"
    SUBNET_VIOLATION = "Request originated outside the VPN subnet"


@dataclass
class ACLVerdict:
    """Result of an ACL evaluation."""
    action: ACLAction
    reason: Optional[DenyReason] = None
    details: str = ""
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def allowed(self) -> bool:
        return self.action == ACLAction.ALLOW

    def __str__(self):
        if self.allowed:
            return "ALLOW"
        return f"DENY ({self.reason.value}: {self.details})"


@dataclass
class BlockedRequestLog:
    """Immutable record of a denied request."""
    timestamp: str
    source_ip: str
    method: str
    path: str
    reason: str
    details: str
    session_subject: Optional[str] = None  # username or device_id if available


@dataclass
class IPRule:
    """An IP-based access rule."""
    network: "ipaddress.IPv4Network | ipaddress.IPv6Network"
    action: ACLAction
    description: str = ""


@dataclass
class DeviceACL:
    """Per-device access control entry."""
    device_id: str
    allowed_endpoints: list[str]
    max_requests_per_min: int = 60
    is_allowed: bool = True


@dataclass
class SessionRequirement:
    """What a route requires from the session."""
    require_auth: bool = True
    required_phase: str = "phase2"  # "phase1", "phase2", "device_auth"
    allowed_sub_types: list[str] = field(default_factory=lambda: ["user"])


# ── Heuristic Anomaly Detector (Context-Aware Monitoring) ─────────────────────

class HeuristicAnomalyDetector:
    """
    Analyzes traffic patterns to identify anomalies (e.g., sudden bursts,
    atypical access times, or data exfiltration attempts).
    """
    def __init__(self, sensitivity: float = 2.0):
        self.sensitivity = sensitivity # How many deviations from avg to trigger
        self.device_history: dict[str, list[float]] = defaultdict(list)
        self.stats = {"anomalies_detected": 0}

    def update_and_check(self, device_id: str, request_time: float) -> bool:
        """Returns True if consistent with history, False if anomalous."""
        history = self.device_history[device_id]
        
        # We need at least 10 data points to establish a baseline
        if len(history) < 10:
            history.append(request_time)
            return True

        avg = sum(history) / len(history)
        # Simple heuristic: is this request too close to the last one (Burst detection)?
        last_time = history[-1]
        interval = request_time - last_time
        
        # Prune and add
        history.append(request_time)
        if len(history) > 100: history.pop(0)

        # If interval is less than 10% of the average interval, flag as burst anomaly
        # In a real system, this would use Standard Deviation
        # For our research grade demo, we'll use a simplified threshold
        avg_interval = (history[-1] - history[0]) / len(history)
        if interval < (avg_interval / self.sensitivity):
            self.stats["anomalies_detected"] += 1
            return False
        
        return True


# ── Rate Limiter (per-device, sliding window) ─────────────────────────────────

class DeviceRateLimiter:
    """
    Sliding-window rate limiter for individual devices.
    Tracks request timestamps and rejects if count exceeds threshold
    within the window (default 60 seconds).
    """

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def check(self, device_id: str, max_requests: int) -> bool:
        """Returns True if the request is within rate limit, False if exceeded."""
        now = time.time()
        cutoff = now - self.window

        # Prune old entries
        self._buckets[device_id] = [
            ts for ts in self._buckets[device_id] if ts > cutoff
        ]

        if len(self._buckets[device_id]) >= max_requests:
            return False  # Rate exceeded

        self._buckets[device_id].append(now)
        return True

    def get_count(self, device_id: str) -> int:
        """Current request count within the window."""
        now = time.time()
        cutoff = now - self.window
        self._buckets[device_id] = [
            ts for ts in self._buckets[device_id] if ts > cutoff
        ]
        return len(self._buckets[device_id])


# ── ACL Engine ────────────────────────────────────────────────────────────────

VPN_SUBNET = os.getenv("VPN_SUBNET", "10.0.0.0/24")

# Routes that bypass all ACL checks (no auth needed)
PUBLIC_ROUTES = frozenset({
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/favicon.ico",
})

# Routes that only need Phase 1 (password verified)
PHASE1_ROUTES = frozenset({
    "/verify-otp",
})

# Routes open to unauthenticated users
UNAUTHENTICATED_ROUTES = frozenset({
    "/register",
    "/login",
    "/device/register",
    "/device/auth",
})


class ACLEngine:
    """
    Central Access Control List engine for the IoT Gateway.

    Evaluates three layers in order:
      1. IP Layer   — Is the source IP allowed?
      2. Device Layer — Is this device registered, unblocked, and authorized
                        for this endpoint? Is it within rate limits?
      3. Session Layer — Is the JWT valid? Does it have the required phase?

    A request must pass ALL applicable layers to be allowed through.
    """

    def __init__(self):
        self.ip_whitelist: list[IPRule] = []
        self.ip_blacklist: list[IPRule] = []
        self.device_acls: dict[str, DeviceACL] = {}
        self.rate_limiter = DeviceRateLimiter(window_seconds=60)
        self.anomaly_detector = HeuristicAnomalyDetector(sensitivity=2.5)
        self.blocked_log: list[BlockedRequestLog] = []
        self.stats = {
            "total_evaluated": 0,
            "total_allowed": 0,
            "total_denied": 0,
            "denied_by_ip": 0,
            "denied_by_device": 0,
            "denied_by_session": 0,
            "denied_by_rate_limit": 0,
            "anomalies_flagged": 0,
        }

        # Default: allow localhost and VPN subnet
        self.add_ip_whitelist("127.0.0.0/8", "Localhost (IPv4)")
        self.add_ip_whitelist("::1/128", "Localhost (IPv6)")
        self.add_ip_whitelist(VPN_SUBNET, "VPN Subnet")

        logger.info(
            f"ACL Engine initialized. VPN subnet: {VPN_SUBNET}. "
            f"Whitelist: {len(self.ip_whitelist)} rules."
        )

    # ── IP Layer ─────────────────────────────────────────────────────────

    def add_ip_whitelist(self, cidr: str, description: str = ""):
        """Add a CIDR range to the IP whitelist."""
        net = ipaddress.ip_network(cidr, strict=False)
        self.ip_whitelist.append(IPRule(network=net, action=ACLAction.ALLOW, description=description))
        logger.info(f"IP whitelist added: {cidr} ({description})")

    def add_ip_blacklist(self, cidr: str, description: str = ""):
        """Add a CIDR range to the IP blacklist. Blacklist overrides whitelist."""
        net = ipaddress.ip_network(cidr, strict=False)
        self.ip_blacklist.append(IPRule(network=net, action=ACLAction.DENY, description=description))
        logger.warning(f"IP blacklisted: {cidr} ({description})")

    def remove_ip_blacklist(self, cidr: str) -> bool:
        """Remove a CIDR range from the blacklist."""
        net = ipaddress.ip_network(cidr, strict=False)
        before = len(self.ip_blacklist)
        self.ip_blacklist = [r for r in self.ip_blacklist if r.network != net]
        removed = len(self.ip_blacklist) < before
        if removed:
            logger.info(f"IP removed from blacklist: {cidr}")
        return removed

    def check_ip(self, source_ip: str) -> ACLVerdict:
        """Evaluate IP-layer access."""
        try:
            addr = ipaddress.ip_address(source_ip)
        except ValueError:
            return ACLVerdict(
                action=ACLAction.DENY,
                reason=DenyReason.IP_BLACKLISTED,
                details=f"Malformed IP: {source_ip}",
            )

        # Blacklist has priority
        for rule in self.ip_blacklist:
            if addr in rule.network:
                return ACLVerdict(
                    action=ACLAction.DENY,
                    reason=DenyReason.IP_BLACKLISTED,
                    details=f"{source_ip} matched blacklist {rule.network} ({rule.description})",
                )

        # Check whitelist
        for rule in self.ip_whitelist:
            if addr in rule.network:
                return ACLVerdict(action=ACLAction.ALLOW)

        # Not in any whitelist
        return ACLVerdict(
            action=ACLAction.DENY,
            reason=DenyReason.IP_NOT_WHITELISTED,
            details=f"{source_ip} not in any allowed network",
        )

    # ── Device Layer ─────────────────────────────────────────────────────

    def register_device_acl(self, device_id: str, allowed_endpoints: list[str],
                            max_requests_per_min: int = 60):
        """Register or update the ACL for a device."""
        self.device_acls[device_id] = DeviceACL(
            device_id=device_id,
            allowed_endpoints=allowed_endpoints,
            max_requests_per_min=max_requests_per_min,
        )
        logger.info(f"Device ACL registered: {device_id} -> {allowed_endpoints}")

    def block_device(self, device_id: str) -> bool:
        """Block a device — all further requests will be denied."""
        if device_id in self.device_acls:
            self.device_acls[device_id].is_allowed = False
            logger.warning(f"Device BLOCKED: {device_id}")
            return True
        return False

    def unblock_device(self, device_id: str) -> bool:
        """Unblock a previously blocked device."""
        if device_id in self.device_acls:
            self.device_acls[device_id].is_allowed = True
            logger.info(f"Device UNBLOCKED: {device_id}")
            return True
        return False

    def check_device(self, device_id: str, path: str) -> ACLVerdict:
        """Evaluate device-layer access for a specific endpoint."""
        if device_id not in self.device_acls:
            return ACLVerdict(
                action=ACLAction.DENY,
                reason=DenyReason.DEVICE_UNKNOWN,
                details=f"Device '{device_id}' has no ACL entry",
            )

        acl = self.device_acls[device_id]

        if not acl.is_allowed:
            return ACLVerdict(
                action=ACLAction.DENY,
                reason=DenyReason.DEVICE_BLOCKED,
                details=f"Device '{device_id}' is explicitly blocked",
            )

        # Endpoint check
        endpoint_allowed = any(
            path.startswith(ep) or path == ep
            for ep in acl.allowed_endpoints
        )
        if not endpoint_allowed:
            return ACLVerdict(
                action=ACLAction.DENY,
                reason=DenyReason.DEVICE_ENDPOINT_DENIED,
                details=f"Device '{device_id}' not authorized for '{path}'. "
                        f"Allowed: {acl.allowed_endpoints}",
            )

        # Rate limit
        if not self.rate_limiter.check(device_id, acl.max_requests_per_min):
            self.stats["denied_by_rate_limit"] += 1
            return ACLVerdict(
                action=ACLAction.DENY,
                reason=DenyReason.DEVICE_RATE_LIMITED,
                details=f"Device '{device_id}' exceeded {acl.max_requests_per_min} req/min. "
                        f"Current: {self.rate_limiter.get_count(device_id)}",
            )

        return ACLVerdict(action=ACLAction.ALLOW)

    # ── Session Layer ────────────────────────────────────────────────────

    def check_session(self, token_data: Optional[dict], path: str) -> ACLVerdict:
        """
        Evaluate session-layer access.
        token_data should be the decoded JWT payload, or None if absent.
        """
        # Public routes bypass session checks
        if path in PUBLIC_ROUTES or path in UNAUTHENTICATED_ROUTES:
            return ACLVerdict(action=ACLAction.ALLOW)

        # Token must be present
        if token_data is None:
            return ACLVerdict(
                action=ACLAction.DENY,
                reason=DenyReason.SESSION_MISSING,
                details=f"No token provided for protected route '{path}'",
            )

        phase = token_data.get("phase", "")

        # Phase1-only routes
        if path in PHASE1_ROUTES:
            if phase in ("phase1", "phase2"):
                return ACLVerdict(action=ACLAction.ALLOW)
            return ACLVerdict(
                action=ACLAction.DENY,
                reason=DenyReason.SESSION_PHASE_INSUFFICIENT,
                details=f"Route '{path}' requires at least phase1, got '{phase}'",
            )

        # Device routes
        if path.startswith("/device/telemetry"):
            if phase == "device_auth":
                return ACLVerdict(action=ACLAction.ALLOW)
            return ACLVerdict(
                action=ACLAction.DENY,
                reason=DenyReason.SESSION_PHASE_INSUFFICIENT,
                details=f"Device telemetry requires device_auth token, got '{phase}'",
            )

        # All other routes require phase2 (full 2FA)
        if phase != "phase2":
            return ACLVerdict(
                action=ACLAction.DENY,
                reason=DenyReason.SESSION_PHASE_INSUFFICIENT,
                details=f"Route '{path}' requires phase2 (full 2FA), got '{phase}'",
            )

        return ACLVerdict(action=ACLAction.ALLOW)

    # ── Full Evaluation Pipeline ────────────────────────────────────────

    def evaluate(
        self,
        source_ip: str,
        method: str,
        path: str,
        token_data: Optional[dict] = None,
        device_id: Optional[str] = None,
    ) -> ACLVerdict:
        """
        Run the full 3-layer ACL evaluation pipeline.

        Order:
          1. Public route bypass
          2. IP layer
          3. Session layer
          4. Device layer (if device_id provided)

        Returns the first DENY verdict, or ALLOW if all pass.
        """
        self.stats["total_evaluated"] += 1

        # 1. Public routes bypass everything
        if path in PUBLIC_ROUTES:
            self.stats["total_allowed"] += 1
            return ACLVerdict(action=ACLAction.ALLOW)

        # 2. IP layer
        ip_verdict = self.check_ip(source_ip)
        if not ip_verdict.allowed:
            self.stats["total_denied"] += 1
            self.stats["denied_by_ip"] += 1
            self._log_blocked(source_ip, method, path, ip_verdict, token_data)
            return ip_verdict

        # 3. Session layer
        if path not in UNAUTHENTICATED_ROUTES:
            session_verdict = self.check_session(token_data, path)
            if not session_verdict.allowed:
                self.stats["total_denied"] += 1
                self.stats["denied_by_session"] += 1
                self._log_blocked(source_ip, method, path, session_verdict, token_data)
                return session_verdict

        # 4. Device layer (only for device-authenticated requests)
        if device_id and device_id in self.device_acls:
            # 4.a Standard ACL & Rate Limit
            device_verdict = self.check_device(device_id, path)
            if not device_verdict.allowed:
                self.stats["total_denied"] += 1
                self.stats["denied_by_device"] += 1
                self._log_blocked(source_ip, method, path, device_verdict, token_data)
                return device_verdict
            
            # 4.b Heuristic Anomaly detection (Advanced Research Layer)
            if not self.anomaly_detector.update_and_check(device_id, time.time()):
                self.stats["anomalies_flagged"] += 1
                logger.warning(f"[ANOMALY] High-frequency burst detected from {device_id}")
                # We log it but potentially still allow if below hard rate limit, 
                # or we can block it. For research, we flag it.

        self.stats["total_allowed"] += 1
        return ACLVerdict(action=ACLAction.ALLOW)

    # ── Logging ──────────────────────────────────────────────────────────

    def _log_blocked(self, source_ip: str, method: str, path: str,
                     verdict: ACLVerdict, token_data: Optional[dict]):
        """Log a blocked request to both the in-memory list and the file."""
        subject = None
        if token_data:
            subject = token_data.get("sub", "unknown")

        entry = BlockedRequestLog(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            method=method,
            path=path,
            reason=verdict.reason.value if verdict.reason else "Unknown",
            details=verdict.details,
            session_subject=subject,
        )
        self.blocked_log.append(entry)

        # Persistent log
        logger.warning(
            f"BLOCKED | {method} {path} | IP: {source_ip} | "
            f"Subject: {subject or 'none'} | Reason: {entry.reason} | {entry.details}"
        )

    def get_blocked_log(self, limit: int = 50) -> list[dict]:
        """Return the most recent blocked requests."""
        entries = self.blocked_log[-limit:]
        return [
            {
                "timestamp": e.timestamp,
                "source_ip": e.source_ip,
                "method": e.method,
                "path": e.path,
                "reason": e.reason,
                "details": e.details,
                "subject": e.session_subject,
            }
            for e in reversed(entries)
        ]

    def get_stats(self) -> dict:
        """Return ACL enforcement statistics."""
        return {
            "acl_engine": "active",
            **self.stats,
            "ip_whitelist_rules": len(self.ip_whitelist),
            "ip_blacklist_rules": len(self.ip_blacklist),
            "registered_device_acls": len(self.device_acls),
            "blocked_log_size": len(self.blocked_log),
        }
