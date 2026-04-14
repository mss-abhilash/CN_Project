"""
IoT VPN + Two-Phase Authentication — FastAPI Backend
=====================================================
Endpoints:
    POST /register         → Create account, get TOTP QR code
    POST /login            → Phase 1 (username + password) → returns temp token
    POST /verify-otp       → Phase 2 (TOTP code + temp token) → returns full JWT
    GET  /health           → Server health check
    GET  /me               → Protected route (requires phase2 token)
    POST /vpn/peers        → Create VPN peer (requires phase2 token)
    GET  /vpn/peers        → List user's VPN peers (requires phase2 token)
    GET  /vpn/peers/{name}/config → Download peer config (requires phase2 token)
    DELETE /vpn/peers/{name}      → Revoke VPN peer (requires phase2 token)
    GET  /vpn/status       → VPN server status (requires phase2 token)
    POST /device/register  → Register IoT device
    POST /device/auth      → Authenticate IoT device
    POST /device/telemetry → Send encrypted telemetry
    GET  /gateway/acl/stats   → ACL enforcement statistics
    GET  /gateway/acl/blocked → View blocked request log
    POST /gateway/acl/blacklist → Blacklist an IP
    DELETE /gateway/acl/blacklist → Remove IP from blacklist
    POST /gateway/acl/block-device → Block a device
    POST /gateway/acl/unblock-device → Unblock a device
"""

import os
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from dotenv import load_dotenv

load_dotenv()

from database.connection import get_db, init_db
from database.models import User, LoginAuditLog, VPNPeer
from backend.auth import (
    hash_password, verify_password,
    create_access_token, decode_token,
    generate_totp_secret, get_totp_uri, generate_qr_base64, verify_totp,
)
from backend.schemas import (
    UserRegisterRequest, UserLoginRequest, OTPVerifyRequest,
    RegisterResponse, LoginResponse, OTPVerifyResponse, ErrorResponse,
    VPNPeerCreateRequest, VPNPeerResponse, VPNPeerConfigResponse,
    VPNPeerListResponse, VPNPeerListItem, VPNStatusResponse,
    DeviceRegisterReq, DeviceAuthReq, DeviceAuthResp, TelemetryReq,
)
from vpn.wireguard_config import VPNManager, generate_keypair, generate_preshared_key, IPAddressPool
from gateway.gateway_core import Gateway
from gateway.acl_engine import ACLEngine
from gateway.security_middleware import GatewaySecurityMiddleware

# ── App Setup ─────────────────────────────────────────────────────────────────

RATE_LIMIT_LOGIN = os.getenv("RATE_LIMIT_LOGIN", "5/minute")
RATE_LIMIT_OTP   = os.getenv("RATE_LIMIT_OTP", "5/minute")
ACCOUNT_LOCK_MINUTES = 15
MAX_FAILED_ATTEMPTS  = 5

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="IoT Secure Home — Two-Phase Auth + VPN API",
    version="2.0.0",
    description="Two-phase authentication (password + TOTP) with WireGuard VPN for IoT home network",
)

# ── VPN, Gateway & ACL Managers (initialized at startup) ─────────────────
vpn_manager: VPNManager = None
gateway_core: Gateway = None
acl_engine: ACLEngine = None

app.state.limiter = limiter

# Security middleware is added FIRST so it runs before rate limiting
acl_engine = ACLEngine()
app.add_middleware(GatewaySecurityMiddleware, acl_engine=acl_engine)
app.add_middleware(SlowAPIMiddleware)

security = HTTPBearer()


@app.on_event("startup")
def on_startup():
    """Initialize database tables, VPN, Gateway, and ACL engine on first run."""
    global vpn_manager, gateway_core
    init_db()
    vpn_manager = VPNManager()
    gateway_core = Gateway()
    # Reload existing active peers from DB into the IP pool
    db = next(get_db())
    try:
        active_peers = db.query(VPNPeer).filter(VPNPeer.is_active == True).all()
        for peer in active_peers:
            vpn_manager.ip_pool.mark_used(peer.assigned_ip)
        print(
            f"[OK] Database initialized. VPN manager started. "
            f"{len(active_peers)} active peers loaded. ACL engine active."
        )
    finally:
        db.close()


# ── Custom exception handler for rate limiting ────────────────────────────────

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Rate limit exceeded. Too many attempts — try again later.",
    )


# ── Helper: Audit Logger ─────────────────────────────────────────────────────

def log_attempt(db: Session, username: str, ip: str, phase: str, success: bool, reason: str = None):
    """Write an immutable record of every auth attempt."""
    entry = LoginAuditLog(
        username=username,
        ip_address=ip,
        phase=phase,
        success=success,
        reason=reason,
    )
    db.add(entry)
    db.commit()


# ── Helper: Account Lockout Check ────────────────────────────────────────────

def check_lockout(user: User):
    """Raise 403 if the account is currently locked due to brute-force."""
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        remaining = (user.locked_until - datetime.now(timezone.utc)).seconds
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account locked due to too many failed attempts. Try again in {remaining}s.",
        )


# ══════════════════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

# ── Health Check ──────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health_check():
    return {"status": "healthy", "service": "IoT 2FA Auth Backend"}


# ── POST /register ────────────────────────────────────────────────────────────

@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    summary="Register a new user and receive TOTP setup QR code",
    responses={409: {"model": ErrorResponse}},
)
def register_user(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    """
    **Phase 0 — User Registration**

    1. Validates uniqueness of username and email.
    2. Hashes the password with bcrypt (12 rounds).
    3. Generates a TOTP secret and QR code for Google Authenticator.
    4. Returns the QR code (base64 PNG) and backup secret.
    """
    # Check for existing user
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="Username already registered")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    # Generate credentials
    hashed_pw   = hash_password(payload.password)
    totp_secret = generate_totp_secret()
    totp_uri    = get_totp_uri(totp_secret, payload.username)
    qr_b64      = generate_qr_base64(totp_uri)

    # Persist user
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hashed_pw,
        totp_secret=totp_secret,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return RegisterResponse(
        message="Registration successful. Scan the QR code with Google Authenticator.",
        username=user.username,
        totp_secret=totp_secret,
        totp_uri=totp_uri,
        qr_code_base64=qr_b64,
    )


# ── POST /login ──────────────────────────────────────────────────────────────

@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
    summary="Phase 1 — Verify username and password",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
@limiter.limit(RATE_LIMIT_LOGIN)
def login_user(payload: UserLoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    **Phase 1 — Password Authentication**

    1. Looks up the user by username.
    2. Checks for account lockout (brute-force protection).
    3. Verifies the bcrypt-hashed password.
    4. On success, returns a **temporary phase1 JWT** — valid ONLY for `/verify-otp`.
    5. On failure, increments the failed attempt counter; locks account after 5 failures.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Lookup user
    user = db.query(User).filter(User.username == payload.username).first()
    if not user:
        log_attempt(db, payload.username, client_ip, "password", False, "user not found")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Lockout check
    check_lockout(user)

    # Verify password
    if not verify_password(payload.password, user.hashed_password):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=ACCOUNT_LOCK_MINUTES)
            user.failed_attempts = 0
            db.commit()
            log_attempt(db, payload.username, client_ip, "password", False, "account locked")
            raise HTTPException(
                status_code=403,
                detail=f"Account locked for {ACCOUNT_LOCK_MINUTES} minutes due to too many failed attempts.",
            )
        db.commit()
        log_attempt(db, payload.username, client_ip, "password", False, "wrong password")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Success — issue phase1 (temporary) token
    user.failed_attempts = 0
    db.commit()

    log_attempt(db, payload.username, client_ip, "password", True)

    phase1_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=5),  # Short-lived: 5 min to complete Phase 2
        phase="phase1",
    )

    return LoginResponse(
        message="Password verified. Submit your TOTP code to complete authentication.",
        phase1_token=phase1_token,
        requires_otp=True,
    )


# ── POST /verify-otp ─────────────────────────────────────────────────────────

@app.post(
    "/verify-otp",
    response_model=OTPVerifyResponse,
    tags=["Authentication"],
    summary="Phase 2 — Verify TOTP code and get full access token",
    responses={401: {"model": ErrorResponse}},
)
@limiter.limit(RATE_LIMIT_OTP)
def verify_otp_endpoint(
    payload: OTPVerifyRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    **Phase 2 — TOTP Verification**

    1. Requires a valid **phase1 JWT** in the Authorization header.
    2. Extracts the username from the token.
    3. Verifies the 6-digit TOTP code against the user's secret.
    4. On success, issues a **full phase2 JWT** with standard expiry.
    5. Marks user as verified on their first successful TOTP entry.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Decode & validate the phase1 token
    token_data = decode_token(credentials.credentials)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if token_data.get("phase") != "phase1":
        raise HTTPException(status_code=401, detail="Invalid token phase. Use the phase1 token from /login.")

    username = token_data.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Malformed token — missing subject")

    # Lookup user
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Verify TOTP
    if not verify_totp(user.totp_secret, payload.otp_code):
        log_attempt(db, username, client_ip, "totp", False, "invalid OTP")
        raise HTTPException(status_code=401, detail="Invalid or expired OTP code")

    # Mark user as fully verified (first-time TOTP setup completion)
    if not user.is_verified:
        user.is_verified = True
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    log_attempt(db, username, client_ip, "totp", True)

    # Issue full-access phase2 token
    access_token = create_access_token(
        data={"sub": username},
        phase="phase2",
    )

    return OTPVerifyResponse(
        message="Authentication complete. Full access granted.",
        access_token=access_token,
        token_type="bearer",
        username=username,
    )


# ── GET /me (Protected Route — Requires Phase2 Token) ────────────────────────

@app.get(
    "/me",
    tags=["Protected"],
    summary="Get current authenticated user info (requires full 2FA)",
    responses={401: {"model": ErrorResponse}},
)
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    **Protected endpoint** — only accessible with a phase2 (fully authenticated) JWT.
    Demonstrates that the two-phase auth pipeline is enforced end-to-end.
    """
    token_data = decode_token(credentials.credentials)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if token_data.get("phase") != "phase2":
        raise HTTPException(status_code=401, detail="Incomplete authentication. Complete both phases first.")

    username = token_data.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return {
        "username": user.username,
        "email": user.email,
        "is_verified": user.is_verified,
        "is_active": user.is_active,
        "created_at": str(user.created_at),
        "last_login": str(user.last_login),
        "auth_phase": "phase2 (fully authenticated)",
        "vpn_peers": len([p for p in user.vpn_peers if p.is_active]),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  VPN ENDPOINTS (All require Phase2 authentication)
# ══════════════════════════════════════════════════════════════════════════════

def require_phase2_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> tuple[User, Session]:
    """
    Dependency: Extract and validate a phase2 user from the JWT.
    Returns (user, db_session).
    """
    token_data = decode_token(credentials.credentials)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if token_data.get("phase") != "phase2":
        raise HTTPException(status_code=401, detail="VPN access requires full 2FA. Complete both auth phases first.")
    username = token_data.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user, db


# ── POST /vpn/peers — Create a new VPN peer ──────────────────────────────────

@app.post(
    "/vpn/peers",
    response_model=VPNPeerResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["VPN"],
    summary="Create a new WireGuard VPN peer (requires full 2FA)",
    responses={401: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
def create_vpn_peer(
    payload: VPNPeerCreateRequest,
    auth: tuple = Depends(require_phase2_user),
):
    """
    **Create VPN Peer** — Only accessible after completing full two-phase authentication.

    1. Generates a Curve25519 keypair for the new peer.
    2. Assigns an IP address from the VPN subnet pool.
    3. Creates a preshared key for additional symmetric encryption.
    4. Persists the peer config to the database, bound to the authenticated user.
    5. Returns the peer info and a URL to download the .conf file.
    """
    user, db = auth

    # Check for duplicate peer name
    existing = db.query(VPNPeer).filter(VPNPeer.peer_name == payload.peer_name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Peer name '{payload.peer_name}' already exists")

    # Generate keys and assign IP
    try:
        peer = vpn_manager.create_peer(
            name=payload.peer_name,
            owner_username=user.username,
            device_type=payload.device_type,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # Persist to database
    db_peer = VPNPeer(
        peer_name=peer.name,
        owner_id=user.id,
        public_key=peer.public_key,
        private_key_enc=peer.private_key,  # In production, encrypt this at rest
        preshared_key=peer.preshared_key,
        assigned_ip=peer.allowed_ip,
        device_type=peer.device_type,
    )
    db.add(db_peer)
    db.commit()
    db.refresh(db_peer)

    # Export configs to disk
    vpn_manager.export_configs()

    return VPNPeerResponse(
        message=f"VPN peer '{peer.name}' created. Download the config to connect.",
        peer_name=peer.name,
        assigned_ip=peer.allowed_ip,
        public_key=peer.public_key,
        device_type=peer.device_type,
        config_download_url=f"/vpn/peers/{peer.name}/config",
    )


# ── GET /vpn/peers — List user's VPN peers ───────────────────────────────────

@app.get(
    "/vpn/peers",
    response_model=VPNPeerListResponse,
    tags=["VPN"],
    summary="List all VPN peers owned by the authenticated user",
)
def list_vpn_peers(auth: tuple = Depends(require_phase2_user)):
    """
    List all WireGuard peers belonging to the authenticated user.
    Includes both active and revoked peers.
    """
    user, db = auth
    peers = db.query(VPNPeer).filter(VPNPeer.owner_id == user.id).all()
    active = [p for p in peers if p.is_active]

    return VPNPeerListResponse(
        username=user.username,
        total_peers=len(peers),
        active_peers=len(active),
        peers=[
            VPNPeerListItem(
                peer_name=p.peer_name,
                assigned_ip=p.assigned_ip,
                device_type=p.device_type,
                is_active=p.is_active,
                created_at=str(p.created_at),
            )
            for p in peers
        ],
    )


# ── GET /vpn/peers/{peer_name}/config — Download peer config ─────────────────

@app.get(
    "/vpn/peers/{peer_name}/config",
    response_class=PlainTextResponse,
    tags=["VPN"],
    summary="Download WireGuard config file for a peer (requires full 2FA)",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
def download_peer_config(
    peer_name: str,
    auth: tuple = Depends(require_phase2_user),
):
    """
    **Download WireGuard Config** — Returns the .conf file content for import
    into the WireGuard client. Only the peer's owner can download.
    """
    user, db = auth

    db_peer = db.query(VPNPeer).filter(
        VPNPeer.peer_name == peer_name,
        VPNPeer.owner_id == user.id,
    ).first()

    if not db_peer:
        raise HTTPException(status_code=404, detail=f"Peer '{peer_name}' not found or access denied")
    if not db_peer.is_active:
        raise HTTPException(status_code=403, detail=f"Peer '{peer_name}' has been revoked")

    # Find the in-memory peer to generate config
    for mem_peer in vpn_manager.server.peers:
        if mem_peer.name == peer_name:
            config = vpn_manager.server.generate_peer_config(mem_peer)
            return PlainTextResponse(
                content=config,
                media_type="text/plain",
                headers={"Content-Disposition": f'attachment; filename="{peer_name}.conf"'},
            )

    # Fallback: reconstruct from DB
    from vpn.wireguard_config import WireGuardPeer as WGPeer
    mem_peer = WGPeer(
        name=db_peer.peer_name,
        public_key=db_peer.public_key,
        private_key=db_peer.private_key_enc,
        preshared_key=db_peer.preshared_key,
        allowed_ip=db_peer.assigned_ip,
        owner_username=user.username,
        device_type=db_peer.device_type,
    )
    config = vpn_manager.server.generate_peer_config(mem_peer)
    return PlainTextResponse(
        content=config,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{peer_name}.conf"'},
    )


# ── DELETE /vpn/peers/{peer_name} — Revoke a VPN peer ────────────────────────

@app.delete(
    "/vpn/peers/{peer_name}",
    tags=["VPN"],
    summary="Revoke a VPN peer (requires full 2FA)",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
def revoke_vpn_peer(
    peer_name: str,
    auth: tuple = Depends(require_phase2_user),
):
    """
    **Revoke VPN Peer** — Deactivates the peer and removes it from the
    server config. The peer's IP is released back to the pool.
    """
    user, db = auth

    db_peer = db.query(VPNPeer).filter(
        VPNPeer.peer_name == peer_name,
        VPNPeer.owner_id == user.id,
    ).first()

    if not db_peer:
        raise HTTPException(status_code=404, detail=f"Peer '{peer_name}' not found or access denied")
    if not db_peer.is_active:
        raise HTTPException(status_code=400, detail=f"Peer '{peer_name}' is already revoked")

    # Revoke in database
    db_peer.is_active = False
    db_peer.revoked_at = datetime.now(timezone.utc)
    db.commit()

    # Revoke in VPN manager (removes from server config, releases IP)
    vpn_manager.revoke_peer(peer_name)
    vpn_manager.export_configs()

    return {
        "message": f"VPN peer '{peer_name}' has been revoked.",
        "peer_name": peer_name,
        "revoked_at": str(db_peer.revoked_at),
    }


# ── GET /vpn/status — VPN server status ──────────────────────────────────────

@app.get(
    "/vpn/status",
    response_model=VPNStatusResponse,
    tags=["VPN"],
    summary="Get WireGuard VPN server status (requires full 2FA)",
)
def vpn_status(auth: tuple = Depends(require_phase2_user)):
    """
    **VPN Status** — Returns the gateway's public key, subnet info,
    and peer count. Useful for monitoring.
    """
    status_data = vpn_manager.get_server_status()
    return VPNStatusResponse(**status_data)

# ══════════════════════════════════════════════════════════════════════════════
#  IoT DEVICE ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

def require_device(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Dependency: Validates device JWT and returns the device_id."""
    token_data = decode_token(credentials.credentials)
    if not token_data or token_data.get("sub_type") != "device":
        raise HTTPException(status_code=401, detail="Invalid device token")
    return token_data.get("sub")


@app.post(
    "/device/register",
    tags=["IoT Devices"],
    summary="Register a new device to the gateway",
)
def register_device(payload: DeviceRegisterReq):
    """Register an IoT device with the Gateway core."""
    key_bytes = bytes.fromhex(payload.aes_key_hex)
    success = gateway_core.register_device(
        payload.device_id, payload.device_type,
        payload.name, payload.ip_address, key_bytes
    )
    if not success:
        raise HTTPException(status_code=400, detail="Failed to register device")

    # Sync device ACL — allow only telemetry, heartbeat, status endpoints
    acl_engine.register_device_acl(
        device_id=payload.device_id,
        allowed_endpoints=["/device/telemetry", "/device/heartbeat", "/device/status"],
        max_requests_per_min=60,
    )

    return {"message": f"Device {payload.device_id} registered"}


@app.post(
    "/device/auth",
    response_model=DeviceAuthResp,
    tags=["IoT Devices"],
    summary="Authenticate a device",
)
def auth_device(payload: DeviceAuthReq):
    """Authenticate device using its AES key as secret, returning a JWT token."""
    record = gateway_core.devices.get(payload.device_id)
    if not record or record.aes_key.hex() != payload.aes_key_hex:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token(
        data={"sub": payload.device_id, "sub_type": "device"},
        expires_delta=timedelta(hours=24), # Long-lived token for devices
        phase="device_auth"
    )
    return DeviceAuthResp(access_token=token)


@app.post(
    "/device/telemetry",
    tags=["IoT Devices"],
    summary="Send encrypted telemetry",
)
def receive_telemetry(
    payload: TelemetryReq,
    device_id: str = Depends(require_device)
):
    """Receive and decrypt IoT telemetry using Gateway core."""
    if payload.device_id != device_id:
        raise HTTPException(status_code=403, detail="Device ID mismatch")
    
    decrypted = gateway_core.decrypt_message(
        payload.device_id, payload.nonce, payload.ciphertext
    )
    if decrypted is None:
        raise HTTPException(status_code=400, detail="Decryption failed or blocked by ACL")
    
    return {"message": "Telemetry received and decrypted", "data": decrypted}


# ══════════════════════════════════════════════════════════════════════════════
#  GATEWAY ACL ADMIN ENDPOINTS (require Phase2 authentication)
# ══════════════════════════════════════════════════════════════════════════════


@app.get(
    "/gateway/acl/stats",
    tags=["Gateway ACL"],
    summary="View ACL enforcement statistics (requires full 2FA)",
)
def acl_stats(auth: tuple = Depends(require_phase2_user)):
    """Returns total evaluations, allowed/denied counts, and breakdown by layer."""
    return acl_engine.get_stats()


@app.get(
    "/gateway/acl/blocked",
    tags=["Gateway ACL"],
    summary="View recent blocked requests (requires full 2FA)",
)
def acl_blocked_log(
    limit: int = 50,
    auth: tuple = Depends(require_phase2_user),
):
    """Returns the most recent blocked/denied requests from the ACL log."""
    return {
        "total_blocked": len(acl_engine.blocked_log),
        "showing": min(limit, len(acl_engine.blocked_log)),
        "entries": acl_engine.get_blocked_log(limit),
    }


@app.post(
    "/gateway/acl/blacklist",
    tags=["Gateway ACL"],
    summary="Blacklist an IP address or CIDR range (requires full 2FA)",
)
def acl_blacklist_ip(
    ip_cidr: str,
    description: str = "Manual blacklist",
    auth: tuple = Depends(require_phase2_user),
):
    """Add an IP or CIDR to the blacklist. Blacklisted IPs are denied before any auth check."""
    try:
        acl_engine.add_ip_blacklist(ip_cidr, description)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {e}")
    return {
        "message": f"IP/CIDR '{ip_cidr}' has been blacklisted.",
        "blacklist_rules": len(acl_engine.ip_blacklist),
    }


@app.delete(
    "/gateway/acl/blacklist",
    tags=["Gateway ACL"],
    summary="Remove an IP from the blacklist (requires full 2FA)",
)
def acl_un_blacklist_ip(
    ip_cidr: str,
    auth: tuple = Depends(require_phase2_user),
):
    """Remove an IP or CIDR from the blacklist."""
    removed = acl_engine.remove_ip_blacklist(ip_cidr)
    if not removed:
        raise HTTPException(status_code=404, detail=f"'{ip_cidr}' was not in the blacklist")
    return {
        "message": f"IP/CIDR '{ip_cidr}' removed from blacklist.",
        "blacklist_rules": len(acl_engine.ip_blacklist),
    }


@app.post(
    "/gateway/acl/block-device",
    tags=["Gateway ACL"],
    summary="Block a device by ID (requires full 2FA)",
)
def acl_block_device(
    device_id: str,
    auth: tuple = Depends(require_phase2_user),
):
    """Block a device — all further requests from this device will be denied."""
    # Block in both ACL engine and gateway core
    acl_blocked = acl_engine.block_device(device_id)
    gw_blocked = gateway_core.block_device(device_id)
    if not acl_blocked and not gw_blocked:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")
    return {"message": f"Device '{device_id}' has been blocked.", "device_id": device_id}


@app.post(
    "/gateway/acl/unblock-device",
    tags=["Gateway ACL"],
    summary="Unblock a device by ID (requires full 2FA)",
)
def acl_unblock_device(
    device_id: str,
    auth: tuple = Depends(require_phase2_user),
):
    """Re-enable a previously blocked device."""
    acl_unblocked = acl_engine.unblock_device(device_id)
    gw_unblocked = gateway_core.unblock_device(device_id)
    if not acl_unblocked and not gw_unblocked:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")
    return {"message": f"Device '{device_id}' has been unblocked.", "device_id": device_id}

