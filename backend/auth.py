"""
Authentication utilities:
- Password hashing (bcrypt via passlib)
- JWT token creation & verification
- TOTP secret generation, QR URI provisioning, and OTP validation
"""

import os
import io
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional

import pyotp
import qrcode
from passlib.context import CryptContext
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

# ── Password Hashing ─────────────────────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ── JWT Tokens ────────────────────────────────────────────────────────────────

SECRET_KEY     = os.getenv("JWT_SECRET_KEY", "INSECURE_FALLBACK_KEY")
ALGORITHM      = os.getenv("JWT_ALGORITHM", "HS256")
EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    phase: str = "phase1"
) -> str:
    """
    Create a signed JWT.
    
    Args:
        data: Payload claims (must include 'sub' for username).
        expires_delta: Custom expiry; defaults to JWT_EXPIRE_MINUTES.
        phase: 'phase1' (password verified) or 'phase2' (fully authenticated).
    
    The 'phase' claim is critical — phase1 tokens can ONLY be used
    to call /verify-otp. Full API access requires a phase2 token.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "phase": phase,
        "iat": datetime.now(timezone.utc),
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT. Returns the payload dict or None if invalid.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ── TOTP (Google Authenticator Compatible) ────────────────────────────────────

TOTP_ISSUER = os.getenv("TOTP_ISSUER", "IoTSecureHome")


def generate_totp_secret() -> str:
    """Generate a random base32 TOTP secret (160-bit)."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """
    Build an otpauth:// URI for QR code scanning.
    Compatible with Google Authenticator, Authy, etc.
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def generate_qr_base64(uri: str) -> str:
    """
    Generate a QR code image from a TOTP URI and return it
    as a base64-encoded PNG string (for embedding in JSON responses).
    """
    qr = qrcode.QRCode(version=1, box_size=6, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode("utf-8")


def verify_totp(secret: str, otp_code: str) -> bool:
    """
    Verify a 6-digit TOTP code.
    Allows ±1 time-step window (30s) to handle clock drift.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(otp_code, valid_window=1)
