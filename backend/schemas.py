"""
Pydantic schemas for request validation and response serialization.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional


# ── Request Schemas ───────────────────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$",
                          description="Alphanumeric username (3-50 chars)")
    email: str = Field(..., max_length=120, description="Valid email address")
    password: str = Field(..., min_length=8, max_length=128,
                          description="Password (min 8 chars)")

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "username": "admin_user",
                "email": "admin@iothome.local",
                "password": "Str0ng!Pass#2024"
            }]
        }
    }


class UserLoginRequest(BaseModel):
    username: str = Field(..., description="Registered username")
    password: str = Field(..., description="Account password")

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "username": "admin_user",
                "password": "Str0ng!Pass#2024"
            }]
        }
    }


class OTPVerifyRequest(BaseModel):
    otp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$",
                          description="6-digit TOTP code from authenticator app")

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "otp_code": "482913"
            }]
        }
    }


# ── Response Schemas ──────────────────────────────────────────────────────────

class RegisterResponse(BaseModel):
    message: str
    username: str
    totp_secret: str = Field(..., description="Base32 secret — save this as backup")
    totp_uri: str = Field(..., description="otpauth:// URI for manual entry")
    qr_code_base64: str = Field(..., description="Base64-encoded PNG QR code")


class LoginResponse(BaseModel):
    message: str
    phase1_token: str = Field(..., description="Temporary JWT — only valid for /verify-otp")
    requires_otp: bool = True


class OTPVerifyResponse(BaseModel):
    message: str
    access_token: str = Field(..., description="Full-access JWT (phase2)")
    token_type: str = "bearer"
    username: str


class ErrorResponse(BaseModel):
    detail: str


# ── VPN Schemas ───────────────────────────────────────────────────────────────

class VPNPeerCreateRequest(BaseModel):
    peer_name: str = Field(..., min_length=3, max_length=100,
                           pattern=r"^[a-zA-Z0-9_\-]+$",
                           description="Unique peer name (e.g. 'iot-thermostat-001')")
    device_type: str = Field("generic", max_length=50,
                             description="Device type: thermostat, camera, lock, sensor, etc.")

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "peer_name": "iot-thermostat-001",
                "device_type": "thermostat"
            }]
        }
    }


class VPNPeerResponse(BaseModel):
    message: str
    peer_name: str
    assigned_ip: str
    public_key: str
    device_type: str
    config_download_url: str = Field(..., description="URL to download the .conf file")


class VPNPeerConfigResponse(BaseModel):
    peer_name: str
    config_content: str = Field(..., description="Full WireGuard .conf file content")
    assigned_ip: str


class VPNPeerListItem(BaseModel):
    peer_name: str
    assigned_ip: str
    device_type: str
    is_active: bool
    created_at: str


class VPNPeerListResponse(BaseModel):
    username: str
    total_peers: int
    active_peers: int
    peers: list[VPNPeerListItem]


class VPNStatusResponse(BaseModel):
    server_public_key: str
    listen_port: int
    gateway_ip: str
    subnet: str
    total_peers: int
    active_peers: int
    available_ips: int


# ── IoT Device Schemas ────────────────────────────────────────────────────────

class DeviceRegisterReq(BaseModel):
    device_id: str = Field(..., description="Unique device ID")
    device_type: str = Field(..., description="Type of device (e.g. smart_camera)")
    name: str = Field(..., description="Human readable name")
    ip_address: str = Field(..., description="VPN assigned IP")
    aes_key_hex: str = Field(..., description="128-bit AES key in hex")

class DeviceAuthReq(BaseModel):
    device_id: str = Field(..., description="Unique device ID")
    aes_key_hex: str = Field(..., description="Acts as device secret")

class DeviceAuthResp(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TelemetryReq(BaseModel):
    device_id: str
    nonce: str
    ciphertext: str
    encrypted: bool


