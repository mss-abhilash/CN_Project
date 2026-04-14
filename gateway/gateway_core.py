"""
Gateway Core
=============
Central IoT gateway that:
- Registers and manages IoT devices
- Enforces ACL (Access Control Lists)
- Decrypts device messages using shared AES keys
- Logs all device communication
"""

import os
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

GATEWAY_ID       = os.getenv("GATEWAY_ID", "gw-home-001")
MAX_IOT_DEVICES  = int(os.getenv("MAX_IOT_DEVICES", "50"))


@dataclass
class ACLRule:
    """Access control rule for a device."""
    device_id: str
    allowed_endpoints: list[str]     # e.g., ["/telemetry", "/heartbeat"]
    max_requests_per_min: int = 60
    is_allowed: bool = True


@dataclass
class DeviceRecord:
    """Internal record of a registered IoT device."""
    device_id: str
    device_type: str
    name: str
    ip_address: str
    aes_key: bytes
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: Optional[datetime] = None
    acl: Optional[ACLRule] = None


class Gateway:
    """
    Central IoT Gateway — manages device registration, message decryption,
    ACL enforcement, and activity logging.
    """

    def __init__(self):
        self.gateway_id = GATEWAY_ID
        self.devices: dict[str, DeviceRecord] = {}
        self.message_log: list[dict] = []
        self.started_at = datetime.now(timezone.utc)
        print(f"[GW] Gateway '{self.gateway_id}' initialized at {self.started_at.isoformat()}")

    @property
    def device_count(self) -> int:
        return len(self.devices)

    def register_device(self, device_id: str, device_type: str, name: str,
                        ip_address: str, aes_key: bytes) -> bool:
        """Register an IoT device with the gateway."""
        if self.device_count >= MAX_IOT_DEVICES:
            print(f"[GW] ERROR: Device limit reached ({MAX_IOT_DEVICES})")
            return False

        if device_id in self.devices:
            print(f"[GW] ERROR: Device '{device_id}' already registered")
            return False

        record = DeviceRecord(
            device_id=device_id,
            device_type=device_type,
            name=name,
            ip_address=ip_address,
            aes_key=aes_key,
            acl=ACLRule(
                device_id=device_id,
                allowed_endpoints=["/telemetry", "/heartbeat", "/status"],
            ),
        )
        self.devices[device_id] = record
        print(f"[GW] SUCCESS: Registered '{name}' ({device_id}) @ {ip_address}")
        return True

    def decrypt_message(self, device_id: str, nonce_hex: str, ciphertext_hex: str) -> Optional[dict]:
        """Decrypt an AES-128-GCM encrypted message from a registered device."""
        if device_id not in self.devices:
            print(f"[GW] ERROR: Unknown device: {device_id}")
            return None

        record = self.devices[device_id]

        # ACL check
        if record.acl and not record.acl.is_allowed:
            print(f"[GW] ERROR: Device '{device_id}' is blocked by ACL")
            return None

        try:
            aesgcm = AESGCM(record.aes_key)
            nonce = bytes.fromhex(nonce_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            data = json.loads(plaintext.decode("utf-8"))

            # Update last seen
            record.last_seen = datetime.now(timezone.utc)

            # Log the message
            self.message_log.append({
                "device_id": device_id,
                "timestamp": record.last_seen.isoformat(),
                "data": data,
            })

            print(f"[GW] SUCCESS: Message decrypted from '{record.name}'")
            return data

        except Exception as e:
            print(f"[GW] ERROR: Decryption failed for '{device_id}': {e}")
            return None

    def block_device(self, device_id: str) -> bool:
        """Block a device via ACL (e.g., after detecting an attack)."""
        if device_id in self.devices and self.devices[device_id].acl:
            self.devices[device_id].acl.is_allowed = False
            print(f"[GW] BLOCKED: Device '{device_id}' BLOCKED")
            return True
        return False

    def unblock_device(self, device_id: str) -> bool:
        """Unblock a previously blocked device."""
        if device_id in self.devices and self.devices[device_id].acl:
            self.devices[device_id].acl.is_allowed = True
            print(f"[GW] RESTORED: Device '{device_id}' UNBLOCKED")
            return True
        return False

    def get_status(self) -> dict:
        """Return gateway status summary."""
        return {
            "gateway_id": self.gateway_id,
            "uptime_since": self.started_at.isoformat(),
            "registered_devices": self.device_count,
            "max_devices": MAX_IOT_DEVICES,
            "messages_processed": len(self.message_log),
        }


if __name__ == "__main__":
    print("=" * 60)
    print("  IoT Gateway — Standalone Test")
    print("=" * 60)
    gw = Gateway()
    print(f"\nStatus: {json.dumps(gw.get_status(), indent=2)}")
