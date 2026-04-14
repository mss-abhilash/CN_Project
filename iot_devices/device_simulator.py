"""
IoT Device Simulator
=====================
Simulates IoT devices (sensors, cameras, thermostats) that communicate
with the gateway using lightweight ECC + AES encrypted messages.
"""

import os
import json
import time
import random
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class DeviceType(str, Enum):
    TEMPERATURE_SENSOR = "temperature_sensor"
    HUMIDITY_SENSOR = "humidity_sensor"
    MOTION_DETECTOR = "motion_detector"
    SMART_CAMERA = "smart_camera"
    SMART_LOCK = "smart_lock"
    THERMOSTAT = "thermostat"


@dataclass
class IoTDevice:
    """Represents a simulated IoT device on the home network."""
    device_id: str
    device_type: DeviceType
    name: str
    ip_address: str
    aes_key: bytes = field(default_factory=lambda: AESGCM.generate_key(bit_length=128))
    is_registered: bool = False
    is_online: bool = True
    last_heartbeat: Optional[datetime] = None

    def generate_telemetry(self) -> dict:
        """Generate realistic sensor telemetry based on device type."""
        now = datetime.now(timezone.utc).isoformat()
        base = {"device_id": self.device_id, "type": self.device_type.value, "timestamp": now}

        if self.device_type == DeviceType.TEMPERATURE_SENSOR:
            base["temperature_c"] = round(random.uniform(18.0, 32.0), 1)
            base["unit"] = "celsius"
        elif self.device_type == DeviceType.HUMIDITY_SENSOR:
            base["humidity_pct"] = round(random.uniform(30.0, 80.0), 1)
        elif self.device_type == DeviceType.MOTION_DETECTOR:
            base["motion_detected"] = random.choice([True, False])
            base["confidence"] = round(random.uniform(0.7, 1.0), 2)
        elif self.device_type == DeviceType.SMART_CAMERA:
            base["recording"] = True
            base["fps"] = random.choice([15, 24, 30])
        elif self.device_type == DeviceType.SMART_LOCK:
            base["locked"] = random.choice([True, True, True, False])  # Mostly locked
            base["battery_pct"] = random.randint(10, 100)
        elif self.device_type == DeviceType.THERMOSTAT:
            base["set_temp_c"] = round(random.uniform(20.0, 26.0), 1)
            base["current_temp_c"] = round(random.uniform(18.0, 30.0), 1)
            base["mode"] = random.choice(["heating", "cooling", "auto", "off"])

        return base

    def encrypt_message(self, plaintext: str) -> tuple[bytes, bytes]:
        """
        Encrypt a message using AES-128-GCM.
        Returns (nonce, ciphertext).
        """
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)   # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce, ciphertext

    def send_telemetry(self) -> dict:
        """Generate, encrypt, and package telemetry for transmission."""
        telemetry = self.generate_telemetry()
        plaintext = json.dumps(telemetry)
        nonce, ciphertext = self.encrypt_message(plaintext)
        self.last_heartbeat = datetime.now(timezone.utc)

        return {
            "device_id": self.device_id,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "encrypted": True,
        }


def create_device_fleet(count: int = 5) -> list[IoTDevice]:
    """Create a fleet of diverse simulated IoT devices."""
    device_types = list(DeviceType)
    devices = []
    for i in range(count):
        dtype = device_types[i % len(device_types)]
        device = IoTDevice(
            device_id=f"dev-{secrets.token_hex(4)}",
            device_type=dtype,
            name=f"{dtype.value.replace('_', ' ').title()} #{i+1}",
            ip_address=f"10.0.0.{20 + i}",
        )
        devices.append(device)
    return devices


if __name__ == "__main__":
    print("=" * 60)
    print("  IoT Device Simulator — Fleet Demo")
    print("=" * 60)
    fleet = create_device_fleet(6)
    for dev in fleet:
        telemetry = dev.generate_telemetry()
        encrypted = dev.send_telemetry()
        print(f"\n[{dev.name}] ({dev.ip_address})")
        print(f"  Plaintext : {json.dumps(telemetry, indent=2)}")
        print(f"  Encrypted : {encrypted['ciphertext'][:64]}...")
