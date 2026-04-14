import os
import json
import time
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

BASE_URL = f"http://{os.getenv('HOST', '127.0.0.1')}:{os.getenv('PORT', '8000')}"

class BaseIoTDevice:
    def __init__(self, device_id: str, device_type: str, name: str, ip_address: str):
        self.device_id = device_id
        self.device_type = device_type
        self.name = name
        self.ip_address = ip_address
        self.aes_key = AESGCM.generate_key(bit_length=128)
        self.aes_key_hex = self.aes_key.hex()
        self.access_token = None

    def register(self) -> bool:
        """Register the device with the Gateway over the VPN API."""
        print(f"[{self.name}] Registering with Gateway...")
        payload = {
            "device_id": self.device_id,
            "device_type": self.device_type,
            "name": self.name,
            "ip_address": self.ip_address,
            "aes_key_hex": self.aes_key_hex
        }
        resp = requests.post(f"{BASE_URL}/device/register", json=payload)
        if resp.status_code == 200:
            print(f"[{self.name}] Registration successful.")
            return True
        print(f"[{self.name}] Registration failed: {resp.text}")
        return False

    def authenticate(self) -> bool:
        """Authenticate using device ID and AES key (as secret) to get JWT."""
        print(f"[{self.name}] Authenticating...")
        payload = {
            "device_id": self.device_id,
            "aes_key_hex": self.aes_key_hex
        }
        resp = requests.post(f"{BASE_URL}/device/auth", json=payload)
        if resp.status_code == 200:
            self.access_token = resp.json()["access_token"]
            print(f"[{self.name}] Authenticated. Got JWT token.")
            return True
        print(f"[{self.name}] Authentication failed: {resp.text}")
        return False

    def get_telemetry_data(self) -> dict:
        """Override this in subclasses."""
        raise NotImplementedError

    def encrypt_payload(self, plaintext_dict: dict) -> tuple[str, str]:
        """Encrypt payload using AES-128-GCM."""
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)
        plaintext = json.dumps(plaintext_dict).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce.hex(), ciphertext.hex()

    def send_telemetry(self):
        """Send encrypted telemetry to server."""
        if not self.access_token:
            print(f"[{self.name}] Cannot send telemetry, not authenticated.")
            return

        telemetry = self.get_telemetry_data()
        telemetry["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        nonce, ciphertext = self.encrypt_payload(telemetry)
        
        payload = {
            "device_id": self.device_id,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "encrypted": True
        }
        
        headers = {"Authorization": f"Bearer {self.access_token}"}
        resp = requests.post(f"{BASE_URL}/device/telemetry", json=payload, headers=headers)
        if resp.status_code == 200:
            print(f"[{self.name}] Telemetry sent successfully.")
        else:
            print(f"[{self.name}] Failed to send telemetry: {resp.text}")

    def run(self, interval: int = 5):
        """Main loop: register, auth, and send data continuously."""
        if not self.register():
            return
        if not self.authenticate():
            return
        
        print(f"[{self.name}] Starting telemetry loop (interval: {interval}s)...")
        try:
            while True:
                self.send_telemetry()
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n[{self.name}] Shutting down.")
