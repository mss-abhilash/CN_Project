"""
Full Demo Script
=================
Demonstrates the complete IoT VPN + 2FA pipeline end-to-end:

1. Register a user → get TOTP secret
2. Login (Phase 1) → get temporary token
3. Verify OTP (Phase 2) → get full access token
4. Access protected endpoint → /me
5. Simulate device fleet + gateway communication
6. Run attack simulations

Usage:
    python -m scripts.demo_full_flow

NOTE: The FastAPI server must be running on http://127.0.0.1:8000
"""

import os
import sys
import json
import time

import requests
import pyotp
from dotenv import load_dotenv

load_dotenv()

BASE_URL = f"http://{os.getenv('HOST', '127.0.0.1')}:{os.getenv('PORT', '8000')}"

DEMO_USER = {
    "username": "demo_user",
    "email": "demo@iothome.local",
    "password": "Demo!Secure#2024",
}


def banner(text: str):
    print(f"\n{'─' * 60}")
    print(f"  {text}")
    print(f"{'─' * 60}")


def step(num: int, desc: str):
    print(f"\n  [{num}] {desc}")
    print(f"  {'·' * 50}")


def main():
    banner("IoT VPN + 2FA — Full Demo Flow")
    print(f"  Server: {BASE_URL}")

    # ── Step 1: Health check ──────────────────────────────────
    step(1, "Health Check")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"    Status: {r.json()}")
    except requests.ConnectionError:
        print(f"    ✗ Server not reachable at {BASE_URL}")
        print(f"    Start it first: uvicorn backend.main:app --reload")
        sys.exit(1)

    # ── Step 2: Register user ─────────────────────────────────
    step(2, f"Register user: {DEMO_USER['username']}")
    r = requests.post(f"{BASE_URL}/register", json=DEMO_USER)
    if r.status_code == 201:
        data = r.json()
        totp_secret = data["totp_secret"]
        print(f"    ✓ Registered! TOTP secret: {totp_secret}")
    elif r.status_code == 409:
        print(f"    ⚠ User already exists, continuing with existing account")
        totp_secret = input("    Enter TOTP secret for existing user: ").strip()
        if not totp_secret:
            print("    ✗ No secret provided, exiting.")
            sys.exit(1)
    else:
        print(f"    ✗ Registration failed: {r.text}")
        sys.exit(1)

    # ── Step 3: Login (Phase 1) ───────────────────────────────
    step(3, "Login — Phase 1 (Password)")
    r = requests.post(f"{BASE_URL}/login", json={
        "username": DEMO_USER["username"],
        "password": DEMO_USER["password"],
    })
    if r.status_code != 200:
        print(f"    ✗ Login failed: {r.text}")
        sys.exit(1)
    phase1_token = r.json()["phase1_token"]
    print(f"    ✓ Phase 1 passed! Token: {phase1_token[:40]}...")

    # ── Step 4: Verify OTP (Phase 2) ──────────────────────────
    step(4, "Verify OTP — Phase 2 (TOTP)")
    totp = pyotp.TOTP(totp_secret)
    otp_code = totp.now()
    print(f"    Generated OTP: {otp_code}")

    r = requests.post(
        f"{BASE_URL}/verify-otp",
        json={"otp_code": otp_code},
        headers={"Authorization": f"Bearer {phase1_token}"},
    )
    if r.status_code != 200:
        print(f"    ✗ OTP verification failed: {r.text}")
        sys.exit(1)
    access_token = r.json()["access_token"]
    print(f"    ✓ Phase 2 passed! Full token: {access_token[:40]}...")

    # ── Step 5: Access protected resource ─────────────────────
    step(5, "Access Protected Endpoint — /me")
    r = requests.get(
        f"{BASE_URL}/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if r.status_code == 200:
        print(f"    ✓ User data: {json.dumps(r.json(), indent=6)}")
    else:
        print(f"    ✗ Access denied: {r.text}")

    # ── Step 6: Device + Gateway Demo ─────────────────────────
    step(6, "IoT Device → Gateway Communication")
    from iot_devices.device_simulator import create_device_fleet
    from gateway.gateway_core import Gateway

    gw = Gateway()
    fleet = create_device_fleet(3)

    for dev in fleet:
        gw.register_device(dev.device_id, dev.device_type.value, dev.name,
                           dev.ip_address, dev.aes_key)

    for dev in fleet:
        encrypted = dev.send_telemetry()
        decrypted = gw.decrypt_message(dev.device_id, encrypted["nonce"], encrypted["ciphertext"])
        if decrypted:
            print(f"    ✓ {dev.name}: {json.dumps(decrypted)}")

    banner("Demo Complete ✓")
    print(f"  All systems operational. Server: {BASE_URL}/docs\n")


if __name__ == "__main__":
    main()
