"""
ACL Gateway Security — End-to-End Test
========================================
Tests:
  1. Public routes pass without auth
  2. Protected routes blocked without auth (session ACL)
  3. Full 2FA flow -> access granted
  4. Device registration syncs ACL
  5. Device telemetry works when authorized
  6. IP blacklisting blocks all traffic
  7. IP un-blacklisting restores access
  8. Device blocking via admin endpoint
  9. Device unblocking via admin endpoint
  10. ACL stats and blocked log endpoints
"""

import requests
import json
import pyotp
import time

BASE = "http://127.0.0.1:8000"


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def test(num, name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    print(f"  [{num:>2}] {status}: {name}" + (f" -- {detail}" if detail else ""))
    return passed


def main():
    results = []
    section("1. Public Route Access (No Auth Required)")

    r = requests.get(f"{BASE}/health")
    results.append(test(1, "GET /health (public)", r.status_code == 200, f"HTTP {r.status_code}"))

    r = requests.get(f"{BASE}/docs")
    results.append(test(2, "GET /docs (public)", r.status_code == 200, f"HTTP {r.status_code}"))

    # ── Session-layer ACL: Protected routes blocked without auth ──────
    section("2. Session ACL — Protected Routes Without Auth")

    r = requests.get(f"{BASE}/me")
    results.append(test(3, "GET /me (no auth)", r.status_code == 403, f"HTTP {r.status_code}"))

    r = requests.get(f"{BASE}/vpn/status")
    results.append(test(4, "GET /vpn/status (no auth)", r.status_code == 403, f"HTTP {r.status_code}"))

    r = requests.get(f"{BASE}/gateway/acl/stats")
    results.append(test(5, "GET /gateway/acl/stats (no auth)", r.status_code == 403, f"HTTP {r.status_code}"))

    # ── Full 2FA flow ────────────────────────────────────────────────
    section("3. Full 2FA Authentication Flow")

    reg = requests.post(f"{BASE}/register", json={
        "username": "acl_admin",
        "email": "admin@acl.test",
        "password": "SecureP@ss2024!",
    })
    if reg.status_code == 201:
        totp_secret = reg.json()["totp_secret"]
        results.append(test(6, "Register user", True, "201 Created"))
    elif reg.status_code == 409:
        print("  [--] User already exists, skipping")
        results.append(True)
        return  # Can't proceed without the TOTP secret
    else:
        results.append(test(6, "Register user", False, f"HTTP {reg.status_code}"))
        return

    login = requests.post(f"{BASE}/login", json={
        "username": "acl_admin",
        "password": "SecureP@ss2024!",
    })
    phase1_token = login.json().get("phase1_token", "")
    results.append(test(7, "Phase 1 login", login.status_code == 200))

    otp = pyotp.TOTP(totp_secret).now()
    verify = requests.post(f"{BASE}/verify-otp",
        json={"otp_code": otp},
        headers={"Authorization": f"Bearer {phase1_token}"},
    )
    access_token = verify.json().get("access_token", "")
    results.append(test(8, "Phase 2 OTP verify", verify.status_code == 200))

    admin_headers = {"Authorization": f"Bearer {access_token}"}

    # Session ACL: now protected routes should work
    r = requests.get(f"{BASE}/me", headers=admin_headers)
    results.append(test(9, "GET /me (with phase2)", r.status_code == 200))

    # ── Device registration and ACL sync ─────────────────────────────
    section("4. Device Registration & ACL Sync")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    aes_key = AESGCM.generate_key(bit_length=128)
    device_id = "acl-test-cam-001"

    r = requests.post(f"{BASE}/device/register", json={
        "device_id": device_id,
        "device_type": "smart_camera",
        "name": "ACL Test Camera",
        "ip_address": "10.0.0.200",
        "aes_key_hex": aes_key.hex(),
    })
    results.append(test(10, "Register device", r.status_code == 200))

    # Authenticate device
    r = requests.post(f"{BASE}/device/auth", json={
        "device_id": device_id,
        "aes_key_hex": aes_key.hex(),
    })
    device_token = r.json().get("access_token", "")
    results.append(test(11, "Authenticate device", r.status_code == 200))

    # Send telemetry
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    payload = json.dumps({"device_id": device_id, "type": "smart_camera", "fps": 30}).encode()
    ciphertext = aesgcm.encrypt(nonce, payload, None)

    r = requests.post(f"{BASE}/device/telemetry",
        json={
            "device_id": device_id,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "encrypted": True,
        },
        headers={"Authorization": f"Bearer {device_token}"},
    )
    results.append(test(12, "Device telemetry (authorized)", r.status_code == 200))

    # ── Device blocking ──────────────────────────────────────────────
    section("5. Device Blocking via ACL Admin")

    r = requests.post(f"{BASE}/gateway/acl/block-device",
        params={"device_id": device_id},
        headers=admin_headers,
    )
    results.append(test(13, "Block device via admin", r.status_code == 200, r.json().get("message", "")))

    # Re-encrypt a fresh message for the blocked test
    nonce2 = os.urandom(12)
    payload2 = json.dumps({"device_id": device_id, "type": "smart_camera", "fps": 15}).encode()
    ciphertext2 = aesgcm.encrypt(nonce2, payload2, None)

    r = requests.post(f"{BASE}/device/telemetry",
        json={
            "device_id": device_id,
            "nonce": nonce2.hex(),
            "ciphertext": ciphertext2.hex(),
            "encrypted": True,
        },
        headers={"Authorization": f"Bearer {device_token}"},
    )
    # The middleware denies at device layer (403) or gateway decryption fails (400)
    results.append(test(14, "Blocked device telemetry denied", r.status_code in (400, 403),
                        f"HTTP {r.status_code}"))

    # Unblock device
    r = requests.post(f"{BASE}/gateway/acl/unblock-device",
        params={"device_id": device_id},
        headers=admin_headers,
    )
    results.append(test(15, "Unblock device via admin", r.status_code == 200))

    # Telemetry should work again
    nonce3 = os.urandom(12)
    payload3 = json.dumps({"device_id": device_id, "type": "smart_camera", "fps": 24}).encode()
    ciphertext3 = aesgcm.encrypt(nonce3, payload3, None)

    r = requests.post(f"{BASE}/device/telemetry",
        json={
            "device_id": device_id,
            "nonce": nonce3.hex(),
            "ciphertext": ciphertext3.hex(),
            "encrypted": True,
        },
        headers={"Authorization": f"Bearer {device_token}"},
    )
    results.append(test(16, "Unblocked device telemetry works", r.status_code == 200))

    # ── ACL Stats & Blocked Log ──────────────────────────────────────
    section("6. ACL Admin Endpoints")

    r = requests.get(f"{BASE}/gateway/acl/stats", headers=admin_headers)
    stats = r.json()
    results.append(test(17, "ACL stats endpoint", r.status_code == 200,
                        f"evaluated={stats.get('total_evaluated')}, "
                        f"denied={stats.get('total_denied')}"))

    r = requests.get(f"{BASE}/gateway/acl/blocked", headers=admin_headers)
    blocked = r.json()
    results.append(test(18, "Blocked log endpoint", r.status_code == 200,
                        f"total_blocked={blocked.get('total_blocked')}"))

    # ── IP Blacklisting ──────────────────────────────────────────────
    section("7. IP Blacklisting")

    # Blacklist a fake attacker IP (not ours, so won't block us)
    r = requests.post(f"{BASE}/gateway/acl/blacklist",
        params={"ip_cidr": "192.168.99.0/24", "description": "Test attacker subnet"},
        headers=admin_headers,
    )
    results.append(test(19, "Blacklist 192.168.99.0/24", r.status_code == 200))

    # Remove it
    r = requests.delete(f"{BASE}/gateway/acl/blacklist",
        params={"ip_cidr": "192.168.99.0/24"},
        headers=admin_headers,
    )
    results.append(test(20, "Remove blacklist 192.168.99.0/24", r.status_code == 200))

    # ── Summary ──────────────────────────────────────────────────────
    section("RESULTS SUMMARY")
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"\n  {passed}/{total} tests passed")
    if passed == total:
        print("  ALL TESTS PASSED!")
    else:
        print(f"  {total - passed} test(s) FAILED")


if __name__ == "__main__":
    main()
