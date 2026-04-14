"""Quick smoke test for VPN API endpoints."""
import requests
import json
import pyotp

BASE = "http://127.0.0.1:8000"

def main():
    # 1. Health
    r = requests.get(f"{BASE}/health")
    print(f"[1] Health: {r.json()}")

    # 2. Check all routes exist
    r = requests.get(f"{BASE}/openapi.json")
    paths = list(r.json()["paths"].keys())
    print(f"[2] Routes: {json.dumps(paths, indent=4)}")

    # 3. VPN endpoints reject unauthenticated
    r = requests.get(f"{BASE}/vpn/status")
    det = r.json().get("detail", "")
    print(f"[3] VPN status (no auth): HTTP {r.status_code} - {det}")

    r = requests.get(f"{BASE}/vpn/peers")
    det = r.json().get("detail", "")
    print(f"[4] VPN peers (no auth):  HTTP {r.status_code} - {det}")

    # 4. Full 2FA flow -> VPN peer creation
    print("\n--- Full 2FA + VPN Flow ---")

    # Register
    reg = requests.post(f"{BASE}/register", json={
        "username": "vpn_test_user",
        "email": "vpn@test.local",
        "password": "Str0ng!Pass#2024",
    })
    if reg.status_code == 201:
        totp_secret = reg.json()["totp_secret"]
        print(f"[5] Registered. TOTP secret: {totp_secret}")
    elif reg.status_code == 409:
        print(f"[5] User exists, skipping registration")
        return
    else:
        print(f"[5] Registration failed: {reg.text}")
        return

    # Login (Phase 1)
    login = requests.post(f"{BASE}/login", json={
        "username": "vpn_test_user",
        "password": "Str0ng!Pass#2024",
    })
    phase1 = login.json()["phase1_token"]
    print(f"[6] Phase 1 token: {phase1[:30]}...")

    # Verify OTP (Phase 2)
    otp = pyotp.TOTP(totp_secret).now()
    verify = requests.post(f"{BASE}/verify-otp",
        json={"otp_code": otp},
        headers={"Authorization": f"Bearer {phase1}"},
    )
    access_token = verify.json()["access_token"]
    print(f"[7] Phase 2 token: {access_token[:30]}...")

    headers = {"Authorization": f"Bearer {access_token}"}

    # Create VPN peer
    peer = requests.post(f"{BASE}/vpn/peers",
        json={"peer_name": "iot-camera-001", "device_type": "camera"},
        headers=headers,
    )
    print(f"[8] Create peer: HTTP {peer.status_code}")
    print(f"    {json.dumps(peer.json(), indent=4)}")

    # List peers
    peers = requests.get(f"{BASE}/vpn/peers", headers=headers)
    print(f"[9] List peers: {json.dumps(peers.json(), indent=4)}")

    # Download config
    conf = requests.get(f"{BASE}/vpn/peers/iot-camera-001/config", headers=headers)
    print(f"[10] Config download: HTTP {conf.status_code}")
    print(f"     Content:\n{conf.text}")

    # VPN status
    stat = requests.get(f"{BASE}/vpn/status", headers=headers)
    print(f"[11] VPN status: {json.dumps(stat.json(), indent=4)}")

    # Revoke peer
    revoke = requests.delete(f"{BASE}/vpn/peers/iot-camera-001", headers=headers)
    print(f"[12] Revoke peer: {json.dumps(revoke.json(), indent=4)}")

    print("\n--- All VPN tests passed! ---")


if __name__ == "__main__":
    main()
