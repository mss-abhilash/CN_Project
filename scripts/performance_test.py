"""
Network Performance Analyst — Benchmark Tool
=============================================
Measures the overhead introduced by the security controls.
Compares:
  1. Baseline (Without Security - simulated direct HTTP)
  2. Secured (With 2FA, AES-128 GCM, and simulated VPN overhead)

Metrics:
  - Authentication Latency (ms)
  - Connection Time / Key Gen (ms)
  - Telemetry Throughput (req/sec)
  - Packet Loss / Success Rate (%)

Usage:
  python scripts/performance_test.py
"""

import os
import time
import json
import statistics
import requests
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from dotenv import load_dotenv

load_dotenv()

BASE_URL = f"http://{os.getenv('HOST', '127.0.0.1')}:{os.getenv('PORT', '8000')}"
ITERATIONS = 50

# Colors for output
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def section(title):
    print(f"\n{BLUE}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{RESET}")

def report_metric(metric, baseline, secured, unit=""):
    diff = secured - baseline
    overhead = (diff / baseline) * 100 if baseline > 0 else 0
    print(f"  {metric:<25} | Baseline: {baseline:>8.2f}{unit} | Secured: {secured:>8.2f}{unit} | Overhead: +{overhead:.1f}%")

def measure_auth_latency():
    section("1. Authentication Latency")
    
    # Register test user
    user = f"perf_user_{int(time.time())}"
    r = requests.post(f"{BASE_URL}/register", json={
        "username": user, "email": f"{user}@test.com", "password": "Password123!"
    })
    if r.status_code != 201:
        print("  [ERROR] Failed to setup test user.")
        return

    totp_secret = r.json()["totp_secret"]

    # Baseline (Simulated: No bcrypt, no TOTP, just a fast DB lookup)
    baseline_times = []
    for _ in range(ITERATIONS):
        start = time.perf_counter()
        # Mocking a fast lookup by hitting public health endpoint
        requests.get(f"{BASE_URL}/health")
        baseline_times.append((time.perf_counter() - start) * 1000)
    baseline_avg = statistics.mean(baseline_times)

    # Secured (bcrypt login + TOTP verification)
    secured_times = []
    for _ in range(ITERATIONS // 5): # Fewer iterations to avoid rate limit bans
        start = time.perf_counter()
        
        # Phase 1
        login = requests.post(f"{BASE_URL}/login", json={
            "username": user, "password": "Password123!"
        })
        p1_token = login.json().get("phase1_token", "")
        
        # Phase 2
        otp = pyotp.TOTP(totp_secret).now()
        requests.post(f"{BASE_URL}/verify-otp", json={"otp_code": otp},
                      headers={"Authorization": f"Bearer {p1_token}"})
        
        secured_times.append((time.perf_counter() - start) * 1000)
        time.sleep(0.1) # Cool down for rate limiter
    
    secured_avg = statistics.mean(secured_times)
    report_metric("Auth Latency (total)", baseline_avg, secured_avg, "ms")


def measure_connection_time():
    section("2. Connection Time (Key Generation)")
    
    # Baseline (TCP handshake time simulated)
    baseline_times = []
    for _ in range(ITERATIONS):
        start = time.perf_counter()
        requests.get(f"{BASE_URL}/health")
        baseline_times.append((time.perf_counter() - start) * 1000)
    baseline_avg = statistics.mean(baseline_times)

    # Secured (WireGuard Curve25519 KeyGen + Handshake simulation)
    secured_times = []
    for _ in range(ITERATIONS):
        start = time.perf_counter()
        # Generate Curve25519 keypair for WireGuard client
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        # Add simulated network RTT
        requests.get(f"{BASE_URL}/health")
        secured_times.append((time.perf_counter() - start) * 1000)
    
    secured_avg = statistics.mean(secured_times)
    report_metric("Connection Setup", baseline_avg, secured_avg, "ms")


def measure_throughput_and_loss():
    section("3. Transport: Throughput & Packet Loss")
    
    # Register device to get token
    aes_key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(aes_key)
    dev_id = f"perf-dev-{int(time.time())}"
    
    requests.post(f"{BASE_URL}/device/register", json={
        "device_id": dev_id, "device_type": "sensor", "name": "Perf", 
        "ip_address": "10.0.0.99", "aes_key_hex": aes_key.hex()
    })
    auth = requests.post(f"{BASE_URL}/device/auth", json={
        "device_id": dev_id, "aes_key_hex": aes_key.hex()
    })
    dev_token = auth.json().get("access_token")

    payload_dict = {"device_id": dev_id, "temp": 24.5, "humidity": 45}
    payload_str = json.dumps(payload_dict)

    # Baseline (Plaintext POST, mocked endpoint)
    # We use a non-existent route or health to mock processing without ACL/AES overhead
    baseline_success = 0
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        r = requests.post(f"{BASE_URL}/health", data=payload_str)
        if r.status_code == 405: # /health is GET only, returns 405. counts as received.
            baseline_success += 1
    baseline_duration = time.perf_counter() - start_time
    baseline_tps = ITERATIONS / baseline_duration
    baseline_loss = ((ITERATIONS - baseline_success) / ITERATIONS) * 100

    # Secured (AES-GCM encryption + ACL + Full API routing)
    secured_success = 0
    start_time = time.perf_counter()
    for _ in range(ITERATIONS):
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, payload_str.encode(), None)
        
        r = requests.post(f"{BASE_URL}/device/telemetry", json={
            "device_id": dev_id, "nonce": nonce.hex(), 
            "ciphertext": ct.hex(), "encrypted": True
        }, headers={"Authorization": f"Bearer {dev_token}"})
        
        if r.status_code == 200:
            secured_success += 1
            
    secured_duration = time.perf_counter() - start_time
    secured_tps = ITERATIONS / secured_duration
    secured_loss = ((ITERATIONS - secured_success) / ITERATIONS) * 100

    print(f"  Throughput (Baseline) : {GREEN}{baseline_tps:>8.2f} req/sec{RESET}")
    print(f"  Throughput (Secured)  : {YELLOW}{secured_tps:>8.2f} req/sec{RESET}")
    diff_tps = baseline_tps - secured_tps
    overhead_tps = (diff_tps / baseline_tps) * 100
    print(f"  Throughput Drop       : -{overhead_tps:.1f}%")
    
    print()
    print(f"  Packet Loss (Baseline): {baseline_loss:>8.2f} %")
    print(f"  Packet Loss (Secured) : {secured_loss:>8.2f} %")

def export_sample_results():
    section("4. Sample Results Format & Graphing Suggestions")
    
    sample_data = {
        "metrics": ["Auth Latency", "VPN Connection", "Encryption Overhead", "Throughput"],
        "baseline": [15, 20, 0, 850],
        "secured": [150, 45, 2, 800],
        "units": ["ms", "ms", "ms", "req/sec"]
    }
    print("  Save results to JSON for automation:")
    print("  " + json.dumps(sample_data, indent=2).replace('\n', '\n  '))
    
    print(f"\n{YELLOW}Graphing Suggestions:{RESET}")
    print("  1. Bar Chart: 'Latency Overhead' -> Grouped bars (Baseline vs Secured) for Auth & Conn Time. Y-axis logarithmic (ms).")
    print("  2. Line Graph: 'Throughput Decay' -> X-axis Payload Size (KB), Y-axis req/sec. Two lines showing plaintext vs AES-GCM.")
    print("  3. Pie Chart: 'Security Time Budget' -> breakdown of Secured Auth Request (Network RTT + bcrypt hash + TOTP verify).")

def main():
    print(f"\n{BLUE}=== IoT Gateway Performance Analyzer ==={RESET}")
    print("Make sure backend is running on http://127.0.0.1:8000")
    
    try:
        requests.get(f"{BASE_URL}/health")
    except requests.exceptions.ConnectionError:
        print("[ERROR] Server not reachable. Run 'python -m uvicorn backend.main:app' first.")
        return
        
    measure_auth_latency()
    measure_connection_time()
    measure_throughput_and_loss()
    export_sample_results()
    
    print(f"\n{GREEN}Performance Test Complete.{RESET}\n")

if __name__ == "__main__":
    main()
