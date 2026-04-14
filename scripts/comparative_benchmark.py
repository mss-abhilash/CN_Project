import os
import time
import json
import statistics
import requests
import random
from iot_devices.base_device import BaseIoTDevice
from dotenv import load_dotenv

load_dotenv()

BASE_URL = f"http://{os.getenv('HOST', '127.0.0.1')}:{os.getenv('PORT', '8000')}"

class ComparatorDevice(BaseIoTDevice):
    def get_telemetry_data(self):
        return {"temp": 22.5, "humidity": 45.0}

def run_comparative_benchmark(iterations=100):
    print(f"\n{'='*60}")
    print(f"  COMPARATIVE BENCHMARK: Plain vs. TLS(Sim) vs. VPN/AES")
    print(f"{'='*60}\n")
    
    # Setup a test device with a unique ID
    rand_id = f"comp-test-{random.randint(1000, 9999)}"
    dev = ComparatorDevice(rand_id, "sensor", "Comparator", "10.0.0.99")
    print(f"[SETUP] Using device ID: {rand_id}")
    dev.register()
    dev.authenticate()
    
    results = {
        "plain": [],
        "tls_sim": [],
        "vpn_aes": []
    }
    
    payload = {"temp": 25.4, "status": "ok"}
    
    print(f"Running {iterations} iterations per protocol...")

    # 1. Plain Simulation (No encryption, no ACL)
    # We simulate this by calling a health endpoint or similar low-overhead route
    for _ in range(iterations):
        start = time.perf_counter()
        requests.get(f"{BASE_URL}/health")
        results["plain"].append((time.perf_counter() - start) * 1000)

    # 2. TLS Simulation (Plain + 40ms handshake + 5ms encryption overhead)
    # Average TLS handshake is 20-50ms
    for _ in range(iterations):
        start = time.perf_counter()
        requests.get(f"{BASE_URL}/health")
        duration = (time.perf_counter() - start) * 1000 + 45 # Add TLS overhead
        results["tls_sim"].append(duration)

    # 3. Our Solution (VPN + ACL + AES-GCM)
    for _ in range(iterations):
        start = time.perf_counter()
        dev.send_telemetry()
        results["vpn_aes"].append((time.perf_counter() - start) * 1000)

    # Calculate Metrics
    print(f"\n--- PERFORMANCE COMPARISON (ms) ---")
    print(f"{'Protocol':<15} | {'Avg':>10} | {'Max':>10} | {'P95':>10}")
    print("-" * 55)
    
    csv_data = []
    
    for protocol, times in results.items():
        avg = statistics.mean(times)
        mx = max(times)
        p95 = sorted(times)[int(len(times) * 0.95)]
        print(f"{protocol:<15} | {avg:>10.2f} | {mx:>10.2f} | {p95:>10.2f}")
        csv_data.append(f"{protocol},{avg:.2f},{mx:.2f},{p95:.2f}")

    # Export to CSV for Research Graphing
    output_file = "scripts/comparative_results.csv"
    with open(output_file, "w") as f:
        f.write("protocol,avg_ms,max_ms,p95_ms\n")
        f.write("\n".join(csv_data))
    
    print(f"\n[OK] Comparative data saved to {output_file}")

if __name__ == "__main__":
    run_comparative_benchmark(50)
