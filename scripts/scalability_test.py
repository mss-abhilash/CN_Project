import os
import time
import json
import threading
import statistics
import requests
from iot_devices.base_device import BaseIoTDevice
from dotenv import load_dotenv

load_dotenv()

BASE_URL = f"http://{os.getenv('HOST', '127.0.0.1')}:{os.getenv('PORT', '8000')}"

class ScalableDevice(BaseIoTDevice):
    def __init__(self, index):
        super().__init__(
            device_id=f"swarm-dev-{index:04d}",
            device_type="simulated_sensor",
            name=f"Swarm Device {index}",
            ip_address=f"10.0.0.{index % 250 + 2}" # Avoid .1
        )
        self.auth_latency = 0
        self.telemetry_latencies = []

    def get_telemetry_data(self):
        return {"data": 123.45}

    def run_benchmark(self, iterations=5):
        try:
            # Measure Registration/Auth Latency
            start = time.perf_counter()
            if not self.register(): return
            if not self.authenticate(): return
            self.auth_latency = (time.perf_counter() - start) * 1000 # ms

            # Measure Telemetry Latency
            for _ in range(iterations):
                t_start = time.perf_counter()
                self.send_telemetry()
                self.telemetry_latencies.append((time.perf_counter() - t_start) * 1000)
                time.sleep(0.1) # Small gap
        except Exception as e:
            print(f"[{self.device_id}] Error: {e}")

def run_scalability_test(device_count=50, iterations=3):
    print(f"\n{'='*60}")
    print(f"  SCALABILITY TEST: {device_count} Concurrent Devices")
    print(f"{'='*60}\n")
    
    devices = [ScalableDevice(i) for i in range(device_count)]
    threads = []
    
    start_total = time.perf_counter()
    
    for dev in devices:
        t = threading.Thread(target=dev.run_benchmark, args=(iterations,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    total_time = time.perf_counter() - start_total
    
    # Collate results
    auth_times = [d.auth_latency for d in devices if d.auth_latency > 0]
    all_telem_times = []
    for d in devices:
        all_telem_times.extend(d.telemetry_latencies)
        
    if not auth_times:
        print("[!] No devices successfully authenticated.")
        return

    print(f"\n--- SCALABILITY RESULTS ({device_count} devices) ---")
    print(f"Total Test Duration      : {total_time:.2f} s")
    print(f"Auth Latency (Avg)       : {statistics.mean(auth_times):.2f} ms")
    print(f"Auth Latency (Max)       : {max(auth_times):.2f} ms")
    print(f"Telemetry Latency (Avg)  : {statistics.mean(all_telem_times):.2f} ms")
    print(f"Telemetry Latency (Max)  : {max(all_telem_times):.2f} ms")
    print(f"Reliability (Success Rate): {(len(auth_times)/device_count)*100:.1f}%")

    # Export to CSV for plotting
    output_file = "scripts/scalability_results.csv"
    file_exists = os.path.isfile(output_file)
    with open(output_file, "a") as f:
        if not file_exists:
            f.write("device_count,avg_auth_ms,avg_telem_ms,total_duration_s\n")
        f.write(f"{device_count},{statistics.mean(auth_times):.2f},{statistics.mean(all_telem_times):.2f},{total_time:.2f}\n")
    print(f"\n[OK] Results appended to {output_file}")

if __name__ == "__main__":
    # Run at different scales for testing
    run_scalability_test(10)
    run_scalability_test(25)
    run_scalability_test(50)
