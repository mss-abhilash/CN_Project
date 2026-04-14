import subprocess
import time
import sys

if __name__ == '__main__':
    print("Starting all devices...")
    
    # Store references so we can terminate them safely on Windows
    p1 = subprocess.Popen([sys.executable, "-m", "iot_devices.smart_camera"])
    p2 = subprocess.Popen([sys.executable, "-m", "iot_devices.temperature_sensor"])
    p3 = subprocess.Popen([sys.executable, "-m", "iot_devices.smart_lock"])
    
    time.sleep(12)
    print("\nStopping all devices...")
    
    p1.terminate()
    p2.terminate()
    p3.terminate()
    
    p1.wait()
    p2.wait()
    p3.wait()
    print("Tests complete.")
