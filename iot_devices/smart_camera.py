import random
import time
from iot_devices.base_device import BaseIoTDevice

class SmartCamera(BaseIoTDevice):
    def __init__(self, device_id: str, name: str, ip_address: str):
        super().__init__(device_id, "smart_camera", name, ip_address)
        self.is_recording = True
        self.fps = 24

    def get_telemetry_data(self) -> dict:
        # Simulate varying FPS or motion events
        if random.random() > 0.8:
            self.fps = random.choice([15, 24, 30])
        
        motion_detected = random.random() > 0.9

        return {
            "device_id": self.device_id,
            "type": self.device_type,
            "recording": self.is_recording,
            "fps": self.fps,
            "motion_detected": motion_detected,
            "status": "online"
        }

if __name__ == "__main__":
    device_id = f"cam-{random.randint(1000, 9999)}"
    camera = SmartCamera(device_id, f"Front Door Camera", "10.0.0.101")
    camera.run(interval=3)
