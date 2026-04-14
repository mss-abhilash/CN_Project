import random
import time
from iot_devices.base_device import BaseIoTDevice

class SmartLock(BaseIoTDevice):
    def __init__(self, device_id: str, name: str, ip_address: str):
        super().__init__(device_id, "smart_lock", name, ip_address)
        self.is_locked = True
        self.battery = 85

    def get_telemetry_data(self) -> dict:
        # Occasional unlock event
        if random.random() > 0.95:
            self.is_locked = not self.is_locked
            print(f"\n[EVENT] Lock state changed -> {'LOCKED' if self.is_locked else 'UNLOCKED'}\n")
            
        # Slow battery drain
        if random.random() > 0.8:
            self.battery_pct = max(0, self.battery - 1)

        return {
            "device_id": self.device_id,
            "type": self.device_type,
            "locked": self.is_locked,
            "battery_pct": self.battery,
            "last_operation": "keypad" if not self.is_locked else "auto-lock"
        }

if __name__ == "__main__":
    device_id = f"lock-{random.randint(1000, 9999)}"
    lock = SmartLock(device_id, f"Main Gate Lock", "10.0.0.103")
    lock.run(interval=5)
