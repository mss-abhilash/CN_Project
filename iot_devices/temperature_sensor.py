import random
import time
from iot_devices.base_device import BaseIoTDevice

class TemperatureSensor(BaseIoTDevice):
    def __init__(self, device_id: str, name: str, ip_address: str):
        super().__init__(device_id, "temperature_sensor", name, ip_address)
        self.current_temp = 22.0

    def get_telemetry_data(self) -> dict:
        # Simulate slight temperature fluctuation
        delta = random.uniform(-0.5, 0.5)
        self.current_temp += delta
        self.current_temp = round(self.current_temp, 2)
        
        # Clamp value to realistic bounds
        self.current_temp = max(15.0, min(35.0, self.current_temp))

        return {
            "device_id": self.device_id,
            "type": self.device_type,
            "temperature_c": self.current_temp,
            "unit": "celsius",
            "battery_pct": random.randint(80, 100)
        }

if __name__ == "__main__":
    device_id = f"temp-{random.randint(1000, 9999)}"
    sensor = TemperatureSensor(device_id, f"Living Room Temp Sensor", "10.0.0.102")
    sensor.run(interval=4)
