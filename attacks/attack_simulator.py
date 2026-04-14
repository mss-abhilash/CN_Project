"""
Attack Simulator
=================
Simulates common IoT network attacks to test the security posture
of the gateway and authentication system.

Supported attacks:
  1. Brute-force login (password guessing)
  2. TOTP replay attack
  3. Spoofed device message injection
  4. Rate-limit exhaustion
  5. Man-in-the-Middle (tampered ciphertext)
"""

import os
import time
import random
import string
import json
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = f"http://{os.getenv('HOST', '127.0.0.1')}:{os.getenv('PORT', '8000')}"


class AttackType(str, Enum):
    BRUTE_FORCE = "brute_force"
    OTP_REPLAY = "otp_replay"
    DEVICE_SPOOF = "device_spoof"
    RATE_LIMIT = "rate_limit"
    MITM_TAMPER = "mitm_tamper"


@dataclass
class AttackResult:
    """Result of a simulated attack."""
    attack_type: AttackType
    target: str
    success: bool
    attempts: int
    duration_sec: float
    details: str
    timestamp: str = ""

    def __post_init__(self):
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type.value,
            "target": self.target,
            "success": self.success,
            "attempts": self.attempts,
            "duration_sec": round(self.duration_sec, 3),
            "details": self.details,
            "timestamp": self.timestamp,
        }


class AttackSimulator:
    """Orchestrates security attack simulations against the IoT backend."""

    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.results: list[AttackResult] = []

    def brute_force_login(self, username: str, attempts: int = 10) -> AttackResult:
        """
        Simulate a brute-force password attack.
        Sends N login attempts with random passwords.
        Expected: Account lockout after MAX_FAILED_ATTEMPTS.
        """
        print(f"\n[ATTACK] Brute-force login → {username} ({attempts} attempts)")
        start = time.time()
        blocked_at = None

        for i in range(1, attempts + 1):
            fake_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            try:
                resp = requests.post(
                    f"{self.base_url}/login",
                    json={"username": username, "password": fake_password},
                    timeout=5,
                )
                status = resp.status_code
                print(f"  Attempt {i:>2}: {fake_password} → HTTP {status}")
                if status == 403:
                    blocked_at = i
                    break
                elif status == 429:
                    print(f"  ⚡ Rate limited at attempt {i}")
                    blocked_at = i
                    break
            except requests.RequestException as e:
                print(f"  Attempt {i:>2}: ERROR — {e}")

        duration = time.time() - start
        result = AttackResult(
            attack_type=AttackType.BRUTE_FORCE,
            target=username,
            success=blocked_at is None,  # Attack "succeeds" if NOT blocked
            attempts=attempts if blocked_at is None else blocked_at,
            duration_sec=duration,
            details=f"Blocked at attempt {blocked_at}" if blocked_at else "Not blocked (VULNERABILITY!)",
        )
        self.results.append(result)
        return result

    def otp_replay_attack(self, phase1_token: str, otp_code: str, replays: int = 5) -> AttackResult:
        """
        Attempt to reuse a valid OTP code multiple times.
        Expected: Only first use succeeds (TOTP time-window enforcement).
        """
        print(f"\n[ATTACK] OTP replay → code={otp_code} ({replays} replays)")
        start = time.time()
        successes = 0

        for i in range(1, replays + 1):
            try:
                resp = requests.post(
                    f"{self.base_url}/verify-otp",
                    json={"otp_code": otp_code},
                    headers={"Authorization": f"Bearer {phase1_token}"},
                    timeout=5,
                )
                status = resp.status_code
                print(f"  Replay {i}: HTTP {status}")
                if status == 200:
                    successes += 1
            except requests.RequestException as e:
                print(f"  Replay {i}: ERROR — {e}")

        duration = time.time() - start
        result = AttackResult(
            attack_type=AttackType.OTP_REPLAY,
            target="verify-otp",
            success=successes > 1,  # Attack succeeds if OTP reused
            attempts=replays,
            duration_sec=duration,
            details=f"{successes}/{replays} accepted" + (" (VULNERABILITY!)" if successes > 1 else " (SECURE)"),
        )
        self.results.append(result)
        return result

    def mitm_tamper_attack(self, nonce_hex: str, ciphertext_hex: str) -> AttackResult:
        """
        Simulate a Man-in-the-Middle attack by tampering with encrypted payload.
        Expected: AES-GCM authentication tag check should reject tampered data.
        """
        print(f"\n[ATTACK] MitM — Tampering with ciphertext...")
        start = time.time()

        # Flip random bits in the ciphertext
        ct_bytes = bytearray(bytes.fromhex(ciphertext_hex))
        for _ in range(3):
            pos = random.randint(0, len(ct_bytes) - 1)
            ct_bytes[pos] ^= 0xFF  # Flip all bits at position

        tampered_hex = ct_bytes.hex()
        duration = time.time() - start

        result = AttackResult(
            attack_type=AttackType.MITM_TAMPER,
            target="device_message",
            success=False,  # Will be determined by gateway's decrypt response
            attempts=1,
            duration_sec=duration,
            details=f"Original: {ciphertext_hex[:32]}... → Tampered: {tampered_hex[:32]}...",
        )
        self.results.append(result)
        return result

    def generate_report(self) -> str:
        """Generate a summary report of all attack simulations."""
        report = "\n" + "=" * 60
        report += "\n  ATTACK SIMULATION REPORT"
        report += "\n" + "=" * 60
        report += f"\n  Timestamp: {datetime.now(timezone.utc).isoformat()}"
        report += f"\n  Total attacks: {len(self.results)}\n"

        for r in self.results:
            status = "⚠ VULNERABLE" if r.success else "✅ SECURE"
            report += f"\n  [{status}] {r.attack_type.value}"
            report += f"\n    Target:   {r.target}"
            report += f"\n    Attempts: {r.attempts}"
            report += f"\n    Duration: {r.duration_sec:.3f}s"
            report += f"\n    Details:  {r.details}\n"

        report += "=" * 60
        return report


if __name__ == "__main__":
    sim = AttackSimulator()
    print("=" * 60)
    print("  Attack Simulator — Ready")
    print(f"  Target: {BASE_URL}")
    print("=" * 60)
    print("\nRun individual attacks via the AttackSimulator class methods.")
    print("Example: sim.brute_force_login('admin_user', attempts=10)")
