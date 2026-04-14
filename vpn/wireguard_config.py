"""
WireGuard VPN Configuration Manager
=====================================
Generates real Curve25519 keypairs and WireGuard configuration files
for the gateway server and IoT device peers.

Key features:
  - Real Curve25519 key generation via `cryptography` library
  - Preshared key (PSK) support for post-quantum defence-in-depth
  - IP address pool management (auto-assigns from VPN_SUBNET)
  - Config export to disk (wg0.conf, peer .conf files)
  - Integration-ready: peers are persisted to the database via the API
"""

import os
import ipaddress
import json
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import secrets

from dotenv import load_dotenv

load_dotenv()

# ── Configuration from .env ──────────────────────────────────────────────────

VPN_SUBNET       = os.getenv("VPN_SUBNET", "10.0.0.0/24")
VPN_GATEWAY_IP   = os.getenv("VPN_GATEWAY_IP", "10.0.0.1")
VPN_LISTEN_PORT  = int(os.getenv("VPN_LISTEN_PORT", "51820"))
VPN_DNS          = os.getenv("VPN_DNS", "1.1.1.1")
VPN_SERVER_HOST  = os.getenv("VPN_SERVER_HOST", "your-server.example.com")
VPN_CONFIG_DIR   = os.getenv("VPN_CONFIG_DIR", os.path.join(os.path.dirname(__file__), "configs"))


# ── Key Generation (Real Curve25519) ─────────────────────────────────────────

def generate_keypair() -> tuple[str, str]:
    """
    Generate a real Curve25519 keypair for WireGuard.
    Returns (private_key_b64, public_key_b64).
    """
    private_key = X25519PrivateKey.generate()

    # Export private key as raw 32 bytes → base64
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_b64 = base64.b64encode(private_bytes).decode("utf-8")

    # Derive public key → raw 32 bytes → base64
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_b64 = base64.b64encode(public_bytes).decode("utf-8")

    return private_b64, public_b64


def generate_preshared_key() -> str:
    """Generate a 256-bit preshared key (base64) for additional symmetric encryption."""
    return base64.b64encode(secrets.token_bytes(32)).decode("utf-8")


# ── IP Address Pool ──────────────────────────────────────────────────────────

class IPAddressPool:
    """
    Manages IP allocation from the VPN subnet.
    Reserves .1 for the gateway, assigns .2+ to peers.
    """

    def __init__(self, subnet: str = VPN_SUBNET, gateway_ip: str = VPN_GATEWAY_IP):
        self.network = ipaddress.IPv4Network(subnet, strict=False)
        self.gateway_ip = ipaddress.IPv4Address(gateway_ip)
        self._allocated: set[str] = {str(self.gateway_ip)}

    def allocate(self) -> str:
        """Allocate the next available IP address from the pool."""
        for host in self.network.hosts():
            if str(host) not in self._allocated:
                self._allocated.add(str(host))
                return str(host)
        raise RuntimeError("VPN IP address pool exhausted")

    def release(self, ip: str):
        """Return an IP address to the pool."""
        self._allocated.discard(ip)

    def mark_used(self, ip: str):
        """Mark an IP as already allocated (e.g., loaded from DB)."""
        self._allocated.add(ip)

    @property
    def available_count(self) -> int:
        total_hosts = self.network.num_addresses - 2  # exclude network + broadcast
        return total_hosts - len(self._allocated)


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class WireGuardPeer:
    """A WireGuard peer (IoT device or authenticated user)."""
    name: str
    public_key: str
    private_key: str
    preshared_key: str
    allowed_ip: str
    owner_username: str           # Bound to the authenticated user
    device_type: str = "generic"
    created_at: str = ""
    is_active: bool = True

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "public_key": self.public_key,
            "allowed_ip": self.allowed_ip,
            "owner_username": self.owner_username,
            "device_type": self.device_type,
            "created_at": self.created_at,
            "is_active": self.is_active,
        }


@dataclass
class WireGuardServer:
    """WireGuard server (gateway) configuration."""
    private_key: str
    public_key: str
    listen_port: int = VPN_LISTEN_PORT
    address: str = VPN_GATEWAY_IP
    subnet: str = VPN_SUBNET
    dns: str = VPN_DNS
    server_host: str = VPN_SERVER_HOST
    peers: list[WireGuardPeer] = field(default_factory=list)

    def add_peer(self, peer: WireGuardPeer):
        self.peers.append(peer)

    def remove_peer(self, peer_name: str) -> bool:
        before = len(self.peers)
        self.peers = [p for p in self.peers if p.name != peer_name]
        return len(self.peers) < before

    def generate_server_config(self) -> str:
        """Generate the wg0.conf for the server/gateway."""
        lines = [
            "[Interface]",
            f"PrivateKey = {self.private_key}",
            f"Address = {self.address}/24",
            f"ListenPort = {self.listen_port}",
            f"DNS = {self.dns}",
            "",
            "# NAT / forwarding (uncomment on Linux gateway)",
            "# PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
            "# PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        ]

        for peer in self.peers:
            if not peer.is_active:
                continue
            lines.extend([
                "",
                f"# ── Peer: {peer.name} ({peer.owner_username}) ──",
                "[Peer]",
                f"PublicKey = {peer.public_key}",
                f"PresharedKey = {peer.preshared_key}",
                f"AllowedIPs = {peer.allowed_ip}/32",
            ])

        return "\n".join(lines) + "\n"

    def generate_peer_config(self, peer: WireGuardPeer) -> str:
        """Generate a client .conf file for a peer to import."""
        return f"""# WireGuard Config — {peer.name}
# Owner: {peer.owner_username}
# Generated: {datetime.now(timezone.utc).isoformat()}

[Interface]
PrivateKey = {peer.private_key}
Address = {peer.allowed_ip}/32
DNS = {self.dns}

[Peer]
PublicKey = {self.public_key}
PresharedKey = {peer.preshared_key}
AllowedIPs = {self.subnet}
Endpoint = {self.server_host}:{self.listen_port}
PersistentKeepalive = 25
"""


# ── VPN Manager (Orchestrator) ───────────────────────────────────────────────

class VPNManager:
    """
    High-level manager that ties together key generation, IP allocation,
    config generation, and file export.
    """

    def __init__(self):
        # Generate or load server keys
        self.server_private, self.server_public = generate_keypair()
        self.ip_pool = IPAddressPool()
        self.server = WireGuardServer(
            private_key=self.server_private,
            public_key=self.server_public,
        )
        self.config_dir = Path(VPN_CONFIG_DIR)
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def create_peer(self, name: str, owner_username: str,
                    device_type: str = "generic") -> WireGuardPeer:
        """
        Create a new VPN peer with auto-generated keys and IP.
        This is called by the API after a user completes 2FA.
        """
        private_key, public_key = generate_keypair()
        psk = generate_preshared_key()
        assigned_ip = self.ip_pool.allocate()

        peer = WireGuardPeer(
            name=name,
            public_key=public_key,
            private_key=private_key,
            preshared_key=psk,
            allowed_ip=assigned_ip,
            owner_username=owner_username,
            device_type=device_type,
        )

        self.server.add_peer(peer)
        return peer

    def revoke_peer(self, peer_name: str) -> bool:
        """Revoke a peer's VPN access (removes from server config)."""
        for peer in self.server.peers:
            if peer.name == peer_name:
                peer.is_active = False
                self.ip_pool.release(peer.allowed_ip)
                return True
        return False

    def export_configs(self) -> dict[str, str]:
        """
        Write all config files to disk and return paths.
        Returns dict of {name: filepath}.
        """
        paths = {}

        # Server config
        server_path = self.config_dir / "wg0.conf"
        server_path.write_text(self.server.generate_server_config(), encoding="utf-8")
        paths["server"] = str(server_path)

        # Peer configs
        for peer in self.server.peers:
            if not peer.is_active:
                continue
            peer_path = self.config_dir / f"{peer.name}.conf"
            peer_path.write_text(self.server.generate_peer_config(peer), encoding="utf-8")
            paths[peer.name] = str(peer_path)

        return paths

    def get_server_status(self) -> dict:
        """Return VPN server status summary."""
        active = [p for p in self.server.peers if p.is_active]
        return {
            "server_public_key": self.server.public_key,
            "listen_port": self.server.listen_port,
            "gateway_ip": self.server.address,
            "subnet": self.server.subnet,
            "total_peers": len(self.server.peers),
            "active_peers": len(active),
            "available_ips": self.ip_pool.available_count,
        }


# ── Standalone Demo ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  WireGuard VPN Manager — Demo")
    print("=" * 60)

    mgr = VPNManager()

    # Create 3 demo peers
    peers = []
    for i, dtype in enumerate(["thermostat", "camera", "door_lock"], 1):
        peer = mgr.create_peer(
            name=f"iot-{dtype}-{i:03d}",
            owner_username="admin_user",
            device_type=dtype,
        )
        peers.append(peer)
        print(f"\n[+] Created peer: {peer.name} → {peer.allowed_ip}")

    # Export configs  
    paths = mgr.export_configs()
    print(f"\n── Exported {len(paths)} config files ──")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    # Print server config
    print("\n── Server Config (wg0.conf) ──")
    print(mgr.server.generate_server_config())

    # Print one peer config
    print(f"\n── Peer Config: {peers[0].name} ──")
    print(mgr.server.generate_peer_config(peers[0]))

    # Status
    print("\n── VPN Status ──")
    print(json.dumps(mgr.get_server_status(), indent=2))
