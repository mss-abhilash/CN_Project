# Presentation Guide: IoT Secure Home Network

This guide provides a structured outline for a professional 10-15 minute presentation.

---

## Slide 1: Title & Introduction
- **Title**: Securing the Infinite Edge: A High-Performance VPN-Based IoT Gateway.
- **Sub-title**: Balancing Zero-Trust Security with Microsecond Latency.
- **Core Message**: Why standard IoT security (Bluetooth/Zigbee) is failing, and how we fix it at the network layer.

---

## Slide 2: The Problem Space
- **Fragmented Standards**: Zigbee, Z-Wave, and MQTT lack unified encryption.
- **The "Plaintext" Problem**: Most home IoT traffic is readable via Wireshark.
- **Auth Vulnerability**: Single-phase passwords are easily brute-forced.
- **Latency Fears**: Manufacturers skip security to avoid the "40ms TLS Penalty."

---

## Slide 3: Our Solution (The Architecture)
- **Zero-Trust Model**: No device is trusted until authenticated via 2-phases.
- **WireGuard Tunneling**: Moving encryption from the application layer to the kernel/transport layer.
- **3-Layer ACL Engine**:
    1.  **Network Layer** (IP Whitelisting)
    2.  **Identity Layer** (JWT & 2FA)
    3.  **Heuristic Layer** (Anomaly Detection)

---

## Slide 4: Research Methodology (The "Grade")
- **Dolev-Yao Adversary**: Formally assuming an attacker has full network control.
- **Experimental Setup**: Simulated "Swarm" of 100+ devices.
- **Comparative Analysis**: Our VPN solution vs. Industry Standard TLS (HTTPS).

---

## Slide 5: Performance Results (The "Wow" Factor)
- **Key Metric**: 1.47ms vs 46.17ms.
- **Visual suggestion**: A Bar Chart showing "Handshake/Processing Latency."
- **Insight**: We achieved **31x speedup** over TLS by utilizing persistent tunnels and pre-shared keys.

---

## Slide 6: Security Verification (The Penetration Test)
- **Replay Attack**: Blocked by Nonce tracking.
- **Brute-Force**: Stopped by Bcrypt rounds + 2FA + Lockout.
- **Sniffing**: Demonstrated full ciphertext noise vs plaintext data.

---

## Slide 7: Intelligent Defense (Anomaly Detection)
- **Mechanism**: Heuristic Monitor tracking request frequency.
- **Scenario**: A "compromised" thermostat suddenly floods the network.
- **Output**: Real-time flagging and automatic ACL blocking.

---

## Slide 8: Scalability Limitations (Academic Honesty)
- **Findings**: Linear latency growth up to 50 devices.
- **Bottleneck**: SQLite locking during high-concurrency registration.
- **Future Work**: Migrating to PostgreSQL for large-scale enterprise deployments.

---

## Slide 9: Conclusion
- High security does **not** equal high latency.
- Lightweight crypto (AES-GCM) + Modern VPNs (WireGuard) is the future of the IoT Edge.

---

## Visualization Strategy (Using our CSVs)
1.  **Bar Chart [scripts/comparative_results.csv]**: "Protocol Latency Comparison." Use colors:
    -   Red: TLS (the slowest)
    -   Green: Our VPN (the fastest)
    -   Gray: Plaintext (Reference)
2.  **Line Graph [scripts/scalability_results.csv]**: "Throughput vs. Device Count."
    -   X-axis: Devices (1-100)
    -   Y-axis: Latency (ms)
    -   Show the "hockey-stick" curve where performance starts to degrade.
