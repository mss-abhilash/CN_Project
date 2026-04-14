# Project Abstract: Unified Secure Edge Gateway for IoT

**Keywords**: IoT Security, WireGuard, AES-128 GCM, Zero-Trust, Edge Computing.

### Research Problem
The exponential growth of Internet of Things (IoT) devices has created a massive surface area for cyberattacks. Current security implementations often rely on weak, application-layer encryption (e.g., standard MQTT or plaintext HTTP) because of the significant latency overhead and complexity associated with Transport Layer Security (TLS) handshakes on resource-constrained hardware.

### Methodology
This research proposes a **Unified Secure Edge Gateway (USEG)** architecture that shifts security from the application layer to a hardened network layer. Our solution utilizes a persistent **WireGuard (Curve25519)** VPN tunnel and **AES-128 GCM** application-layer encryption to ensure end-to-end confidentiality and integrity. We implemented a three-tier Access Control List (ACL) engine featuring:
1.  **Identity-based validation** (JWT & Multi-Factor TOTP).
2.  **Context-aware rate limiting**.
3.  **Heuristic anomaly detection** for identifying atypical traffic patterns.

### Key Findings
Experimental analysis was conducted using a "Swarm" simulation of 100 concurrent IoT devices. 
- **Performance**: The proposed USEG architecture demonstrated a mean end-to-end latency of **1.47 ms**, representing a **31.4x improvement** over industry-standard TLS-simulated processing (~46.17 ms).
- **Security Posture**: Penetration testing verified 100% resistance to Replay, Brute-force, and Packet Sniffing attacks under the Dolev-Yao adversary model.
- **Scalability**: While the architecture maintains O(1) encryption overhead, performance bottlenecks were identified at 50+ concurrent devices due to in-memory database locking, suggesting a path forward for enterprise-grade clustering.

### Conclusion
Our results demonstrate that high-grade security does not require high-latency trade-offs. By combining modern light-weight cryptography with persistent network tunneling, standard home IoT devices can achieve enterprise-level security with negligible performance impact.
