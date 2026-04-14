# Formal Threat Model: IoT Secure Home Network

## 1. Adversarial Model
We adopt the **Dolev-Yao Adversary Model**, assuming an attacker who has full control over the communication network. The attacker can:
- Intercept any message sent between nodes.
- Modify, delete, or replay captured messages.
- Inject their own forged messages.
- Capture specific IoT devices (Physical compromise is considered out-of-scope for the network layer but mitigated by per-device keys).

### Attacker Profiles
- **Passive Sniffer**: Aims to eavesdrop on telemetry to identify user habits (Privacy breach).
- **Active Injector**: Aims to send unauthorized commands (e.g., "Unlock Door") via Replay or Man-in-the-Middle (MITM).
- **Brute-Force Attacker**: Aims to gain administrative control over the Gateway through credential smashing.

---

## 2. Security Assumptions
1.  **Trustworthy Gateway**: The Edge Gateway is considered a "Trusted Execution Environment" unless physically compromised.
2.  **Cryptographic Primitives**: Standard primitives (Curve25519, ChaCha20-Poly1305, AES-GCM) are assumed to be computationally secure against non-quantum adversaries.
3.  **Out-of-Band Registration**: The initial sharing of keys (or setup of TOTP) is done over a secure physical channel or local-only network during onboarding.

---

## 3. Defense-in-Depth Analysis

### 3.1 Resistance to Replay Attacks
- **Mechanism**: Use of **96-bit unique nonces** in AES-GCM and **timestamped JWT tokens**.
- **Formal Proof Concept**: Let $M$ be the message and $N$ be the nonce. The tuple $(N, E_K(M, N))$ is unique. Re-sending the same tuple is rejected by the Gateway because the nonce $N$ is tracked (or significantly outside the valid time window of the JWT).

### 3.2 Resistance to Man-in-the-Middle (MITM)
- **Mechanism**: **WireGuard VPN (Curve25519 Diffie-Hellman)**.
- **Analysis**: Since the Gateway and Peer perform a mutually authenticated key exchange, an attacker $E$ cannot establish a bridge between User $A$ and Gateway $B$ without $E$ possessing the private keys of either $A$ or $B$.

### 3.3 Resistance to Brute-Force
- **Mechanism**: **Iterative Bcrypt + TOTP (2FA)**.
- **Analysis**: Even if the entropy of the password is low, the **second phase (TOTP)** adds a 6-digit dynamic factor ($10^6$ combinations) that changes every 30 seconds. The **Account Lockout** policy further limits the search space to 5 attempts per window, making brute-force mathematically infeasible.

---

## 4. Protection Goals (CIA Triad)

| Goal | Implementation |
| :--- | :--- |
| **Confidentiality** | AES-128 GCM encryption ensures that telemetry data is unreadable to sniffers. |
| **Integrity** | AES-GCM tags (16-byte) detect any tampering with the ciphertext during transit. |
| **Availability** | Rate limiting and IP blacklisting mitigate low-level DoS attacks against the Gateway. |

---

## 5. Mitigation Summary

| Threat | Mitigation Strategy | Efficiency |
| :--- | :--- | :--- |
| **Packet Sniffing** | WireGuard Tunnel + AES-GCM | O(1) Overhead |
| **Command Injection** | 2FA (TOTP) + JWT Signature | High Security |
| **Replay Attack** | Nonce Tracking + Short JWT Expiry | Medium Memory |
| **Dictionary Attack** | Bcrypt (12 Rounds) + Lockout | High CPU (on Auth) |
