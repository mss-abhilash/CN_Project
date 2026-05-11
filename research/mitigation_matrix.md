# Attack Mitigation & Access Control Matrix

| Attack Vector | Threat Level | Primary Mitigation Layer | Mechanism Description |
| :--- | :---: | :--- | :--- |
| **Eavesdropping / Packet Sniffing** | High | Transport Security (VPN) | All telemetry is encrypted via AES-128 GCM, preventing payload inspection. |
| **Replay Attacks** | High | Encryption Protocol | Cryptographic nonces generated for each payload ensure old packets are rejected. |
| **Sybil / Rogue Device** | Critical | Two-Phase Authentication | Devices require both valid hashed credentials (bcrypt) and a valid TOTP code to establish a session. |
| **SSH Brute Force / Probing** | Medium | Gateway / Sentinel-Trap | Unauthenticated lateral probing is intercepted and permanently diverted to a deceptive Honeypot environment. |
| **Denial of Service (DoS)** | Low-Medium | API Rate Limiter | `SlowAPI` integration restricts authentication endpoint spamming to 5 requests/minute. |
| **Data Manipulation** | Critical | Encryption / ACL Engine | AES-GCM guarantees payload integrity; ACL engine enforces strict structural schemas before vault insertion. |
