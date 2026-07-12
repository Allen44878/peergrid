# DCP Threat Model

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

---

## 1. Introduction & Security Assumptions

This document defines the security boundaries, capabilities, and limitations of the Decentralized Communication Protocol (DCP). DCP is designed for end-to-end encrypted (E2EE), onion-routed, serverless communications.

### 1.1. Core Assumptions
- **Cryptographic Primitives**: Standard primitives (X25519, Ed25519, AES-256-GCM, HKDF-SHA256) are mathematically secure and correct.
- **Endpoint Integrity**: The user's device is secure. It is free of malware, spyware, and physical compromise.
- **Network Adversary**: The network adversary can monitor, intercept, drop, delay, and inject traffic at any point in the routing network.

---

## 2. Threat Vector Assessment

### 2.1. Protected Threat Vectors (DCP Mitigation)

| Threat | Attack Vector | DCP Mitigation Mechanism |
|---|---|---|
| **Eavesdropping** | Passive network observer sniffing packets. | All payloads are end-to-end encrypted using the **Double Ratchet** protocol. Intermediate relays only see the outermost onion envelope. |
| **Relay Compromise** | An intermediate hop (Relay A, B, or C) is malicious, modified, or compromise-audited. | **Onion routing layers** ensure no single relay knows both the sender's IP address and the recipient's IP address. Relay A knows the sender but not the recipient; Relay C knows the recipient but not the sender. |
| **Mailbox Snoop** | A malicious exit relay snooping cached offline packets. | Mailboxes store only peeled E2EE packets. The relay cannot decrypt the payload. |
| **Replay Attacks** | Injecting identical packets or duplicate acknowledgments (ACKs) twice. | Relay nodes track unique `packetId` values. Delivery ACKs sign the packet ID, recipient device ID, timestamp, and session token, rejecting skew > 5 mins. |
| **Traffic Fingerprinting** | Eavesdropper correlating user message events based on packet sizes. | Payload sizes are obfuscated using **PKCS#7 padding** (Medium) or constant **2KB fixed padding and dummy traffic** (Maximum). |

### 2.2. Unprotected Threat Vectors (Out-of-Scope)

- **Compromised Endpoints**: If an adversary gains root/admin access to a client device, they can read messages directly from RAM/storage, bypass Double Ratchet keys, or capture key entries.
- **Recovery Phrase Theft**: If an adversary steals the 12-word BIP-39 mnemonic, they can derive the user's master private identity key and register under their User ID.
- **Endpoint Physical Seizure**: Local chat logs stored on device must rely on OS-level full disk encryption (FDE) or local passcode locks.
- **Metadata Timing Correlation**: In Low/Medium privacy modes, a global passive adversary monitoring both the Entrance and Exit relays can match packets based on timing correlation. Only Maximum privacy mode (cover traffic loops) mitigates this.
- **Social Engineering**: Users scanning incorrect QR codes or adding malicious User IDs.

---

## 3. Protocol Limitations & Future Vectors

- **Relay Collusion**: If all three relays selected in an onion circuit (Entrance, Middle, Exit) are run by the same adversary and collude, the circuit anonymity is compromised. Clients mitigate this by selecting routes from diverse IP blocks and prioritizing relays with high local reputation scores.
- **Key Recovery**: There is no central authority to reset passphrases. A lost mnemonic phrase results in permanent loss of identity and message history.
