# RFC 0009: Metadata Protection Spec

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
This document specifies metadata protection mechanisms in DCP. It defines packet size obfuscation (padding), timing obfuscation (random delays), dummy cover traffic generation, and configurable bandwidth budgets to defend against traffic analysis and network eavesdropping.

---

## 2. Packet Size Obfuscation (Padding)

To prevent attackers from fingerprinting message contents based on packet sizes, DCP clients pad payloads before encryption.

### 2.1. PKCS#7 Padding
- Payload bytes are padded using the standard **PKCS#7** padding algorithm.
- The padding byte value equals the number of padding bytes added.
- **Medium Privacy Mode**: Envelopes are padded to the nearest **256-byte** boundary.
- **Maximum Privacy Mode**: Envelopes are padded to a fixed size of **2048 bytes** plus a small randomized jitter offset of `0 to 128 bytes` (yielding variable boundaries to confuse strict packet filter matching).

---

## 3. Timing Obfuscation & Cover Traffic

To obscure the time at which communication events occur, the client SDK routes packets through timing delays and generates synthetic dummy traffic.

### 3.1. Randomized Transmission Delays (Jitter)
- In **Medium** and **Maximum** privacy modes, relay nodes and clients inject random delays before forwarding packets:
  - **Medium Delay Jitter**: Random delay between `100ms and 500ms`.
  - **Maximum Delay Jitter**: Packets are queued and released at fixed time intervals (e.g., every `500ms`) with a micro-jitter offset of `0 to 50ms`.

### 3.2. Dummy Packet Cover Traffic
- In **Maximum** privacy mode, the client SDK runs a continuous background loop to maintain constant network activity.
- If no E2EE user packet is queued for transmission within the active `500ms` window, the client automatically generates and sends a **Dummy Packet**:
  - **Packet Type**: `0x08` Ephemeral.
  - **Payload**: Randomized length (typically matching a padded message envelope) containing cryptographically random noise.
  - **Encryption**: Encrypted using a random ephemeral key so that external passive sniffers cannot distinguish dummy traffic from actual E2EE communication.

---

## 4. Client Bandwidth Budgets

Generating dummy traffic increases network data usage. To prevent mobile battery and data drain, clients can configure a **Maximum Dummy Bandwidth Budget**:

| Budget Level | Allowed Dummy Traffic | Description |
|---|---|---|
| **Low Privacy** | 0 KB/min | Dummy packets disabled. Payload padding and timing delays disabled. |
| **Medium Privacy** | 10 KB/min | Payload padding to 256B. Dummy traffic limited to rare heartbeats. |
| **High / Max Privacy** | 500 KB/min | Payload padding to 2KB. Active dummy cover traffic loops. |
| **Unlimited** | No Limit | Constant timing interval dummy traffic. High security, high data usage. |

If the selected budget is exceeded, the SDK automatically throttles or suspends dummy packet generation, returning to Medium privacy behavior temporarily until the rate limit window resets.
