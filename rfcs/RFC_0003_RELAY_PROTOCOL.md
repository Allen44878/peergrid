# RFC 0003: Noise Handshake, Onion Routing & Relays

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
This document specifies the interaction protocol between clients and Relay Nodes. This includes secure session establishment, layered onion encapsulation, and the adaptive Proof-of-Work (PoW) mechanism to protect relays from denial-of-service and spam attacks.

---

## 2. Relay Authentication & Noise Handshake

DCP clients communicate with relays over a secure WebSocket transport. To guarantee relay identity and prevent man-in-the-middle attacks, client-relay sessions perform a **Noise_XX_25519_ChaChaPoly_SHA256** handshake:

1. **Relay Key Announcement**: The relay publishes its long-term Ed25519 identity key (`relay_pub_sign`) and its derived X25519 encryption key (`relay_pub_dh`).
2. **Handshake Protocol**:
   - Step 1: Client -> Relay: Client sends its ephemeral public key (`e_client`).
   - Step 2: Relay -> Client: Relay sends its ephemeral public key (`e_relay`), performs Diffie-Hellman agreements, sends its static public key (`s_relay`) encrypted, and signs the session with `relay_pub_sign`.
   - Step 3: Client -> Relay: Client sends its static public key (`s_client`) encrypted, performing a final DH agreement.
3. **Session Keys**: The resulting symmetric keys are used to encrypt all socket communication between client and relay.

---

## 3. Onion Routing Layering

A message packet is onion-routed through a path of relays (typically 3 relays: Entrance, Middle, Exit).

### 3.1. Envelope Structure
Let `P_final` be the binary packet (as specified in RFC-0002) destined for the recipient. The sender selects Relay A (Entrance), Relay B (Middle), and Relay C (Exit).

The sender wraps the packet in nested onion headers, working backward:

1. **Layer 3 (Exit - Relay C)**:
   - Encrypts `[Recipient_ID, P_final]` using Relay C's public encryption key (`X25519_C`) using ChaCha20-Poly1305.
   - Result: `Envelope_C = Enc_C(Recipient_ID, P_final)`.

2. **Layer 2 (Middle - Relay B)**:
   - Encrypts `[Relay_C_Address, Envelope_C]` using Relay B's public encryption key (`X25519_B`).
   - Result: `Envelope_B = Enc_B(Relay_C_Address, Envelope_C)`.

3. **Layer 1 (Entrance - Relay A)**:
   - Encrypts `[Relay_B_Address, Envelope_B]` using Relay A's public encryption key (`X25519_A`).
   - Result: `Envelope_A = Enc_A(Relay_B_Address, Envelope_B)`.

### 3.2. Relay Processing
Each relay in the path receives an envelope, decrypts the outermost layer using its private key, extracts the address of the next hop, and forwards the inner envelope.
- **No relay sees more than one hop forward and one hop backward.**
- **Relay C (Exit)** decrypts the final layer to find the destination client ID, then either delivers it directly (if online) or deposits it into the recipient's Mailbox (if offline).

---

## 4. Adaptive Proof-of-Work (PoW)

To prevent packet flooding, a relay requires clients to solve a cryptographic PoW challenge before accepting packets for routing or mailbox storage.

### 4.1. Challenge Exchange
When a client sends a request `REQ_PUSH_PACKET`, the relay responds with:
```json
{
  "status": "pow_challenge",
  "salt": "random_hex_string_32_bytes",
  "difficulty": 12
}
```

### 4.2. Hashcash Calculation
The client must find a numeric `nonce` such that:
```
SHA-256(salt + nonce) < 2^(256 - difficulty)
```
In other words, the binary representation of the SHA-256 hash must start with `difficulty` number of leading zero bits.

### 4.3. Adaptive Difficulty
The relay dynamically adjusts the `difficulty` parameter based on its active CPU load and pending packet queues:
- **Idle Load**: Difficulty = `8` (easy, takes < 5ms).
- **Medium Load**: Difficulty = `14` (takes ~100-200ms).
- **High / Under Attack**: Difficulty = `20+` (takes > 2 seconds, throttling spam sources).
- The client submits the solved `nonce` along with the packet. The relay performs a single SHA-256 hash operation to verify the solution. If verified, the packet is queued for routing.
