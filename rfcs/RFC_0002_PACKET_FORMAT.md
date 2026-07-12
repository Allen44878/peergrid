# RFC 0002: Binary Packet Layout & Flags

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
To ensure maximum speed, minimal overhead, resistance to fingerprinting, and future-proof extensibility, DCP defines a strict binary packet serialization layout. All packet headers are serialized in big-endian byte order.

---

## 2. Packet Layout Spec

A DCP packet consists of a **Binary Header**, a **Cryptographic Signature**, and the **Encrypted Payload**.

```
+------------------+------------------+------------------+------------------+
| Magic (4B)                          | Protocol Ver(1B) | Header Ver(1B)   |
+------------------+------------------+------------------+------------------+
| Flags (1B)       | Cipher Suite(1B) | Packet Type (1B) | TTL (1B)         |
+------------------+------------------+------------------+------------------+
| Timestamp (8B)                                                            |
|                                                                           |
+------------------+------------------+------------------+------------------+
| Packet ID (32B)                                                           |
|                                                                           |
|                                                                           |
|                                                                           |
+------------------+------------------+------------------+------------------+
| Payload Len (4B) |                                                        |
+------------------+------------------+------------------+------------------+
| Header Signature (64B)                                                    |
|                                                                           |
|                                                                           |
|                                                                           |
+------------------+------------------+------------------+------------------+
| Encrypted Payload (Variable Length)                                       |
| ...                                                                       |
+---------------------------------------------------------------------------+
```

### 2.1. Header Fields Specification

| Offset (Bytes) | Field Name | Size (Bytes) | Type | Description |
|---|---|---|---|---|
| 0 | **Magic Bytes** | 4 | `[4]byte` | Always `0x44 0x43 0x50 0x01` (`DCP\x01`). |
| 4 | **Protocol Version** | 1 | `uint8` | Version of the DCP protocol suite (e.g. `0x01`). |
| 5 | **Header Version** | 1 | `uint8` | Version of the header formatting schema (e.g. `0x01`). |
| 6 | **Flags** | 1 | `uint8` | Bitmask specifying transport and payload flags (see Section 2.2). |
| 7 | **Cipher Suite ID** | 1 | `uint8` | Cryptographic suite selection (see Section 2.3). |
| 8 | **Packet Type** | 1 | `uint8` | Message payload classification (see Section 2.4). |
| 9 | **TTL** | 1 | `uint8` | Time-to-Live / Hop count remaining. Decremented by each relay. |
| 10 | **Timestamp** | 8 | `uint64` | Unix Epoch timestamp in milliseconds. |
| 18 | **Packet ID** | 32 | `[32]byte` | Cryptographic SHA-256 hash of the payload. |
| 50 | **Payload Length** | 4 | `uint32` | Size of the Encrypted Payload in bytes. |
| 54 | **Header Signature** | 64 | `[64]byte` | Ed25519 signature of bytes `0` to `53` (Header), signed by the sender's device key. |
| 118 | **Encrypted Payload** | Var | `[]byte` | The actual packet payload, encrypted according to Cipher Suite. |

---

## 2.2. Flags Bitmask

The `Flags` byte (Offset 6) is a bitmask used to direct packet processing:

| Bit | Name | Description |
|---|---|---|
| `0` (LSB) | **Compressed** | If set (`1`), the decrypted payload must be decompressed (e.g., using zlib/deflate). |
| `1` | **Encrypted** | If set (`1`), the payload is encrypted. If unset (`0`), payload is plaintext. |
| `2` | **Signed** | If set (`1`), a signature covers the payload. |
| `3` | **Relay-Forwarded** | Set by relays to denote packet went through onion routing. |
| `4-7` | **Reserved** | Reserved for future extensions (e.g. priority flags). |

---

## 2.3. Cipher Suite IDs

DCP allows cipher negotiation via the `Cipher Suite ID` field (Offset 7):

| ID | Suite Primitives | Status |
|---|---|---|
| `0x01` | **Ed25519 + X25519 + ChaCha20-Poly1305 + SHA-256** | Active (Default) |
| `0x02` | **Ed25519 + X25519 + AES-256-GCM + SHA-256** | Supported |
| `0x90` | **Post-Quantum Hybrid (ML-DSA-65 + Kyber-768)** | Draft / Future |

---

## 2.4. Packet Types

The `Packet Type` byte (Offset 8) determines how the payload is routed and processed:

| Code | Type Name | Description |
|---|---|---|
| `0x01` | **Direct Message** | Core text/chat message (Double Ratchet encrypted). |
| `0x02` | **Voice Signaling** | SDP offer/answer or ICE candidate (Double Ratchet encrypted). |
| `0x03` | **Video Signaling** | Video session initiation parameters. |
| `0x04` | **File Descriptor** | Chunk descriptors, hashes, and encryption keys for files. |
| `0x05` | **Handshake** | Initial identity verification and capability exchange. |
| `0x06` | **Group Update** | Member addition, removal, or group key rotation. |
| `0x07` | **Acknowledgment** | Mailbox download confirmations and read receipts. |
| `0x08` | **Ephemeral** | Low-latency state notifications (typing indicators, presence). |
