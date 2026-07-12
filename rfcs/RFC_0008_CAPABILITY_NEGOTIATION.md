# RFC 0008: Ephemeral Capability Negotiation

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
To ensure backwards compatibility while enabling rapid protocol evolution, DCP nodes must negotiate their capabilities at session startup. This document specifies the handshake format and negotiation rules for protocol versions, crypto suites, and application features.

---

## 2. Handshake Payload Format

Capability negotiation is carried within a `0x05` **Handshake** packet payload. The decrypted payload has the following binary structure:

```
+------------------+------------------+------------------+------------------+
| Client Proto(1B) | Min Proto (1B)   | Crypto Mask (2B) | Feature Mask (2B)|
+------------------+------------------+------------------+------------------+
| Device ID Length (2B)               | Device ID (Variable Length)         |
+-------------------------------------+-------------------------------------+
| Optional Extension Card (Variable Length)                                 |
| ...                                                                       |
+---------------------------------------------------------------------------+
```

### 2.1. Payload Fields

1. **Client Protocol Version** (1 byte): The highest version of DCP the client supports.
2. **Minimum Protocol Version** (1 byte): The lowest version of DCP the client can fall back to.
3. **Crypto Suite Mask** (2 bytes, Big-Endian): A bitmask representing supported cryptographic suites:
   - `Bit 0`: `0x01` suite (Ed25519, X25519, ChaCha20-Poly1305, SHA256)
   - `Bit 1`: `0x02` suite (Ed25519, X25519, AES-256-GCM, SHA256)
   - `Bit 2`: Post-quantum hybrid suite
   - `Bits 3-15`: Reserved
4. **Feature Mask** (2 bytes, Big-Endian): A bitmask representing supported application features:
   - `Bit 0`: Direct Messages (1-on-1 chat)
   - `Bit 1`: Voice calls (direct P2P signalling)
   - `Bit 2`: Video calls (direct P2P signalling)
   - `Bit 3`: Chunked File Transfer
   - `Bit 4`: Group Chats
   - `Bit 5`: Ephemeral indicators (typing/online presence)
   - `Bits 6-15`: Reserved
5. **Device ID** (Variable Length): The public key identifying this client device.

---

## 3. Negotiation State Machine

When User A wants to start a secure channel with User B:

1. **Exchange**: User A initiates contact by sending their `0x05` Handshake packet containing their Capability masks.
2. **Evaluation**: User B receives the packet, parses the masks, and compares them with their own capabilities.
   - **Protocol Version**: The active version is set to `min(A_client, B_client)`. If this value is less than the recipient's supported minimum version, the connection is terminated with a protocol mismatch error.
   - **Crypto Suite**: The highest common bit set in both crypto masks is chosen. If there is no common crypto suite, the connection is aborted.
   - **Features**: The intersection of the two feature masks is calculated (`Features_Negotiated = A_mask & B_mask`).
3. **Response**: User B replies with their own `0x05` Handshake packet confirming the negotiated parameters.
4. **Active Session**: Both clients proceed with messaging, disabling any UI options or packet types that are not active in `Features_Negotiated`.
