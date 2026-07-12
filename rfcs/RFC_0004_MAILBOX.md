# RFC 0004: Mailbox Protocol

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
This document defines the Mailbox Protocol, the offline store-and-forward mechanism of the Decentralized Communication Protocol (DCP). It describes the lifecycle of offline packets, quota limits, and the secure, signed Delivery Acknowledgment (ACK) flow.

---

## 2. Packet Lifecycle & Database Schema

If a packet's recipient is offline, the Exit Relay caches the packet. The record status must track the packet state accurately.

### 2.1. Mailbox Record Fields

| Field Name | Type | Description |
|---|---|---|
| `mailbox_id` | `[32]byte` | Unique identifier for the mailbox entry. |
| `recipient_hash` | `[32]byte` | `SHA-256` of the Recipient's Master Identity Public Key. |
| `packet_id` | `[32]byte` | The cryptographic SHA-256 identifier of the binary packet payload. |
| `encrypted_packet` | `[]byte` | The binary packet content (with nested onion routing envelopes peeled). |
| `created_at` | `uint64` | Unix Epoch timestamp (seconds) when the packet entered the mailbox. |
| `expires_at` | `uint64` | Unix Epoch timestamp (seconds) after which the packet must be deleted. |
| `retry_counter` | `uint8` | Number of times the relay attempted delivery to the recipient. |
| `delivery_state` | `string` | Current audit state: `Pending` | `Delivered` | `Expired` | `Deleted`. |
| `integrity_hash` | `[32]byte` | `SHA-256` hash of the encrypted packet payload for integrity validation. |

---

## 3. Secure Delivery Acknowledgment (ACK)

To verify that a packet was successfully received by the intended recipient before deleting it, the exit relay requires a signed delivery acknowledgment.

### 3.1. ACK Payload Structure
The client generates an ACK block containing:
```json
{
  "packet_id": "sha256_hash_of_packet",
  "recipient_device_id": "recipient_device_public_key_hex",
  "timestamp": 1782390231,
  "relay_session_id": "noise_handshake_session_nonce"
}
```

### 3.2. Signature Verification
- The recipient signs the SHA-256 hash of this JSON block using their **Device Identity Key** (derived under RFC-0001).
- The Exit Relay validates the signature against the registered device card.
- **Replay Protection**: The relay checks the `timestamp` (must be within $\pm$ 5 minutes of current clock to prevent replay) and the `relay_session_id`. It discards duplicate ACKs.
- Once verified, the relay updates the packet's `delivery_state` to `Delivered`, purges the packet payload from storage, and marks the record `Deleted`.

---

## 4. Quotas, Expiration & Retries

### 4.1. Mailbox Quota Limits
To prevent denial-of-service storage exhaustion, relays enforce strict limits per user mailbox:
- **Maximum Packets**: 500 packets.
- **Maximum Size**: 10 Megabytes.
- **Overflow Behavior**: If a user's mailbox exceeds either threshold, the relay discards the oldest `Pending` packets (First-In, First-Out) to make space. It returns a `0x07` Acknowledgment packet to the sender denoting mailbox overflow.

### 4.2. TTL & Expiration
- **Default TTL**: 24 hours. The sender can configure this in the packet headers up to a maximum of 7 days.
- **Cleanup**: Relays run a background cleanup task every 10 minutes, changing the status of expired packets to `Expired` and purging their payloads.

### 4.3. ACK Timeouts
- **Delivery Attempt**: When the recipient reconnects, the relay streams all pending packets.
- **ACK Wait**: The relay expects an ACK within **5 minutes**.
- If no ACK is received, the relay increments the `retry_counter`. It will retry up to **3 times** on subsequent reconnections. After 3 failed attempts, the packet state is marked `Expired` and purged.
