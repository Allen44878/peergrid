# RFC 0010: Peer Discovery Spec

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
This document specifies the privacy-preserving peer discovery protocol of DCP. It describes the format of contact exchange invitations, rotating blinded identifiers for lookup, randomized DHT advertising intervals, and advertisement expiration windows.

---

## 2. Out-of-Band Contact Exchange

To establish a secure channel, two clients must exchange basic cryptographic identity cards.

### 2.1. Contact Card Format
A contact card is serialized as a JSON structure (encoded in text or scanned via QR code):
```json
{
  "userId": "@username.network.checksum",
  "identityKey": "ed25519_master_public_key_hex",
  "dhKey": "x25519_master_public_key_hex",
  "deviceCard": {
    "device_id": "ed25519_device_key_hex",
    "device_enc": "x25519_device_key_hex",
    "signature": "master_sig"
  },
  "activeRelays": [
    "ws://relay1.dcp.net:8765",
    "ws://relay2.dcp.net:8765"
  ]
}
```
Upon scanning, both clients derive a **Shared Contact Secret** using X25519 DH between their master identity key agreement keys.

---

## 3. Rotating Blinded DHT Identifiers

To locate a peer's active relay node without exposing their permanent identity to the DHT or relay routers, DCP uses rotating blinded lookup keys.

### 3.1. Key Derivation
The lookup key for the Distributed Hash Table (DHT) is derived from the Shared Contact Secret and the current time epoch:
```
WindowedTimestamp = Floor(UnixTime / 3600)  // 1-hour window epochs
DHT_Lookup_Key = HKDF-SHA256(SharedContactSecret || WindowedTimestamp)
```
- **Privacy Guarantee**: Since only the two users hold the `SharedContactSecret`, only they can calculate the rotating `DHT_Lookup_Key`. Passive network crawlers cannot query the DHT for a specific User ID or public key.

---

## 4. DHT Advertisement Jitter & Expiration

### 4.1. Randomized Advertisement Interval
To prevent network timing fingerprinting and load spikes where all devices republish exactly at the hour mark, clients randomize their DHT publication timer:
```
Interval = 55 + random(10) minutes  // Jittered between 55 and 65 minutes
```

### 4.2. Advertisement Expiration
- **Lifetime**: DHT advertisements are stored in the registry with a strict **90-minute Expiration TTL**.
- If a client goes offline and does not refresh their advertisement within 90 minutes, the registry automatically purges the mapping. This prevents stale relay addresses from cluttering queries.

### 4.3. Reference Implementation Overlay
This RFC defines the interface boundaries of the DHT. The Milestone 2 reference implementation simulates this registry using BroadcastChannel overlays or WebSocket relay node databases. The SDK keeps the DHT broker module modular and replaceable, allowing seamless upgrades to a standard Kademlia-based P2P overlay in future versions.
