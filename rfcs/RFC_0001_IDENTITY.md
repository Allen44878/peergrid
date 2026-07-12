# RFC 0001: Identity, BIP-32 Derivation & Multi-Device

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
This document defines the identity system of the Decentralized Communication Protocol (DCP). DCP identities are fully user-owned, cryptographically secure, and human-friendly. There are no usernames or passwords registered with a central authority. Identity is rooted in a cryptographic seed derived from a mnemonic recovery phrase.

---

## 2. Key Derivation Architecture

### 2.1. Seed Generation
DCP uses the BIP-39 standard to generate a 12-word mnemonic phrase. The mnemonic is converted into a 512-bit binary seed using PBKDF2-HMAC-SHA512 (with 2048 iterations and the salt prefix `"mnemonic"` plus optional password).

### 2.2. Derivation Paths
To support multi-device syncing and modular key hierarchies without exposing the master seed, DCP defines key paths under the custom registered coin type `1234'` (non-hardened paths for subkeys allow public derivation when appropriate, though DCP uses hardened keys for master paths):

`m / 44' / 1234' / 0'` (DCP Master Root Account)

Below this master path, keys are derived for specific cryptographic functions:

| Path | Purpose | Key Type | Description |
|---|---|---|---|
| `m/44'/1234'/0'/0/0` | Identity Signature Key | Ed25519 | The primary master identity key. Used for signing device lists, profiles, and contact cards. |
| `m/44'/1234'/0'/0/1` | Identity Key Agreement Key | X25519 | Derived from the master seed for initial Diffie-Hellman handshakes (prekeys). |
| `m/44'/1234'/0'/0/2` | Local Storage Encryption | Symmetric | Derived to encrypt the user's local database. |
| `m/44'/1234'/0'/1/d` | Device Signing Key | Ed25519 | Device-specific signing key (where `d` represents device index `0, 1, 2...`). |
| `m/44'/1234'/0'/2/d` | Device Encryption Key | X25519 | Device-specific encryption key for direct message ratcheting. |

---

## 3. Human-Friendly User IDs

To ensure that keys are easily shareable, DCP introduces a network-aware User ID format.

```
@<username>.<network>.<checksum>
```

### 3.1. Fields
1. **username**: A user-defined handle containing 3 to 15 characters (regex `^[a-z0-9_]{3,15}$`). This handle is only stored locally by contacts and does not require global registry validation (collisions are resolved via the public key checksum).
2. **network**: Defines the subnet ID (e.g., `dcp` for the main network, `test` for developer sandboxes).
3. **checksum**: A 4-character Base32 string used to verify key matching and resolve collisions.

### 3.2. Checksum Calculation
Let `PK_Ed` be the 32-byte Ed25519 Master Identity Public Key.
1. Calculate `Hash = SHA-256(PK_Ed)`.
2. Extract the first 20 bits (2.5 bytes) of `Hash`.
3. Encode these 20 bits into a 4-character Base32 string (using the alphabet `abcdefghjkmnpqrstuvwxyz23456789`, excluding confusing characters `i`, `l`, `o`, `0`, `1`).

*Example*: If `PK_Ed` hashes to a value whose first 2.5 bytes match the index indices for `4k8x`, the resulting ID might look like `@dip.dcp.4k8x`.

---

## 4. Multi-Device Architecture

To prevent sharing the master seed across secondary devices (e.g., laptops, tablets), DCP implements a Master-to-Device key delegation structure.

### 4.1. Device Registration (Device Cards)
When adding a new device:
1. The secondary device generates its own local ephemeral Ed25519 identity key (`device_pub_sign`) and X25519 key (`device_pub_enc`).
2. The primary device (which has access to the master identity key) signs a **Device Card**:
   ```json
   {
     "master_id": "Ed25519_Master_Public_Key_Hex",
     "device_id": "Ed25519_Device_Public_Key_Hex",
     "device_enc": "X25519_Device_Public_Key_Hex",
     "device_name": "My Laptop",
     "issued_at": 1782390231,
     "expires_at": 1813926231,
     "signature": "Ed25519_Signature_of_Card_By_Master_Identity_Key"
   }
   ```
3. This card is uploaded to the user's active Relays. When other contacts connect, they download the Device Card, verify the master signature, and initiate Double Ratchet sessions directly with each active device key.
