# DCP Design Principles

This document outlines the core architectural and philosophical principles guiding the development of the Decentralized Communication Protocol (DCP). All future protocol additions, reference implementations, and extension designs must align with these values.

---

## 1. Core Principles

### 1.1. Privacy by Default
Security controls are not opt-in. All user identity data, message contents, file transfers, and metadata are encrypted end-to-end and hidden by default.

### 1.2. User Ownership of Identity & Data
Users are the sole owners of their identities and data. No central registrar, identity provider, or directory exists. All identities are cryptographic public keys (Ed25519) and cannot be revoked, suspended, or modified by external network entities.

### 1.3. Protocols over Products
DCP is defined strictly as a protocol layer (RFCs 0001–0014), not a single product or service. The protocol is implementation-neutral, allowing developers to construct compatible clients and relays in any language.

### 1.4. Stable Standards, Evolving Implementations
The core protocol is frozen and versioned. Higher-level services (device sync, file transfer, messaging) are implemented in the application layer, allowing rapid software iteration without introducing protocol-level instability.

### 1.5. Defense in Depth
Security does not rely on a single layer. We combine asymmetric key identity models, Double Ratchet session handshakes, multi-hop onion routing, PKCS#7 / fixed padding, and cover traffic to defend against transport eavesdropping, metadata leakage, and timing analysis.

### 1.6. Metadata Minimization
We protect not only what is said, but also who is talking, when, and from where. Onion routing blinds IP addresses, blind key derivations hide lookup patterns on the DHT, and mailbox queues decouple online presence from packet reception.

### 1.7. Local-First Architecture
Decisions regarding relay trustworthiness, routing paths, and identity circles are calculated locally on the client device. Reputation scoring is local and private, avoiding global reputation systems that leak metadata.

### 1.8. Establish, Don't Invent Cryptography
DCP relies entirely on standard, audited, peer-reviewed cryptographic primitives (Curve25519, Ed25519, AES-GCM, HKDF, SHA-256). We do not design new cryptography.
