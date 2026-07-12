# RFC 0013: Network Diagnostics

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
To ensure that independent implementations of DCP relays and clients can verify network health, route tracing, and diagnose performance bottlenecks, this document reserves diagnostic specifications and health-checking APIs.

---

## 2. Standardized Relay Health Metrics

Relays should expose an optional, local-only diagnostic endpoint (or via specialized admin WebSocket messages) reporting:
- `active_connections`: Total current TCP/WebSocket sessions.
- `requests_per_second`: Rate of incoming routing and registration requests.
- `pow_difficulty_level`: Current adaptive PoW bit count.
- `mailbox_records_count`: Current count of offline packets stored.
- `mailbox_storage_bytes`: Database utilization.
- `packets_dropped_overflow`: Count of packets deleted due to mailbox quotas.
- `uptime_seconds`: Process lifetime indicator.

---

## 3. Onion Path Tracing (Diagnostics Mode)

Clients can set the diagnostic flag in the binary header (RFC-0002) to request Hop Tracing:
- **Trace Envelopes**: Each hop records its latency and returns a standardized trace report back through the secure circuit.
- **Privacy Notice**: Diagnostic flags should only be enabled in testing environments. Production packets must never request hop tracing, as it leaks circuit nodes.
