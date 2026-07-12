# RFC 0011: Relay Reputation & Adaptive PoW

```
Status: Stable
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
This document specifies client-side local reputation scoring and the relay-side adaptive Proof-of-Work (PoW) throttling protocol. It defines the metrics collected, path selection algorithms, load-balancing route diversity, and dynamic hashcash challenges.

---

## 2. Client-Side Local Reputation Scoring

Clients evaluate the performance of relays using local observations only. Metrics are never uploaded to any node.

### 2.1. Metrics Collected
1. **Latency ($L_{ms}$)**: Round-trip time of handshakes and packets.
2. **Uptime ($U$)**: Percentage of successful connections over attempts.
3. **Delivery Success ($D$)**: Ratio of successfully delivered packets to total sent.
4. **Mailbox Reliability ($M$)**: Verification that packets stored in mailbox are successfully fetched and deleted via signed ACKs without corruption.
5. **Connection Health ($H$)**: Inverse count of unexpected socket disconnects, handshake failures, and packet corruptions.

### 2.2. Scoring Profiles
Clients calculate a weighted reputation score $S \in [0, 100]$ using one of four selectable profiles:

| Profile | Latency ($W_L$) | Uptime ($W_U$) | Delivery ($W_D$) | Mailbox ($W_M$) | Health ($W_H$) |
|---|---|---|---|---|---|
| **Balanced** | 0.20 | 0.30 | 0.20 | 0.10 | 0.20 |
| **Latency Optimized** | 0.50 | 0.15 | 0.10 | 0.10 | 0.15 |
| **Reliability Optimized** | 0.10 | 0.40 | 0.20 | 0.15 | 0.15 |
| **Privacy Optimized** | 0.10 | 0.20 | 0.10 | 0.10 | 0.50 |

Score Equation:
$$S = (W_L \times L_{factor}) + (W_U \times U) + (W_D \times D) + (W_M \times M) + (W_H \times H)$$
where $L_{factor} = \max(0, 100 - (L_{ms} / 10))$.

---

## 3. Route Diversity & Load Balancing

To prevent centralization where all clients select the single fastest active relay, the path selection algorithm enforces route diversity.

### 3.1. Recently Used Penalty
- When building an onion path, the SDK applies a **Recently Used Penalty** to relays chosen in the last 5 minutes:
  $$S_{active} = S_{local} - 15$$
- This temporary 15-point penalty pushes the client to select alternative high-quality nodes, balancing network load and obscuring routing patterns.

---

## 4. Adaptive Proof-of-Work (PoW)

Relay nodes monitor their incoming packet queues and adjust PoW difficulty to throttle spam.

### 4.1. Difficulty Target Gates
The difficulty bits target dynamically scales based on requests per second:

| Requests/Sec | Difficulty Bits | Average Solve Time |
|---|---|---|
| $< 5$ (Idle) | **8** | $< 5$ ms |
| $5 \le \text{RPS} < 20$ (Medium) | **12** | $\approx 80$ ms |
| $\ge 20$ (Heavy / Attack) | **18** | $\approx 2.5$ sec |

- The challenge salt and difficulty expire after **5 minutes**. Nonces submitted after challenge expiration are rejected.
