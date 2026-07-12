# PeerGrid Alpha Launch Checklist

Use this checklist to verify application security, transport reliability, and operational readiness before distributing the PeerGrid Progressive Web App (PWA) client to alpha testers.

---

## 1. Security Checklist

- [ ] **Mnemonic visibility**: Ensure the 12-word recovery phrase is displayed clearly during setup and the user is warned that loss of this seed equals permanent loss of identity and logs.
- [ ] **Zero leakage**: Verify that the 12-word mnemonic is never transmitted over the network (check local consoles and network inspectors).
- [ ] **Encrypted local storage**: Verify that plaintext mnemonics and raw private keys are never stored directly in local storage.
- [ ] **Vault integrity**: Ensure that the AES-GCM-256 vault is generated with unique salt and IV blocks for every state update.
- [ ] **Brute-force delay**: Verify that repeated vault unlock failures introduce exponential backoff or brief UI locking delays (e.g. 1 second per failed attempt).

---

## 2. Reliability & Restore Checklist

- [ ] **PWA installation**: Install the client on both Android and iOS devices. Check launcher icons and standalone fullscreen rendering.
- [ ] **Browser refresh**: Ensure that refreshing the page preserves E2EE history and contact whitelists (requires entering Security PIN/Passphrase).
- [ ] **State restore**: Reset the wallet local cache and verify that the client correctly rebuilds the entire profile and derives identical keys using the 12-word recovery phrase.
- [ ] **Offline sync**: Send a message while the receiver is offline. Connect the receiver and verify that mailbox queues successfully deliver and clear the packets.

---

## 3. Alpha Launch Playbook

### 3.1. Deploying the PWA
Host the PWA client directory (`client/`) on a static hosting provider or VPS with forced HTTPS redirection.
* Ensure WebSocket endpoints are configured with secure protocols (`wss://`).

### 3.2. Alpha Test Group
- Reciprocate testing with **10–20 testers**.
- Ensure a heterogeneous mix of hardware: iOS, Android, Windows, and macOS devices.
- Run unscripted observations to track where users struggle.

### 3.3. Feedback Sheet
Ask specific, targeted questions:
1. *Was creating or restoring your identity easy?*
2. *Could you add another user without help?*
3. *Did messages arrive reliably?*
4. *Did file transfers complete?*
5. *Was anything confusing?*
6. *Did the app ever freeze or crash?*
7. *Would you use this instead of another messaging app for a day?*

### 3.4. Bug Tracking Matrix
Track issues categorized by priority:

| Priority | Type | Example |
| :--- | :--- | :--- |
| 🔴 **Critical** | Security / Data Loss | Wallet fails to restore from seed |
| 🟠 **High** | Reliability | Packets not fetched from mailbox |
| 🟡 **Medium** | UX | Eviction warning not clear |
| 🔵 **Low** | Cosmetic | Text overflow in debug JSON panel |
