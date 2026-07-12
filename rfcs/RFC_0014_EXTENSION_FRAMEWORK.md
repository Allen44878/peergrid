# RFC 0014: Extension Framework

```
Status: Draft
Version: 1.0.0
Author: DCP Core WG
Date: 2026-07-13
```

## 1. Introduction
To preserve the frozen status of the core DCP protocol layers (RFC-0001 through RFC-0013) while allowing developers to construct third-party integrations, bots, automation scripts, and user interface plugins, this document specifies the Extension Framework.

---

## 2. Interface Boundaries
All extensions operate strictly in the **Application Layer** of the DCP stack:
- Extensions communicate with the DCP Client SDK via a secure local IPC (Inter-Process Communication) socket or a sandboxed JavaScript API.
- Extensions **never** access raw private identity keys or private session keys.
- Extensions receive decrypted message streams and send plain text messages to the SDK, which handles PKCS#7 padding, onion wrapping, double ratcheting, and transport serialization.

---

## 3. Automation & Bot Accounts
- Bots represent standard user identities with specialized capability flags registered in their **Device Cards** (RFC-0008).
- E2EE sessions with bots are established using the same Double Ratchet mechanism. The bot platform decrypts incoming commands and executes actions in isolated execution sandboxes.
