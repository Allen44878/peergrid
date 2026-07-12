/**
 * Decentralized Communication Protocol (DCP) Core SDK
 * Reference Implementation of Milestone 2
 */

// 256 Word Mini-Dictionary for Mnemonic Generation
const MEMORY_WORDS = [
  "acid", "aqua", "arch", "atom", "aura", "auto", "axis", "baby", "back", "ball",
  "band", "bank", "bare", "bark", "barn", "base", "bath", "beam", "bean", "bear",
  "beat", "beef", "beer", "bell", "belt", "best", "bike", "bird", "bite", "black",
  "blade", "block", "blow", "blue", "boat", "body", "bold", "bone", "book", "boom",
  "boot", "boss", "bowl", "brick", "bright", "brown", "brush", "buck", "bulb", "bull",
  "burn", "bush", "busy", "buzz", "cake", "call", "calm", "camp", "cane", "cape",
  "card", "care", "case", "cash", "cast", "cave", "cell", "cent", "chat", "chef",
  "chin", "chip", "city", "clan", "claw", "clay", "cliff", "clog", "club", "coal",
  "coat", "code", "coin", "cold", "cone", "cook", "cool", "cope", "cord", "core",
  "cork", "corn", "cost", "cozy", "crab", "cram", "crew", "crop", "crow", "cube",
  "cult", "cup", "cure", "curl", "cute", "dawn", "days", "deal", "dear", "debt",
  "deep", "deer", "desk", "dial", "diet", "disc", "dock", "dog", "doll", "dome",
  "door", "dose", "dove", "down", "drag", "draw", "dream", "dress", "drift", "drill",
  "drink", "drip", "drive", "drop", "drum", "dry", "duck", "duct", "duke", "dull",
  "dust", "duty", "each", "earn", "earth", "east", "easy", "echo", "edge", "edit",
  "epic", "even", "ever", "exam", "exit", "face", "fact", "fade", "fair", "fake",
  "fall", "fame", "fang", "farm", "fast", "fate", "fear", "feed", "feel", "fiber",
  "field", "file", "film", "find", "fine", "fire", "firm", "fish", "fist", "five",
  "flag", "flame", "flat", "flee", "flesh", "flight", "flip", "float", "flock", "flow",
  "flower", "fluid", "fly", "foam", "focus", "fog", "foil", "fold", "folk", "food",
  "foot", "force", "ford", "forest", "forge", "fork", "form", "fort", "found", "four",
  "fox", "frame", "free", "fresh", "fret", "frog", "front", "frost", "frown", "fruit",
  "fuel", "full", "fume", "fund", "funky", "fuse", "game", "gang", "gap", "gas",
  "gate", "gear", "gem", "ghost", "giant", "gift", "giggle", "glad", "glass", "glide",
  "globe", "gloom", "glory", "glow", "glue", "goal", "goat", "gold", "golf", "good"
];

// Helper: Convert Uint8Array to Hex String
export function toHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: Convert Hex String to Uint8Array
export function fromHex(hex) {
  if (!hex) return new Uint8Array(0);
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const arr = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

// Helper: Base32 Encoding for User ID Checksum
const B32_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
export function encodeBase32(bytes) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

// PKCS#7 Padding
export function padPKCS7(data, blockSize = 256) {
  const padLength = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLength);
  padded.set(data, 0);
  padded.fill(padLength, data.length);
  return padded;
}

export function unpadPKCS7(data) {
  const padLength = data[data.length - 1];
  if (padLength < 1 || padLength > data.length) {
    throw new Error("Invalid PKCS#7 padding size");
  }
  for (let i = data.length - padLength; i < data.length; i++) {
    if (data[i] !== padLength) {
      throw new Error("Invalid PKCS#7 padding contents");
    }
  }
  return data.slice(0, data.length - padLength);
}

// Fixed-Size Padding (with Jitter)
export function padFixedSize(data, baseSize = 2048, jitterMax = 128) {
  const jitter = Math.floor(Math.random() * jitterMax);
  const totalSize = baseSize + jitter;
  if (data.length > totalSize - 4) {
    throw new Error("Payload too large for fixed-size padding block");
  }
  const result = new Uint8Array(totalSize);
  new DataView(result.buffer).setUint32(0, data.length);
  result.set(data, 4);
  
  // Fill remaining space with random bytes
  const randomNoise = new Uint8Array(totalSize - 4 - data.length);
  window.crypto.getRandomValues(randomNoise);
  result.set(randomNoise, 4 + data.length);
  return result;
}

export function unpadFixedSize(data) {
  const len = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(0);
  if (len < 0 || len > data.length - 4) {
    throw new Error("Invalid fixed-size padding length indicator");
  }
  return data.slice(4, 4 + len);
}

export class DCPIdentity {
  static generateMnemonic() {
    const entropy = new Uint8Array(16);
    window.crypto.getRandomValues(entropy);
    const words = [];
    for (let i = 0; i < 12; i++) {
      const index = entropy[i % entropy.length];
      words.push(MEMORY_WORDS[index]);
    }
    return words.join(" ");
  }

  static async deriveSeed(mnemonic, passphrase = "") {
    const encoder = new TextEncoder();
    const salt = encoder.encode("mnemonic" + passphrase);
    const mnemonicBytes = encoder.encode(mnemonic.trim().toLowerCase().replace(/\s+/g, " "));
    const pbkdf2Key = await crypto.subtle.importKey(
      "raw",
      mnemonicBytes,
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const seedBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 2048,
        hash: "SHA-512"
      },
      pbkdf2Key,
      512
    );
    return new Uint8Array(seedBits);
  }

  static parseUserId(userId) {
    const match = userId.match(/^@([a-z0-9_]{3,15})\.([a-z0-9_]{3,10})\.([a-z2-9]{4})$/);
    if (!match) return null;
    return {
      username: match[1],
      network: match[2],
      checksum: match[3]
    };
  }

  static async generateUserId(username, network, identityPublicKey) {
    const pkBytes = typeof identityPublicKey === 'string' ? fromHex(identityPublicKey) : identityPublicKey;
    const hashBuffer = await crypto.subtle.digest("SHA-256", pkBytes);
    const hashBytes = new Uint8Array(hashBuffer);
    const checksumBytes = hashBytes.slice(0, 3);
    const b32 = encodeBase32(checksumBytes).slice(0, 4);
    return `@${username.toLowerCase()}.${network.toLowerCase()}.${b32}`;
  }
}

export class DCPCrypto {
  static deriveKeysFromSeed(seed) {
    if (!self.nacl) {
      throw new Error("nacl.js is not loaded! Cannot derive keys.");
    }
    const edKeyPair = self.nacl.sign.keyPair.fromSeed(seed.slice(0, 32));
    const xKeyPair = self.nacl.box.keyPair.fromSecretKey(seed.slice(32, 64));
    return {
      identityKey: {
        publicKey: toHex(edKeyPair.publicKey),
        privateKey: toHex(edKeyPair.secretKey)
      },
      encryptionKey: {
        publicKey: toHex(xKeyPair.publicKey),
        privateKey: toHex(xKeyPair.secretKey)
      }
    };
  }

  static sign(headerBytes, privateKeyHex) {
    return self.nacl.sign.detached(headerBytes, fromHex(privateKeyHex));
  }

  static verify(headerBytes, signatureBytes, publicKeyHex) {
    return self.nacl.sign.detached.verify(headerBytes, signatureBytes, fromHex(publicKeyHex));
  }

  static deriveX25519SharedSecret(ourPrivateHex, theirPublicHex) {
    return self.nacl.scalarMult(fromHex(ourPrivateHex), fromHex(theirPublicHex));
  }

  static async hkdf(sharedSecret, salt, info) {
    const saltKey = await crypto.subtle.importKey(
      "raw",
      salt || new Uint8Array(32),
      "HKDF",
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt || new Uint8Array(32),
        info: info || new Uint8Array(0)
      },
      saltKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async encryptAES(plaintext, cryptoKey) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      plaintext
    );
    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encrypted), iv.length);
    return result;
  }

  static async decryptAES(ciphertextWithIv, cryptoKey) {
    const iv = ciphertextWithIv.slice(0, 12);
    const ciphertext = ciphertextWithIv.slice(12);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      ciphertext
    );
    return new Uint8Array(decrypted);
  }
}

export class DoubleRatchetSession {
  constructor(ourDHKey, theirDHPubHex) {
    this.ourDHKey = ourDHKey;
    this.theirDHPubHex = theirDHPubHex;
    this.rootKey = null;
    this.sendingChainKey = null;
    this.receivingChainKey = null;
    this.sequenceNumberSend = 0;
    this.sequenceNumberRecv = 0;
    this.skippedMessageKeys = {};
  }

  static async init(ourDHKey, theirDHPubHex, isInitiator) {
    const session = new DoubleRatchetSession(ourDHKey, theirDHPubHex);
    const sharedSecret = DCPCrypto.deriveX25519SharedSecret(ourDHKey.privateKey, theirDHPubHex);
    const info = new TextEncoder().encode("DCP_DOUBLE_RATCHET_KDF_INIT");
    const saltKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
    const derivedBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: info },
      saltKey,
      512
    );
    const derived = new Uint8Array(derivedBits);
    session.rootKey = await crypto.subtle.importKey("raw", derived.slice(0, 32), "HKDF", false, ["deriveBits", "deriveKey"]);
    
    if (isInitiator) {
      session.sendingChainKey = derived.slice(32, 64);
      session.receivingChainKey = null;
    } else {
      session.sendingChainKey = null;
      session.receivingChainKey = derived.slice(32, 64);
    }
    return session;
  }

  async _stepChain(chainKeyBytes) {
    const importedChain = await crypto.subtle.importKey("raw", chainKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const nextChainBits = await crypto.subtle.sign("HMAC", importedChain, new Uint8Array([0x01]));
    const msgKeyBits = await crypto.subtle.sign("HMAC", importedChain, new Uint8Array([0x02]));
    const msgKey = await crypto.subtle.importKey("raw", new Uint8Array(msgKeyBits), "AES-GCM", false, ["encrypt", "decrypt"]);
    return {
      nextChainKey: new Uint8Array(nextChainBits),
      messageKey: msgKey
    };
  }

  async encrypt(plaintext) {
    if (!this.sendingChainKey) {
      throw new Error("No sending chain established yet");
    }
    const { nextChainKey, messageKey } = await this._stepChain(this.sendingChainKey);
    this.sendingChainKey = nextChainKey;
    const ciphertext = await DCPCrypto.encryptAES(plaintext, messageKey);
    return {
      ciphertext: ciphertext,
      sequence: this.sequenceNumberSend++,
      dhPub: this.ourDHKey.publicKey
    };
  }

  async decrypt(ciphertext, dhPubHex, sequence) {
    if (dhPubHex !== this.theirDHPubHex) {
      this.theirDHPubHex = dhPubHex;
      this.sequenceNumberRecv = 0;
      
      const entropy = new Uint8Array(32);
      window.crypto.getRandomValues(entropy);
      const newKeyPair = self.nacl.box.keyPair.fromSeed(entropy);
      this.ourDHKey = {
        publicKey: toHex(newKeyPair.publicKey),
        privateKey: toHex(newKeyPair.secretKey)
      };
      
      const sharedSecret = DCPCrypto.deriveX25519SharedSecret(this.ourDHKey.privateKey, dhPubHex);
      const saltKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
      const derivedBits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("DCP_DOUBLE_RATCHET_DH_RATCHET") },
        saltKey,
        512
      );
      const derived = new Uint8Array(derivedBits);
      this.receivingChainKey = derived.slice(32, 64);
      this.rootKey = await crypto.subtle.importKey("raw", derived.slice(0, 32), "HKDF", false, ["deriveBits", "deriveKey"]);
      
      const nextSendSecret = DCPCrypto.deriveX25519SharedSecret(this.ourDHKey.privateKey, dhPubHex);
      const sendSaltKey = await crypto.subtle.importKey("raw", nextSendSecret, "HKDF", false, ["deriveBits"]);
      const sendBits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: derived.slice(0, 32), info: new TextEncoder().encode("DCP_DOUBLE_RATCHET_SEND_RATCHET") },
        sendSaltKey,
        256
      );
      this.sendingChainKey = new Uint8Array(sendBits);
    }
    
    if (!this.receivingChainKey) {
      throw new Error("No receiving chain established yet");
    }
    
    let currentChain = this.receivingChainKey;
    let targetKey = null;
    while (this.sequenceNumberRecv <= sequence) {
      const { nextChainKey, messageKey } = await this._stepChain(currentChain);
      currentChain = nextChainKey;
      if (this.sequenceNumberRecv === sequence) {
        targetKey = messageKey;
      }
      this.sequenceNumberRecv++;
    }
    this.receivingChainKey = currentChain;
    
    if (!targetKey) {
      throw new Error("Failed to derive appropriate decryption key");
    }
    return await DCPCrypto.decryptAES(ciphertext, targetKey);
  }
}

export class DCPPacket {
  static async pack(params) {
    const {
      protocolVersion = 1,
      headerVersion = 1,
      flags = 0,
      cipherSuiteId = 2,
      packetType = 1,
      ttl = 10,
      timestamp = Date.now(),
      packetIdBytes = new Uint8Array(32),
      payloadBytes,
      senderPrivateKeyHex
    } = params;

    const payloadLength = payloadBytes.byteLength;
    const headerBuffer = new ArrayBuffer(118);
    const view = new DataView(headerBuffer);
    const bytes = new Uint8Array(headerBuffer);

    bytes[0] = 0x44; // D
    bytes[1] = 0x43; // C
    bytes[2] = 0x50; // P
    bytes[3] = 0x01; // Version suffix

    view.setUint8(4, protocolVersion);
    view.setUint8(5, headerVersion);
    view.setUint8(6, flags);
    view.setUint8(7, cipherSuiteId);
    view.setUint8(8, packetType);
    view.setUint8(9, ttl);
    
    const high = Math.floor(timestamp / 0x100000000);
    const low = timestamp % 0x100000000;
    view.setUint32(10, high);
    view.setUint32(14, low);

    let idBytes = packetIdBytes;
    if (idBytes.byteLength === 0 || toHex(idBytes) === toHex(new Uint8Array(32))) {
      const hashBuf = await crypto.subtle.digest("SHA-256", payloadBytes);
      idBytes = new Uint8Array(hashBuf);
    }
    bytes.set(idBytes, 18);
    view.setUint32(50, payloadLength);

    const signableBytes = bytes.slice(0, 54);
    let signature = new Uint8Array(64);
    if (senderPrivateKeyHex) {
      signature = DCPCrypto.sign(signableBytes, senderPrivateKeyHex);
    }
    bytes.set(signature, 54);

    const envelope = new Uint8Array(118 + payloadLength);
    envelope.set(bytes, 0);
    envelope.set(payloadBytes, 118);
    return envelope;
  }

  static unpack(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    if (bytes.length < 118) {
      throw new Error("Packet is too short to parse header");
    }
    const view = new DataView(arrayBuffer);
    if (bytes[0] !== 0x44 || bytes[1] !== 0x43 || bytes[2] !== 0x50 || bytes[3] !== 0x01) {
      throw new Error("Invalid Magic Bytes: Not a DCP Packet");
    }
    const protocolVersion = view.getUint8(4);
    const headerVersion = view.getUint8(5);
    const flags = view.getUint8(6);
    const cipherSuiteId = view.getUint8(7);
    const packetType = view.getUint8(8);
    const ttl = view.getUint8(9);

    const high = view.getUint32(10);
    const low = view.getUint32(14);
    const timestamp = high * 0x100000000 + low;

    const packetId = bytes.slice(18, 50);
    const payloadLength = view.getUint32(50);
    const signature = bytes.slice(54, 118);
    const payloadBytes = bytes.slice(118, 118 + payloadLength);

    return {
      header: {
        magic: "DCP\x01",
        protocolVersion,
        headerVersion,
        flags,
        cipherSuiteId,
        packetType,
        ttl,
        timestamp,
        packetId: toHex(packetId),
        payloadLength,
        signature: toHex(signature),
        rawHeader: bytes.slice(0, 54)
      },
      payload: payloadBytes
    };
  }
}

export class DCPMailbox {
  /**
   * Build a secure, replay-protected Delivery ACK (RFC-0004 v2)
   */
  static buildACK(packetId, recipientDeviceIdHex, relaySessionId, privateKeyHex) {
    const ackPayload = {
      packet_id: packetId,
      recipient_device_id: recipientDeviceIdHex,
      timestamp: Date.now(),
      relay_session_id: relaySessionId
    };
    const encoder = new TextEncoder();
    const ackBytes = encoder.encode(JSON.stringify(ackPayload));
    
    // Sign with Device Identity Key
    const sig = DCPCrypto.sign(ackBytes, privateKeyHex);
    return {
      payload: ackPayload,
      signature: toHex(sig)
    };
  }
}

export class DCPDHT {
  /**
   * Calculate rotating blinded DHT query key (RFC-0010)
   */
  static async deriveBlindedLookupKey(sharedSecretHex, offsetHours = 0) {
    const epochHour = Math.floor(Date.now() / (3600 * 1000)) + offsetHours;
    const info = new TextEncoder().encode("DCP_DHT_ROTATING_KEY_" + epochHour);
    const secretBytes = fromHex(sharedSecretHex);
    const saltKey = await crypto.subtle.importKey("raw", secretBytes, "HKDF", false, ["deriveBits"]);
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32),
        info: info
      },
      saltKey,
      256
    );
    return toHex(new Uint8Array(derivedBits));
  }
}

export class DCPReputation {
  /**
   * Compute relay score based on observer profile (RFC-0011)
   */
  static calculateScore(metrics, profile = "balanced") {
    const { latency = 100, uptime = 1.0, deliveryRate = 1.0, mailboxSuccess = 1.0, health = 1.0 } = metrics;
    
    // Latency factor: 100 max, decrements 1 pt per 10ms
    const latencyFactor = Math.max(0, 100 - (latency / 10));
    const uptimePct = uptime * 100;
    const deliveryPct = deliveryRate * 100;
    const mailboxPct = mailboxSuccess * 100;
    const healthPct = health * 100;

    let weights = { latency: 0.20, uptime: 0.30, delivery: 0.20, mailbox: 0.10, health: 0.20 }; // Balanced
    
    if (profile === "latency") {
      weights = { latency: 0.50, uptime: 0.15, delivery: 0.10, mailbox: 0.10, health: 0.15 };
    } else if (profile === "reliability") {
      weights = { latency: 0.10, uptime: 0.40, delivery: 0.20, mailbox: 0.15, health: 0.15 };
    } else if (profile === "privacy") {
      weights = { latency: 0.10, uptime: 0.20, delivery: 0.10, mailbox: 0.10, health: 0.50 };
    }

    return Math.round(
      (latencyFactor * weights.latency) +
      (uptimePct * weights.uptime) +
      (deliveryPct * weights.delivery) +
      (mailboxPct * weights.mailbox) +
      (healthPct * weights.health)
    );
  }

  /**
   * Apply recently used penalty to enforce Route Diversity (load balancing)
   * recentlyUsedRelays: array of relay keys used in the last 5 minutes.
   */
  static applyRouteDiversity(relaysList, recentlyUsedKeys) {
    return relaysList.map(relay => {
      let finalScore = relay.score;
      if (recentlyUsedKeys.includes(relay.pubKey)) {
        finalScore = Math.max(0, relay.score - 15); // 15-point penalty
      }
      return { ...relay, activeScore: finalScore };
    });
  }
}

export class DCPTransport {
  static async wrapOnion(payloadBytes, relayPathKeys, finalRecipientId) {
    let currentPayload = payloadBytes;
    for (let i = relayPathKeys.length - 1; i >= 0; i--) {
      const relayKey = relayPathKeys[i];
      const nextHop = i === relayPathKeys.length - 1 ? finalRecipientId : relayPathKeys[i + 1];
      const entropy = new Uint8Array(32);
      window.crypto.getRandomValues(entropy);
      const epKeyPair = self.nacl.box.keyPair.fromSeed(entropy);
      const sharedSecret = DCPCrypto.deriveX25519SharedSecret(toHex(epKeyPair.secretKey), relayKey);
      const info = new TextEncoder().encode("DCP_ONION_ROUTING_HOP");
      const aesKey = await DCPCrypto.hkdf(sharedSecret, null, info);
      const nextHopBytes = new TextEncoder().encode(nextHop);
      const hopHeader = new Uint8Array(2);
      new DataView(hopHeader.buffer).setUint16(0, nextHopBytes.length);
      const unencryptedHop = new Uint8Array(hopHeader.length + nextHopBytes.length + currentPayload.length);
      unencryptedHop.set(hopHeader, 0);
      unencryptedHop.set(nextHopBytes, hopHeader.length);
      unencryptedHop.set(currentPayload, hopHeader.length + nextHopBytes.length);
      const encryptedHop = await DCPCrypto.encryptAES(unencryptedHop, aesKey);
      const layerBytes = new Uint8Array(32 + encryptedHop.length);
      layerBytes.set(epKeyPair.publicKey, 0);
      layerBytes.set(encryptedHop, 32);
      currentPayload = layerBytes;
    }
    return currentPayload;
  }

  static async solvePoW(saltHex, difficulty) {
    const encoder = new TextEncoder();
    const saltBytes = fromHex(saltHex);
    let nonce = 0;
    while (true) {
      const nonceStr = nonce.toString();
      const nonceBytes = encoder.encode(nonceStr);
      const hashable = new Uint8Array(saltBytes.length + nonceBytes.length);
      hashable.set(saltBytes, 0);
      hashable.set(nonceBytes, saltBytes.length);
      const hashBuffer = await crypto.subtle.digest("SHA-256", hashable);
      const hashBytes = new Uint8Array(hashBuffer);
      
      let leadingZeros = 0;
      for (let i = 0; i < hashBytes.length; i++) {
        const byte = hashBytes[i];
        if (byte === 0) {
          leadingZeros += 8;
        } else {
          leadingZeros += Math.clz32(byte) - 24;
          break;
        }
      }
      if (leadingZeros >= difficulty) {
        return nonce;
      }
      nonce++;
    }
  }

  static buildHandshake(devicePubKeyHex, featuresMask = 0x003F, cryptoMask = 0x0001) {
    const devPub = fromHex(devicePubKeyHex);
    const buffer = new ArrayBuffer(6 + devPub.length);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    view.setUint8(0, 1);
    view.setUint8(1, 1);
    view.setUint16(2, cryptoMask);
    view.setUint16(4, featuresMask);
    bytes.set(devPub, 6);
    return bytes;
  }

  static parseHandshake(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const clientProto = view.getUint8(0);
    const minProto = view.getUint8(1);
    const cryptoMask = view.getUint16(2);
    const featureMask = view.getUint16(4);
    const devicePubKey = toHex(bytes.slice(6));
    return { clientProto, minProto, cryptoMask, featureMask, devicePubKey };
  }
}

export class DCPDevice {
  /**
   * Create a signed Device Card (RFC-0006)
   */
  static createDeviceCard(devicePubKeyHex, deviceEncPubKeyHex, masterIdentityPrivateKeyHex, trustLevel = "desktop") {
    const cardData = {
      device_id: devicePubKeyHex,
      device_enc: deviceEncPubKeyHex,
      trust_level: trustLevel,
      timestamp: Date.now()
    };
    const encoder = new TextEncoder();
    const cardBytes = encoder.encode(JSON.stringify(cardData));
    const sig = DCPCrypto.sign(cardBytes, masterIdentityPrivateKeyHex);
    
    return {
      ...cardData,
      signature: toHex(sig)
    };
  }

  /**
   * Verify a Device Card signature using the master identity key
   */
  static verifyDeviceCard(card, masterIdentityPublicKeyHex) {
    const cardData = {
      device_id: card.device_id,
      device_enc: card.device_enc,
      trust_level: card.trust_level,
      timestamp: card.timestamp
    };
    const encoder = new TextEncoder();
    const cardBytes = encoder.encode(JSON.stringify(cardData));
    const sigBytes = fromHex(card.signature);
    return DCPCrypto.verify(cardBytes, sigBytes, masterIdentityPublicKeyHex);
  }
}

export class DCPSync {
  /**
   * Pack and encrypt sync state data (RFC-0006)
   */
  static async encryptSyncState(syncClass, dataObj, sharedX25519SecretHex) {
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(JSON.stringify({
      sync_class: syncClass,
      data: dataObj,
      timestamp: Date.now()
    }));
    
    const info = encoder.encode("DCP_DEVICE_SYNC_" + syncClass.toUpperCase());
    const aesKey = await DCPCrypto.hkdf(fromHex(sharedX25519SecretHex), null, info);
    const ciphertext = await DCPCrypto.encryptAES(plaintext, aesKey);
    return toHex(ciphertext);
  }

  /**
   * Decrypt and unpack sync state data (RFC-0006)
   */
  static async decryptSyncState(syncClass, encryptedHex, sharedX25519SecretHex) {
    const ciphertext = fromHex(encryptedHex);
    const info = new TextEncoder().encode("DCP_DEVICE_SYNC_" + syncClass.toUpperCase());
    const aesKey = await DCPCrypto.hkdf(fromHex(sharedX25519SecretHex), null, info);
    const plaintextBytes = await DCPCrypto.decryptAES(ciphertext, aesKey);
    return JSON.parse(new TextDecoder().decode(plaintextBytes));
  }
}

export class DCPFile {
  /**
   * Split binary file bytes into 256KB chunks (RFC-0007)
   */
  static chunkFile(fileBytes, chunkSize = 262144) {
    const chunks = [];
    let offset = 0;
    while (offset < fileBytes.length) {
      const slice = fileBytes.slice(offset, offset + chunkSize);
      chunks.push(slice);
      offset += chunkSize;
    }
    return chunks;
  }

  /**
   * Encrypt file chunk using AES-GCM with deterministic IV derived from Key and Index
   */
  static async encryptChunk(chunkBytes, keyHex, chunkIndex) {
    const keyBytes = fromHex(keyHex);
    // Derive IV: HKDF(keyBytes || chunkIndex)
    const info = new TextEncoder().encode("DCP_FILE_CHUNK_IV_" + chunkIndex);
    const saltKey = await crypto.subtle.importKey("raw", keyBytes, "HKDF", false, ["deriveBits"]);
    const iv = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: info },
      saltKey,
      96 // 12 bytes IV
    );
    
    // Import encryption key
    const aesKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      aesKey,
      chunkBytes
    );
    return new Uint8Array(encrypted);
  }

  /**
   * Decrypt file chunk using AES-GCM
   */
  static async decryptChunk(encryptedBytes, keyHex, chunkIndex) {
    const keyBytes = fromHex(keyHex);
    const info = new TextEncoder().encode("DCP_FILE_CHUNK_IV_" + chunkIndex);
    const saltKey = await crypto.subtle.importKey("raw", keyBytes, "HKDF", false, ["deriveBits"]);
    const iv = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: info },
      saltKey,
      96
    );
    
    const aesKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      aesKey,
      encryptedBytes
    );
    return new Uint8Array(decrypted);
  }

  /**
   * Verify ciphertext chunk hash matches index hash
   */
  static async verifyChunk(chunkCiphertextBytes, expectedHashHex) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", chunkCiphertextBytes);
    const hashHex = toHex(new Uint8Array(hashBuffer));
    return hashHex === expectedHashHex;
  }
}

export class DCPGroup {
  /**
   * Step the Sender Chain Key using HMAC-SHA256 to derive next chain key and message key
   */
  static async deriveGroupMessageKey(chainKeyBytes) {
    const importedChain = await crypto.subtle.importKey("raw", chainKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const nextChainBits = await crypto.subtle.sign("HMAC", importedChain, new Uint8Array([0x01]));
    const msgKeyBits = await crypto.subtle.sign("HMAC", importedChain, new Uint8Array([0x02]));
    
    return {
      nextChainKey: new Uint8Array(nextChainBits),
      messageKey: new Uint8Array(msgKeyBits)
    };
  }

  /**
   * Encrypt a group message using the current Sender Chain Key and sign with Ed25519
   */
  static async encryptGroupMessage(plaintextBytes, chainKeyHex, signaturePrivateKeyHex) {
    const { nextChainKey, messageKey } = await this.deriveGroupMessageKey(fromHex(chainKeyHex));
    
    // Import AES Key
    const aesKey = await crypto.subtle.importKey("raw", messageKey, "AES-GCM", false, ["encrypt"]);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      plaintextBytes
    );
    
    const ciphertext = new Uint8Array(iv.length + encrypted.byteLength);
    ciphertext.set(iv, 0);
    ciphertext.set(new Uint8Array(encrypted), iv.length);
    
    // Sign the ciphertext using Ed25519
    const sig = DCPCrypto.sign(ciphertext, signaturePrivateKeyHex);
    
    return {
      ciphertext: toHex(ciphertext),
      signature: toHex(sig),
      nextChainKeyHex: toHex(nextChainKey)
    };
  }

  /**
   * Decrypt and verify a group message
   */
  static async decryptGroupMessage(ciphertextHex, signatureHex, chainKeyHex, signaturePublicKeyHex) {
    const ciphertext = fromHex(ciphertextHex);
    const sig = fromHex(signatureHex);
    
    // Verify signature first
    const isSigValid = DCPCrypto.verify(ciphertext, sig, signaturePublicKeyHex);
    if (!isSigValid) {
      throw new Error("Ed25519 Group Message signature verification failed");
    }
    
    const { nextChainKey, messageKey } = await this.deriveGroupMessageKey(fromHex(chainKeyHex));
    const aesKey = await crypto.subtle.importKey("raw", messageKey, "AES-GCM", false, ["decrypt"]);
    
    const iv = ciphertext.slice(0, 12);
    const encData = ciphertext.slice(12);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      encData
    );
    
    return {
      plaintextBytes: new Uint8Array(decrypted),
      nextChainKeyHex: toHex(nextChainKey)
    };
  }
}



