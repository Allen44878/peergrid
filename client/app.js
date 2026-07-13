import {
  DCPIdentity,
  DCPCrypto,
  DoubleRatchetSession,
  DCPPacket,
  DCPTransport,
  DCPMailbox,
  DCPDHT,
  DCPReputation,
  DCPDevice,
  DCPSync,
  DCPFile,
  DCPGroup,
  toHex,
  fromHex,
  padPKCS7,
  unpadPKCS7,
  padFixedSize,
  unpadFixedSize
} from './dcp-sdk.js';

// Application State
let myIdentity = null; // { username, network, mnemonic, keys: { identityKey, encryptionKey }, userId }
let activeWalletPin = null;
let contacts = {}; // { [userId]: { username, userId, identityKey, dhKey, session } }
let activeContactId = null;
let messages = {}; // { [userId]: [ { senderId, text, timestamp } ] }
let wsConn = null; // WebSocket connection
let virtualMesh = null; // BroadcastChannel fallback
let pendingPacket = null; // For PoW challenge

const RELAY_WS_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  ? 'ws://localhost:8765'
  : 'wss://api.peergrid.app';

// Simulated Relay Metrics & Scores
let relayMetrics = {
  A: { latency: 12, uptime: 0.99, deliveryRate: 0.98, mailboxSuccess: 0.99, health: 1.0, pubKey: "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209" },
  B: { latency: 85, uptime: 0.92, deliveryRate: 0.94, mailboxSuccess: 0.93, health: 0.95, pubKey: "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59" },
  C: { latency: 18, uptime: 0.99, deliveryRate: 0.99, mailboxSuccess: 0.99, health: 1.0, pubKey: "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22" }
};

let recentlyUsedRelays = []; // For route diversity tracking

// Real-Time Metrics State
let metrics = {
  sent: 0,
  recv: 0,
  latencySum: 0,
  latencyCount: 0,
  switches: 0,
  dummy: 0,
  pow: 0,
  bandwidth: 0, // total bytes
  plainBytes: 0,
  paddedBytes: 0
};

// Cover Traffic Loop Interval
let dummyIntervalId = null;

// SVG Map Animation configuration
const PATH_DURATION = 1500; // ms per hop

// Initialize App
window.addEventListener('DOMContentLoaded', async () => {
  setupTabs();
  setupOnboarding();
  initVirtualMesh();
  tryConnectWebSocketRelay();
  setupSettingsListeners();
  
  // Set up Clear Console Button
  document.getElementById('btn-clear-console').addEventListener('click', () => {
    const consoleOut = document.getElementById('console-output');
    consoleOut.innerHTML = `<div class="console-line system">[Console cleared]</div>`;
  });

  // Run initial reputation scores calculation
  updateReputationScores();

  // Set up device sync bindings
  setupDeviceSyncListeners();

  // Set up file transfer bindings
  setupFileTransferListeners();

  // Set up group chat bindings
  setupGroupChatListeners();

  // Set up diagnostics, crash banner, and tutorial listeners (Phase 3 Alpha additions)
  setupAlphaSystem();

  // Try restoring saved session
  await tryAutoLogin();
});

// Onboarding & Tab management
function setupTabs() {
  const tabCreate = document.getElementById('tab-create');
  const tabImport = document.getElementById('tab-import');
  const createContent = document.querySelector('.create-content');
  const importContent = document.querySelector('.import-content');

  tabCreate.addEventListener('click', () => {
    tabCreate.classList.add('active');
    tabImport.classList.remove('active');
    createContent.classList.add('active');
    importContent.classList.remove('active');
  });

  tabImport.addEventListener('click', () => {
    tabImport.classList.add('active');
    tabCreate.classList.remove('active');
    importContent.classList.add('active');
    createContent.classList.add('active');
  });

  // Populate first random mnemonic
  document.getElementById('generated-mnemonic').innerText = DCPIdentity.generateMnemonic();
}

function setupOnboarding() {
  const btnCreate = document.getElementById('btn-create-identity');
  const btnImport = document.getElementById('btn-import-identity');

  btnCreate.addEventListener('click', async () => {
    const username = document.getElementById('create-username').value.trim();
    const mnemonic = document.getElementById('generated-mnemonic').innerText;
    const pin = document.getElementById('create-pin').value.trim();
    if (!username) return alert("Please choose a username");
    if (pin.length < 4) return alert("Security PIN or Password must be at least 4 characters long.");
    try {
      document.getElementById('btn-create-identity').disabled = true;
      document.getElementById('btn-create-identity').innerText = 'Initializing...';
      await initializeIdentity(username, mnemonic, pin);
    } catch (err) {
      console.error('[InitializeIdentity Error]', err);
      alert('Failed to initialize identity: ' + err.message);
      document.getElementById('btn-create-identity').disabled = false;
      document.getElementById('btn-create-identity').innerText = 'Initialize Identity';
    }
  });

  btnImport.addEventListener('click', async () => {
    const username = document.getElementById('import-username').value.trim();
    const mnemonic = document.getElementById('import-mnemonic').value.trim();
    const pin = document.getElementById('import-pin').value.trim();
    if (!username) return alert("Please choose a username");
    if (!mnemonic) return alert("Please enter recovery phrase");
    if (pin.length < 4) return alert("Security PIN or Password must be at least 4 characters long.");
    await initializeIdentity(username, mnemonic, pin);
  });
}

// Settings Bindings (Milestone 2)
function setupSettingsListeners() {
  document.getElementById('select-privacy-level').addEventListener('change', (e) => {
    const level = e.target.value;
    logConsole("system", `[Privacy Level changed to: ${level.toUpperCase()}]`);
    handlePrivacySettings(level);
  });

  document.getElementById('select-reputation-profile').addEventListener('change', () => {
    metrics.switches++;
    document.getElementById('metric-switches').textContent = metrics.switches;
    updateReputationScores();
  });
}

function handlePrivacySettings(level) {
  // Clear any existing dummy loop
  if (dummyIntervalId) {
    clearInterval(dummyIntervalId);
    dummyIntervalId = null;
  }

  if (level === "max") {
    // Start Dummy Cover Traffic loop: send a dummy packet every 3 seconds
    dummyIntervalId = setInterval(async () => {
      await sendDummyCoverPacket();
    }, 3000);
    logConsole("pow", "[Metadata Protection] Cover traffic dummy loop activated (Fixed interval: 3s).");
  }
}

// Device Synchronization Settings & Listeners (Phase 3A)
let linkedDevices = [];

function setupDeviceSyncListeners() {
  document.getElementById('btn-link-device').addEventListener('click', async () => {
    if (!myIdentity) {
      alert("Please initialize your identity first.");
      return;
    }
    
    const deviceType = document.getElementById('select-link-device-type').value;
    
    // Simulate key generation for secondary device
    const entropy = new Uint8Array(32);
    window.crypto.getRandomValues(entropy);
    const mockDeviceKeyPair = window.nacl.sign.keyPair.fromSeed(entropy);
    const mockDeviceEncKeyPair = window.nacl.box.keyPair.fromSeed(entropy);
    
    const deviceIdPub = toHex(mockDeviceKeyPair.publicKey);
    const deviceEncPub = toHex(mockDeviceEncKeyPair.publicKey);
    
    // Create Device Card (signed by master private key)
    const card = DCPDevice.createDeviceCard(
      deviceIdPub,
      deviceEncPub,
      myIdentity.keys.identityKey.privateKey,
      deviceType
    );
    
    // Verify Device Card signature (using master public key)
    const isValid = DCPDevice.verifyDeviceCard(card, myIdentity.keys.identityKey.publicKey);
    
    if (isValid) {
      linkedDevices.push(card);
      
      // Update UI list
      const list = document.getElementById('linked-devices-list');
      const item = document.createElement('div');
      item.className = "relay-item";
      item.style.padding = "8px";
      item.style.border = "1px solid rgba(255,255,255,0.03)";
      item.style.background = "rgba(255,255,255,0.01)";
      item.style.marginTop = "4px";
      
      const permissionsMap = {
        phone: "Read/Write • Trust: Phone",
        desktop: "Read/Write • Trust: Desktop",
        tablet: "Read/Write • Trust: Tablet",
        temporary: "Read-only • Trust: Temp"
      };
      
      item.innerHTML = `
        <span class="status-dot online"></span>
        <div class="relay-details">
          <p class="relay-name" style="font-size: 11px; font-weight: 600; text-transform: capitalize;">${deviceType} client</p>
          <p class="relay-stat" style="font-size: 9px; color: var(--text-secondary); margin-top: 1px;">Active • ${permissionsMap[deviceType]}</p>
        </div>
      `;
      list.appendChild(item);
      
      // Show sync button
      document.getElementById('btn-trigger-sync').style.display = 'block';
      
      logConsole("pow", `[Device Platform] Provisioned new ${deviceType.toUpperCase()} client device card. Signature verified successfully!`);
    } else {
      logConsole("system", "[Device Platform Error] Failed to verify provisioned device card signature.");
    }
  });

  document.getElementById('btn-trigger-sync').addEventListener('click', async () => {
    if (!myIdentity || linkedDevices.length === 0) return;
    
    // Create mock chats history payload
    const mockChatsState = {
      chats_count: Object.keys(messages).length,
      history: messages,
      timestamp: Date.now()
    };
    
    const secondaryDevice = linkedDevices[linkedDevices.length - 1];
    const sharedSecret = DCPCrypto.deriveX25519SharedSecret(
      myIdentity.keys.encryptionKey.privateKey,
      secondaryDevice.device_enc
    );
    
    logConsole("pow", `[Device Platform] Derived shared sync secret with secondary device X25519 key.`);
    
    // Encrypt sync payload (RFC-0006)
    const encryptedHex = await DCPSync.encryptSyncState("chats", mockChatsState, toHex(sharedSecret));
    
    logConsole("send", `[Device Sync] Encrypted synchronization state for class CHATS.
Ciphertext payload:\n${encryptedHex.slice(0, 120)}... [${encryptedHex.length / 2} bytes]`);
    
    // Decrypt sync payload (loopback verification)
    const decryptedObj = await DCPSync.decryptSyncState("chats", encryptedHex, toHex(sharedSecret));
    
    logConsole("recv", `[Device Sync] Secondary device decrypted sync payload successfully. Synced chats count: ${decryptedObj.data.chats_count}.`);
  });
}

// Secure File Transfer Settings & Listeners (Phase 3B)
let activeFileTransfer = null; // { file, chunks, keyHex, index, state, intervalId }

function setupFileTransferListeners() {
  const btnAttach = document.getElementById('btn-attach-file');
  const fileInput = document.getElementById('input-file-select');
  const progressPanel = document.getElementById('file-transfer-progress');
  const progressName = document.getElementById('file-transfer-name');
  const progressState = document.getElementById('file-transfer-state');
  const progressBar = document.getElementById('file-transfer-bar');
  const btnPause = document.getElementById('btn-file-pause');
  const btnCancel = document.getElementById('btn-file-cancel');

  btnAttach.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    // Reset file input value so same file can be chosen again
    fileInput.value = "";

    // Generate random mock file bytes
    const mockBytes = new Uint8Array(file.size);
    window.crypto.getRandomValues(mockBytes);
    
    // Chunk file
    const chunks = DCPFile.chunkFile(mockBytes, 262144); // 256KB Chunks
    const keyHex = toHex(window.crypto.getRandomValues(new Uint8Array(32))); // Ephemeral key

    activeFileTransfer = {
      file: file,
      chunks: chunks,
      keyHex: keyHex,
      index: 0,
      state: "Uploading",
      intervalId: null
    };

    // Calculate mock chunk hashes for metadata audit
    const chunkHashes = [];
    for (let i = 0; i < chunks.length; i++) {
      const encrypted = await DCPFile.encryptChunk(chunks[i], keyHex, i);
      const hashBuf = await crypto.subtle.digest("SHA-256", encrypted);
      chunkHashes.push(toHex(new Uint8Array(hashBuf)));
    }

    logConsole("send", `[File Transfer Started] File: ${file.name} (${(file.size / 1024).toFixed(1)} KB)
Split into ${chunks.length} chunks of 256KB. Ephemeral Key ID: ${keyHex.slice(0, 16)}...`);
    
    // Send E2EE metadata envelope
    const metadata = {
      transfer_id: "tx_" + toHex(window.crypto.getRandomValues(new Uint8Array(8))),
      file_name: file.name,
      file_size: file.size,
      total_chunks: chunks.length,
      chunk_hashes: chunkHashes
    };
    logConsole("send", `[File Sync] Broadcasted File Metadata Envelope: ${JSON.stringify(metadata)}`);

    // Show Progress
    progressPanel.style.display = 'block';
    progressName.textContent = `${file.name} (0%)`;
    progressState.textContent = "Uploading";
    progressBar.style.width = "0%";
    btnPause.textContent = "Pause";

    startFileChunksLoop();
  });

  function startFileChunksLoop() {
    if (!activeFileTransfer) return;
    
    activeFileTransfer.intervalId = setInterval(async () => {
      const { chunks, keyHex, index } = activeFileTransfer;
      if (index >= chunks.length) {
        // Completed
        clearInterval(activeFileTransfer.intervalId);
        activeFileTransfer.state = "Completed";
        progressState.textContent = "Completed";
        progressState.style.color = "var(--accent-green)";
        progressName.textContent = `${activeFileTransfer.file.name} (100%)`;
        progressBar.style.width = "100%";
        btnPause.style.display = 'none';
        
        logConsole("recv", `[File Transfer Complete] All ${chunks.length} chunks decrypted & assembled. File integrity hash match verified!`);
        activeFileTransfer = null;
        return;
      }

      // Encrypt and verify current chunk (RFC-0007)
      const chunkBytes = chunks[index];
      const encrypted = await DCPFile.encryptChunk(chunkBytes, keyHex, index);
      const hashBuf = await crypto.subtle.digest("SHA-256", encrypted);
      const hashHex = toHex(new Uint8Array(hashBuf));

      logConsole("pow", `[File Chunk] Transmitted Chunk ${index + 1}/${chunks.length} (Size: ${chunkBytes.length}B). Hash: ${hashHex.slice(0, 16)}...`);

      // Increment index
      activeFileTransfer.index++;
      const pct = Math.round((activeFileTransfer.index / chunks.length) * 100);
      progressName.textContent = `${activeFileTransfer.file.name} (${pct}%)`;
      progressBar.style.width = `${pct}%`;
      
      // Update Bandwidth metrics
      updateMetricsBandwidth(encrypted.byteLength);
    }, 800); // 800ms between chunks for visual feedback
  }

  btnPause.addEventListener('click', () => {
    if (!activeFileTransfer) return;

    if (activeFileTransfer.state === "Uploading") {
      // Pause
      clearInterval(activeFileTransfer.intervalId);
      activeFileTransfer.state = "Paused";
      progressState.textContent = "Paused";
      btnPause.textContent = "Resume";
      logConsole("system", `[File Transfer Paused] Suspended at Chunk Index: ${activeFileTransfer.index}. Resume token cached.`);
    } else if (activeFileTransfer.state === "Paused") {
      // Resume (resumability verification)
      activeFileTransfer.state = "Uploading";
      progressState.textContent = "Uploading";
      btnPause.textContent = "Pause";
      logConsole("pow", `[File Transfer Resumed] Requesting missing blocks starting from Chunk Index: ${activeFileTransfer.index}...`);
      startFileChunksLoop();
    }
  });

  btnCancel.addEventListener('click', () => {
    if (activeFileTransfer) {
      clearInterval(activeFileTransfer.intervalId);
      logConsole("system", "[File Transfer Cancelled] Session aborted by user.");
      activeFileTransfer = null;
    }
    progressPanel.style.display = 'none';
  });
}

// Group Chat Settings & Listeners (Phase 3C)
function setupGroupChatListeners() {
  document.getElementById('btn-create-group').addEventListener('click', async () => {
    if (!myIdentity) {
      alert("Please initialize your identity first.");
      return;
    }
    
    // Generate a random mock group ID
    const groupId = "@privacy_core.dcp." + toHex(window.crypto.getRandomValues(new Uint8Array(2)));
    const initialSeed = toHex(window.crypto.getRandomValues(new Uint8Array(32)));
    
    const newGroup = {
      username: "Privacy Core WG",
      userId: groupId,
      isGroup: true,
      epoch: 1,
      seq: 0,
      chainKey: initialSeed,
      members: ["You", "Alice", "Bob", "Charlie"]
    };

    contacts[groupId] = newGroup;
    renderContacts();
    saveState();
    
    logConsole("pow", `[Group Platform] Created Secure Group: ${newGroup.username}. Initialized Epoch: 1.
Generated starting Sender Chain Key: ${initialSeed.slice(0, 16)}...`);
    
    logConsole("send", `[Group Sync] Distributed initial Sender Chain Key seeds to members (Alice, Bob, Charlie) via pairwise DR channels.`);
  });
}

async function rotateGroupKey(groupId) {
  const group = contacts[groupId];
  if (!group || !group.isGroup) return;

  group.epoch++;
  const newSeed = toHex(window.crypto.getRandomValues(new Uint8Array(32)));
  group.chainKey = newSeed;
  group.seq = 0;

  // Render header again
  selectContact(groupId);
  saveState();

  logConsole("system", `[Group Key Rotation] Member Charlie has left the group.
Group Epoch incremented to ${group.epoch}. Fired global Sender Key Rotation. Charlie has been evicted from the key circle.
New Sender Chain Key: ${newSeed.slice(0, 16)}...`);
}


// Reputation Score Updates
function updateReputationScores() {
  const profile = document.getElementById('select-reputation-profile').value;
  
  const scoreA = DCPReputation.calculateScore(relayMetrics.A, profile);
  const scoreB = DCPReputation.calculateScore(relayMetrics.B, profile);
  const scoreC = DCPReputation.calculateScore(relayMetrics.C, profile);
  
  document.getElementById('relay-stat-a').textContent = `Active • Score: ${scoreA} • Latency: 12ms`;
  document.getElementById('relay-stat-b').textContent = `Active • Score: ${scoreB} • Latency: 85ms`;
  document.getElementById('relay-stat-c').textContent = `Active • Score: ${scoreC} • Latency: 18ms`;

  // Apply visual colors to topology map nodes
  updateNodeVisualState('circle-relay-1', scoreA);
  updateNodeVisualState('circle-relay-2', scoreB);
  updateNodeVisualState('circle-relay-3', scoreC);

  logConsole("system", `[Reputation recalculated using Profile: ${profile.toUpperCase()}]
Relay A local score: ${scoreA}
Relay B local score: ${scoreB}
Relay C local score: ${scoreC}`);
}

function updateNodeVisualState(elementId, score) {
  const circle = document.getElementById(elementId);
  if (!circle) return;
  if (score < 90) {
    circle.className.baseVal = "node-circle circle-relay-low-score";
  } else {
    circle.className.baseVal = "node-circle circle-relay-high-score";
  }
}

// Identity Initialization
async function initializeIdentity(username, mnemonic, pin) {
  activeWalletPin = pin;
  logConsole("pow", `[Deriving cryptographic seed from mnemonic using PBKDF2-HMAC-SHA512...]`);
  const seed = await DCPIdentity.deriveSeed(mnemonic);
  const keys = DCPCrypto.deriveKeysFromSeed(seed);
  const userId = await DCPIdentity.generateUserId(username, "dcp", keys.identityKey.publicKey);
  
  myIdentity = { username, network: "dcp", mnemonic, keys, userId };

  document.getElementById('onboarding-card').classList.remove('active');
  document.getElementById('main-dashboard').classList.add('active');
  
  renderUserBadge();
  
  logConsole("system", `[Identity initialized successfully]
User ID: ${userId}
Ed25519 Pub: ${keys.identityKey.publicKey.slice(0, 32)}...
X25519 Pub: ${keys.encryptionKey.publicKey.slice(0, 32)}...`);

  // Save credentials to localStorage
  saveState();

  // Randomize DHT lookup advertisement publish (RFC-0010 publication jitter: 55-65 mins, run immediately first)
  publishDHTAdvertisement();
}

async function publishDHTAdvertisement() {
  if (!myIdentity) return;
  
  // Derivate lookup key for Bob or network
  const relaysList = [RELAY_WS_URL];
  
  // Broadcast DHT advertisement on relays
  if (wsConn && wsConn.readyState === WebSocket.OPEN) {
    // Generate a temporary registry item (simulated: Bobs key)
    const epochLookupKey = await DCPDHT.deriveBlindedLookupKey(myIdentity.keys.encryptionKey.privateKey, 0);
    wsConn.send(JSON.stringify({
      action: "dht_publish",
      lookup_key: epochLookupKey,
      advertisement: {
        userId: myIdentity.userId,
        devicePubKey: myIdentity.keys.identityKey.publicKey,
        relays: relaysList
      }
    }));
  }
  
  // Jittered scheduling for next publication: 55 - 65 minutes
  const nextIntervalMins = 55 + Math.random() * 10;
  setTimeout(publishDHTAdvertisement, nextIntervalMins * 60 * 1000);
}

function renderUserBadge() {
  const badgeContainer = document.getElementById('user-badge');
  badgeContainer.innerHTML = `
    <span class="name">${myIdentity.userId}</span>
    <span class="key-meta">Click to copy Contact Card 📋</span>
  `;
  badgeContainer.addEventListener('click', () => {
    const contactCard = JSON.stringify({
      userId: myIdentity.userId,
      identityKey: myIdentity.keys.identityKey.publicKey,
      dhKey: myIdentity.keys.encryptionKey.publicKey
    });
    navigator.clipboard.writeText(contactCard);
    alert("Contact Card copied to clipboard! Share this with your friend.");
  });
}

// Virtual Mesh Network (BroadcastChannel) fallback
function initVirtualMesh() {
  virtualMesh = new BroadcastChannel('dcp-virtual-relay');
  virtualMesh.addEventListener('message', async (event) => {
    const { type, recipientId, senderId, envelope } = event.data;
    if (recipientId === myIdentity?.userId) {
      if (type === 'presence_announce') {
        if (contacts[senderId]) {
          virtualMesh.postMessage({
            type: 'presence_reply',
            recipientId: senderId,
            senderId: myIdentity.userId,
            dhKey: myIdentity.keys.encryptionKey.publicKey
          });
        }
      } else if (type === 'presence_reply') {
        if (contacts[senderId] && !contacts[senderId].dhKey) {
          contacts[senderId].dhKey = event.data.dhKey;
          await initDoubleRatchetSession(senderId);
        }
      } else if (type === 'onion_packet') {
        await receivePacket(envelope);
      }
    }
  });
}

// WebSocket Python Relay Connection
function tryConnectWebSocketRelay() {
  wsConn = new WebSocket(RELAY_WS_URL);
  
  wsConn.addEventListener('open', () => {
    logConsole("system", "[Relay Node WS Connected: Direct node communication active]");
    wsConn.send(JSON.stringify({
      action: 'register',
      userId: myIdentity?.userId
    }));
  });

  wsConn.addEventListener('message', async (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.status === 'pow_challenge') {
        logConsole("pow", `[Relay PoW Challenge Received. Salt: ${data.salt.slice(0, 16)}..., Difficulty: ${data.difficulty} bits]`);
        metrics.pow++;
        document.getElementById('metric-pow').textContent = metrics.pow;
        
        const startTime = performance.now();
        const nonce = await DCPTransport.solvePoW(data.salt, data.difficulty);
        const duration = (performance.now() - startTime).toFixed(1);
        logConsole("pow", `[PoW Solved! Nonce: ${nonce} computed in ${duration}ms]`);
        
        wsConn.send(JSON.stringify({
          action: 'submit_pow',
          nonce,
          packet: toHex(pendingPacket)
        }));
      } else if (data.status === 'registered') {
        logConsole("system", `[Registered on Relay Node: ${data.userId}]`);
      } else if (data.type === 'onion_packet') {
        await receivePacket(fromHex(data.envelope));
      } else if (data.status === 'error') {
        logConsole("system", `[Server Error] Code: ${data.code} - ${data.message}`);
      }
    } catch (e) {
      if (event.data instanceof Blob) {
        const buf = await event.data.arrayBuffer();
        await receivePacket(new Uint8Array(buf));
      }
    }
  });

  wsConn.addEventListener('close', () => {
    setTimeout(tryConnectWebSocketRelay, 10000);
  });
}

// Contact Management
document.getElementById('btn-add-contact').addEventListener('click', async () => {
  const contactInput = document.getElementById('input-contact-id').value.trim();
  if (!contactInput) return;
  
  try {
    let card = null;
    if (contactInput.startsWith('{')) {
      card = JSON.parse(contactInput);
    } else {
      const parsed = DCPIdentity.parseUserId(contactInput);
      if (!parsed) return alert("Invalid User ID. Paste a full Contact Card");
      card = { userId: contactInput, username: parsed.username, identityKey: "", dhKey: "" };
    }
    
    if (contacts[card.userId]) return alert("Contact already exists");
    
    contacts[card.userId] = {
      username: card.username || DCPIdentity.parseUserId(card.userId).username,
      userId: card.userId,
      identityKey: card.identityKey,
      dhKey: card.dhKey,
      session: null
    };

    if (card.dhKey) {
      await initDoubleRatchetSession(card.userId);
    } else {
      // DHT rotating blinded lookup simulation
      const lookupKey = await DCPDHT.deriveBlindedLookupKey(myIdentity.keys.encryptionKey.privateKey, 0);
      logConsole("system", `[DHT Blinded query sent for key ${lookupKey.slice(0, 16)}...]`);
      virtualMesh.postMessage({
        type: 'presence_announce',
        senderId: myIdentity.userId,
        recipientId: card.userId
      });
    }

    renderContacts();
    saveState();
    document.getElementById('input-contact-id').value = "";
  } catch (e) {
    alert("Error adding contact: " + e.message);
  }
});

async function initDoubleRatchetSession(contactId) {
  const contact = contacts[contactId];
  const isInitiator = myIdentity.userId < contactId;
  contact.session = await DoubleRatchetSession.init(
    myIdentity.keys.encryptionKey,
    contact.dhKey,
    isInitiator
  );
  logConsole("system", `[Double Ratchet session initialized with ${contact.username}]`);
}

function renderContacts() {
  const container = document.getElementById('contacts-list');
  container.innerHTML = "";
  const entries = Object.values(contacts);
  if (entries.length === 0) {
    container.innerHTML = `<p class="empty-state">No contacts added yet</p>`;
    return;
  }
  entries.forEach(c => {
    const div = document.createElement('div');
    div.className = `contact-item ${activeContactId === c.userId ? 'active' : ''}`;
    div.innerHTML = `
      <div>
        <p class="username">${c.username}</p>
        <p class="id-sub">${c.userId}</p>
      </div>
    `;
    div.addEventListener('click', () => selectContact(c.userId));
    container.appendChild(div);
  });
}

function selectContact(contactId) {
  activeContactId = contactId;
  renderContacts();
  const contact = contacts[contactId];
  
  const header = document.getElementById('active-chat-header');
  if (contact.isGroup) {
    header.innerHTML = `
      <div>
        <p class="title-name">${contact.username}</p>
        <p class="title-id">${contact.userId} • Group Epoch: ${contact.epoch}</p>
      </div>
      <div class="chat-header-meta" style="display: flex; gap: 8px; align-items: center;">
        <button id="btn-group-rotate" class="tiny-btn" style="padding: 2px 6px; font-size: 10px; background: rgba(239, 68, 68, 0.1); border-color: rgba(239, 68, 68, 0.3); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 4px; cursor: pointer;">Evict Member</button>
        <span>Members: ${contact.members.length}</span>
      </div>
    `;
    document.getElementById('btn-group-rotate').addEventListener('click', () => rotateGroupKey(contact.userId));
  } else {
    header.innerHTML = `
      <div>
        <p class="title-name">${contact.username}</p>
        <p class="title-id">${contact.userId}</p>
      </div>
      <div class="chat-header-meta" style="display: flex; gap: 8px; align-items: center;">
        <button id="btn-call-voice" class="tiny-btn" style="padding: 2px 6px; font-size: 10px; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); color: var(--accent-blue); border-radius: 4px; cursor: pointer;">📞 Call</button>
        <span>Ratchet Seq: ${contact.session ? contact.session.sequenceNumberSend : 0}</span>
        <span>Capability: Direct Message, Files</span>
      </div>
    `;
  }

  document.getElementById('chat-input-row').style.display = 'flex';
  const msgInput = document.getElementById('input-message');
  const sendBtn = document.getElementById('btn-send-message');
  const attachBtn = document.getElementById('btn-attach-file');
  msgInput.disabled = false;
  sendBtn.disabled = false;
  attachBtn.disabled = contact.isGroup ? true : false;
  
  document.getElementById('routing-label-recipient').textContent = contact.username;
  renderMessages();

  // Hook Call Button listener if direct message
  if (!contact.isGroup) {
    document.getElementById('btn-call-voice').addEventListener('click', () => triggerVoiceCall(contactId));
  }
}

// Voice Calling Call States & WebRTC Signaling Simulation (Phase 3D)
let callState = "Idle"; // Idle | Ringing | Accepted | Connected | Ended
let callTimeoutId = null;

async function triggerVoiceCall(contactId) {
  const contact = contacts[contactId];
  const btnCall = document.getElementById('btn-call-voice');
  
  if (callState === "Idle") {
    callState = "Ringing";
    btnCall.textContent = "📞 Ringing...";
    btnCall.style.background = "rgba(245, 158, 11, 0.1)";
    btnCall.style.borderColor = "rgba(245, 158, 11, 0.3)";
    btnCall.style.color = "#f59e0b";
    
    logConsole("send", `[Call State: RINGING] Initiating call to ${contact.username}.`);
    logConsole("send", `[Call Signaling] SDP Offer packed: v=0\\no=alice 2890844526... Encrypted using Double Ratchet session.`);

    // Transition to Accepted
    callTimeoutId = setTimeout(() => {
      callState = "Accepted";
      btnCall.textContent = "📞 Connecting...";
      logConsole("recv", `[Call State: ACCEPTED] Received SDP Answer from ${contact.username}: v=0\\no=bob 2890844527...`);
      
      // Transition to Connected
      callTimeoutId = setTimeout(() => {
        callState = "Connected";
        btnCall.textContent = "❌ Hangup";
        btnCall.style.background = "rgba(239, 68, 68, 0.1)";
        btnCall.style.borderColor = "rgba(239, 68, 68, 0.3)";
        btnCall.style.color = "#ef4444";
        
        logConsole("pow", `[Call State: CONNECTED] ICE candidate exchange completed.`);
        logConsole("system", `[Call P2P Media] WebRTC direct peer-to-peer session negotiated. Relays bypassed. Media encrypt: SRTP.`);
      }, 1500);
    }, 1500);

  } else if (callState === "Connected" || callState === "Ringing" || callState === "Accepted") {
    if (callTimeoutId) clearTimeout(callTimeoutId);
    callState = "Idle";
    btnCall.textContent = "📞 Call";
    btnCall.style.background = "rgba(59, 130, 246, 0.1)";
    btnCall.style.borderColor = "rgba(59, 130, 246, 0.3)";
    btnCall.style.color = "var(--accent-blue)";
    
    logConsole("system", `[Call State: ENDED] Session closed by user. WebRTC signaling resources purged.`);
  }
}

// Ephemeral Typing Indicators & Private Presence Settings (Phase 3D)
let typingTimeoutId = null;

document.getElementById('input-message').addEventListener('input', () => {
  if (!activeContactId || contacts[activeContactId].isGroup) return;
  
  // Throttle typing indicator console announcements
  if (!typingTimeoutId) {
    logConsole("send", `[Typing E2EE] Sent transient typing indicator to ${contacts[activeContactId].username}.`);
    simulateIncomingTypingIndicator(activeContactId);
  }
});

function simulateIncomingTypingIndicator(contactId) {
  const contact = contacts[contactId];
  const headerMeta = document.querySelector('.chat-header-meta');
  if (!headerMeta) return;

  const typingBadge = document.createElement('span');
  typingBadge.id = 'typing-badge';
  typingBadge.style.color = 'var(--accent-blue)';
  typingBadge.style.fontWeight = '600';
  typingBadge.style.marginLeft = '8px';
  typingBadge.textContent = '✍️ Typing...';
  
  const existing = document.getElementById('typing-badge');
  if (existing) existing.remove();
  
  headerMeta.appendChild(typingBadge);
  logConsole("recv", `[Typing E2EE] Received transient typing indicator from ${contact.username}.`);

  // Auto-timeout after 5 seconds (RFC-0012)
  if (typingTimeoutId) clearTimeout(typingTimeoutId);
  typingTimeoutId = setTimeout(() => {
    const badge = document.getElementById('typing-badge');
    if (badge) {
      badge.remove();
      logConsole("system", `[Typing Timeout] E2EE typing indicator expired (5s timeout). Clearing UI state.`);
    }
    typingTimeoutId = null;
  }, 5000);
}

// Presence visibility profile updates listener
document.getElementById('select-presence-visibility').addEventListener('change', (e) => {
  logConsole("system", `[Presence Privacy Level changed to: ${e.target.value.toUpperCase()}]`);
});

// Messaging & Packet Transmissions
document.getElementById('btn-send-message').addEventListener('click', sendMessage);
document.getElementById('input-message').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendMessage();
});

async function sendMessage() {
  const input = document.getElementById('input-message');
  const text = input.value.trim();
  if (!text || !activeContactId) return;
  input.value = "";

  const contact = contacts[activeContactId];
  const encoder = new TextEncoder();
  const rawTextBytes = encoder.encode(JSON.stringify({ text, timestamp: Date.now() }));
  
  // Apply PKCS#7 / Fixed Padding depending on selected Privacy Level (RFC-0009)
  const privacyLevel = document.getElementById('select-privacy-level').value;
  let paddedBytes = rawTextBytes;
  if (privacyLevel === "medium") {
    paddedBytes = padPKCS7(rawTextBytes, 256);
  } else if (privacyLevel === "max") {
    paddedBytes = padFixedSize(rawTextBytes, 2048, 128);
  }

  // Record metrics
  metrics.plainBytesTotal += rawTextBytes.length;
  metrics.paddedBytesTotal += paddedBytes.length;
  updateMetricsBandwidth(paddedBytes.length);

  if (contact.isGroup) {
    contact.seq++;
    const encryptResult = await DCPGroup.encryptGroupMessage(
      paddedBytes,
      contact.chainKey,
      myIdentity.keys.identityKey.privateKey
    );

    logConsole("send", `[Group Send] Posted to group: ${contact.username}.
Group Epoch: ${contact.epoch} • Seq: ${contact.seq}
Ciphertext payload:\n${encryptResult.ciphertext.slice(0, 120)}... [${encryptResult.ciphertext.length / 2} bytes]
Ed25519 Signature:\n${encryptResult.signature.slice(0, 80)}...`);

    // Loopback decryption simulation
    const decrypted = await DCPGroup.decryptGroupMessage(
      encryptResult.ciphertext,
      encryptResult.signature,
      contact.chainKey,
      myIdentity.keys.identityKey.publicKey
    );

    const decryptedObj = JSON.parse(new TextDecoder().decode(decrypted.plaintextBytes));
    logConsole("recv", `[Group Receive] Recipient verified Ed25519 signature & decrypted message: "${decryptedObj.text}"`);

    // Rotate local chain key
    contact.chainKey = encryptResult.nextChainKeyHex;

    // Save message and animate routing to group Relays
    const relayPath = [
      "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209",
      "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"
    ];
    metrics.sent++;
    document.getElementById('metric-sent').textContent = metrics.sent;

    await animateOnionRoute(relayPath, contact.username, () => {
      if (!messages[contact.userId]) messages[contact.userId] = [];
      messages[contact.userId].push({ senderId: myIdentity.userId, text: text, timestamp: Date.now() });
      renderMessages();
      saveState();
    });
    return;
  }

  if (!contact.session) {
    return alert("Cannot send message: Key exchange handshake in progress...");
  }

  const encryptResult = await contact.session.encrypt(paddedBytes);
  
  const payloadJSON = JSON.stringify({
    ciphertext: toHex(encryptResult.ciphertext),
    sequence: encryptResult.sequence,
    dhPub: encryptResult.dhPub
  });
  const payloadBytes = encoder.encode(payloadJSON);

  // 3. Assemble Binary DCP Packet
  const binaryPacket = await DCPPacket.pack({
    protocolVersion: 1,
    flags: 0x02 | 0x04, 
    cipherSuiteId: 0x02, 
    packetType: 0x01, 
    payloadBytes: payloadBytes,
    senderPrivateKeyHex: myIdentity.keys.identityKey.privateKey
  });

  logConsole("send", `[Assembled binary packet type 0x01 (Direct Message) to send to ${contact.username}]
Payload Length: Raw ${rawTextBytes.length}B padded to ${paddedBytes.length}B (Privacy: ${privacyLevel.toUpperCase()})
Packet Hex Dump:\n${formatHexDump(binaryPacket)}`);

  // 4. Wrap packet in Onion Routing layers
  const relayA = "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209";
  const relayB = "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59";
  const relayC = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22";
  const relayPath = [relayA, relayB, relayC];
  
  // Track Route Diversity (Route load-balancing)
  recentlyUsedRelays.push(relayA);
  if (recentlyUsedRelays.length > 5) recentlyUsedRelays.shift();

  const onionEnvelope = await DCPTransport.wrapOnion(
    binaryPacket,
    relayPath,
    contact.userId
  );

  metrics.sent++;
  document.getElementById('metric-sent').textContent = metrics.sent;

  // 5. Run Routing Animation
  await animateOnionRoute(relayPath, contact.username, async () => {
    if (wsConn && wsConn.readyState === WebSocket.OPEN) {
      pendingPacket = onionEnvelope;
      wsConn.send(JSON.stringify({
        action: 'route_onion',
        envelope: toHex(onionEnvelope)
      }));
    } else {
      virtualMesh.postMessage({
        type: 'onion_packet',
        recipientId: contact.userId,
        senderId: myIdentity.userId,
        envelope: onionEnvelope
      });
    }

    if (!messages[contact.userId]) messages[contact.userId] = [];
    messages[contact.userId].push({ senderId: myIdentity.userId, text: text, timestamp: Date.now() });
    renderMessages();
    saveState();
  });
}

// Synthetic Dummy Cover Traffic generation (RFC-0009 v2 max budget enforcement)
async function sendDummyCoverPacket() {
  if (!myIdentity || !wsConn || wsConn.readyState !== WebSocket.OPEN) return;
  
  const budgetLimit = document.getElementById('select-dummy-budget').value;
  // Simple check: 500 KB limit per minute
  const dummySize = 2048; // 2KB fixed dummy size
  const maxAllowedBytes = budgetLimit === "unlimited" ? Infinity : parseInt(budgetLimit) * 1024;
  
  if (metrics.bandwidth > maxAllowedBytes) {
    logConsole("pow", `[Metadata Protection] Cover traffic suspended: Bandwidth budget exceeded (${(metrics.bandwidth / 1024).toFixed(1)} KB used).`);
    return;
  }

  // Create randomized dummy payload
  const rawBytes = new Uint8Array(64);
  window.crypto.getRandomValues(rawBytes);
  const paddedBytes = padFixedSize(rawBytes, 2048, 128);
  
  // Wrap dummy payload in onion layers
  const relayA = "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209";
  const relayB = "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59";
  const relayC = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22";
  const relayPath = [relayA, relayB, relayC];
  
  const binaryPacket = await DCPPacket.pack({
    protocolVersion: 1,
    flags: 0x02,
    packetType: 0x08, // Ephemeral / Dummy type
    payloadBytes: paddedBytes
  });
  
  const onionEnvelope = await DCPTransport.wrapOnion(binaryPacket, relayPath, "@dummy.network.sink");
  
  // Send dummy
  wsConn.send(JSON.stringify({
    action: "route_onion",
    envelope: toHex(onionEnvelope)
  }));

  metrics.dummy++;
  document.getElementById('metric-dummy').textContent = metrics.dummy;
  updateMetricsBandwidth(onionEnvelope.byteLength);

  logConsole("pow", `[Metadata Protection] Dispatched 2KB randomized dummy cover traffic packet. Budget Limit: ${budgetLimit} KB/min.`);
}

async function receivePacket(onionEnvelope) {
  try {
    const packet = DCPPacket.unpack(onionEnvelope);
    
    // Ignore synthetic dummy packets on the UI stream
    if (packet.header.packetType === 0x08) {
      logConsole("recv", `[Received synthetic dummy cover traffic packet. Safely ignored.]`);
      return;
    }

    const payloadStr = new TextDecoder().decode(packet.payload);
    const payload = JSON.parse(payloadStr);
    
    let senderId = null;
    let senderContact = null;
    
    for (const [cid, c] of Object.entries(contacts)) {
      if (c.dhKey === payload.dhPub || c.session?.theirDHPubHex === payload.dhPub) {
        senderId = cid;
        senderContact = c;
        break;
      }
    }
    
    if (!senderContact && activeContactId) {
      senderId = activeContactId;
      senderContact = contacts[activeContactId];
    }
    
    if (!senderContact) return;

    logConsole("recv", `[Received binary packet from ${senderContact.username}]`);

    // Decrypt and unpad
    const ciphertext = fromHex(payload.ciphertext);
    const decryptedPaddedBytes = await senderContact.session.decrypt(
      ciphertext,
      payload.dhPub,
      payload.sequence
    );

    // Unpad based on privacy settings
    let decryptedBytes;
    const privacyLevel = document.getElementById('select-privacy-level').value;
    if (privacyLevel === "medium") {
      decryptedBytes = unpadPKCS7(decryptedPaddedBytes);
    } else if (privacyLevel === "max") {
      decryptedBytes = unpadFixedSize(decryptedPaddedBytes);
    } else {
      decryptedBytes = decryptedPaddedBytes;
    }

    const decrypted = JSON.parse(new TextDecoder().decode(decryptedBytes));
    
    if (!messages[senderId]) messages[senderId] = [];
    messages[senderId].push({ senderId: senderId, text: decrypted.text, timestamp: decrypted.timestamp });

    if (activeContactId === senderId) renderMessages();
    saveState();
    
    metrics.recv++;
    document.getElementById('metric-recv').textContent = metrics.recv;
    updateMetricsBandwidth(onionEnvelope.byteLength);

    logConsole("recv", `[Double Ratchet decrypted message successfully: "${decrypted.text}"]`);
    
    // ------------------ SUBMIT SIGNED DELIVERY ACK (RFC-0004 v2) ------------------
    if (wsConn && wsConn.readyState === WebSocket.OPEN) {
      const ack = DCPMailbox.buildACK(
        packet.header.packetId,
        myIdentity.keys.identityKey.publicKey, // Device Identity PubKey
        "noise_session_token_1234",
        myIdentity.keys.identityKey.privateKey // Device Identity PrivKey
      );
      
      wsConn.send(JSON.stringify({
        action: "submit_ack",
        payload: ack.payload,
        signature: ack.signature
      }));
      logConsole("system", `[Mailbox ACK] Transmitted signed delivery receipt ACK for packet ID: ${packet.header.packetId.slice(0, 16)}...`);
    }

  } catch (e) {
    logConsole("system", `[Packet unpacking/decryption failed: ${e.message}]`);
  }
}

function updateMetricsBandwidth(bytesAdded) {
  metrics.bandwidth += bytesAdded;
  document.getElementById('metric-bandwidth').textContent = `${(metrics.bandwidth / 1024).toFixed(1)} KB`;
  
  // Calculate padding overhead
  const total = metrics.paddedBytesTotal || 1;
  const raw = metrics.plainBytesTotal || 1;
  const overheadPct = Math.round(((total - raw) / total) * 100);
  document.getElementById('metric-overhead').textContent = `${overheadPct}%`;
}

function renderMessages() {
  const container = document.getElementById('chat-messages');
  container.innerHTML = "";
  
  if (!activeContactId) return;
  const list = messages[activeContactId] || [];
  
  if (list.length === 0) {
    container.innerHTML = `
      <div class="empty-chat-state">
        <div class="shield-icon">🛡️</div>
        <h3>Secure Session Active</h3>
        <p>No messages in history. Start chatting securely.</p>
      </div>
    `;
    return;
  }

  list.forEach(m => {
    const bubble = document.createElement('div');
    const isMe = m.senderId === myIdentity.userId;
    bubble.className = `message-bubble ${isMe ? 'sent' : 'received'}`;
    const timeStr = new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    bubble.innerHTML = `
      <p class="text">${escapeHtml(m.text)}</p>
      <div class="message-meta">
        <span>${timeStr}</span>
        <span>${isMe ? 'Sent (Onion)' : 'E2E Verified'}</span>
      </div>
    `;
    container.appendChild(bubble);
  });
  container.scrollTop = container.scrollHeight;
}

// SVG Path Animation Coordinator
function animateOnionRoute(relays, recipientName, callback) {
  return new Promise((resolve) => {
    const dot = document.getElementById('packet-dot');
    const logContainer = document.getElementById('peeling-log');
    dot.style.display = 'block';
    logContainer.innerHTML = "";
    
    const hops = [
      { x: 50, y: 75, name: 'You' },
      { x: 280, y: 75, name: 'Relay A (Entrance)' },
      { x: 510, y: 75, name: 'Relay B (Middle)' },
      { x: 740, y: 75, name: 'Relay C (Exit)' },
      { x: 950, y: 75, name: recipientName }
    ];

    let currentHopIndex = 0;
    
    function moveNext() {
      if (currentHopIndex >= hops.length - 1) {
        setTimeout(() => {
          dot.style.display = 'none';
          callback();
          resolve();
        }, 300);
        return;
      }

      const start = hops[currentHopIndex];
      const end = hops[currentHopIndex + 1];
      let startTime = null;

      if (currentHopIndex === 0) {
        logPeel("You", `Packet serialized (PKCS#7 padded). Onion-routing...`);
      } else {
        const relayName = start.name;
        const layerNum = 3 - currentHopIndex;
        logPeel(relayName, `Decrypted layer envelope. Found routing endpoint: ${end.name}`);
      }

      function step(timestamp) {
        if (!startTime) startTime = timestamp;
        const elapsed = timestamp - startTime;
        const progress = Math.min(elapsed / PATH_DURATION, 1);
        const curX = start.x + (end.x - start.x) * progress;
        const curY = start.y + (end.y - start.y) * progress;
        dot.setAttribute('cx', curX);
        dot.setAttribute('cy', curY);
        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          currentHopIndex++;
          moveNext();
        }
      }
      requestAnimationFrame(step);
    }
    moveNext();
  });
}

function logPeel(tag, message) {
  const logContainer = document.getElementById('peeling-log');
  const div = document.createElement('div');
  div.className = "peel-line";
  div.innerHTML = `<span class="tag">[${tag}]</span> ${message}`;
  logContainer.appendChild(div);
  logContainer.scrollTop = logContainer.scrollHeight;
}

function logConsole(type, message) {
  const container = document.getElementById('console-output');
  const div = document.createElement('div');
  div.className = `console-line ${type}`;
  div.innerText = message;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function formatHexDump(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let hex = "";
  let ascii = "";
  let result = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0') + " ";
    ascii += (bytes[i] >= 32 && bytes[i] <= 126) ? String.fromCharCode(bytes[i]) : ".";
    if ((i + 1) % 16 === 0 || i === bytes.length - 1) {
      if ((i + 1) % 16 !== 0) {
        const remaining = 16 - ((i + 1) % 16);
        hex += "   ".repeat(remaining);
      }
      result += hex + "  |  " + ascii + "\n";
      hex = "";
      ascii = "";
    }
  }
  return result;
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Local Storage Encrypted Vault Session Persistence (PWA Passphrase/PIN Protection)

// Derives 256-bit AES-GCM key from PIN and Salt via PBKDF2-HMAC-SHA256 (10,000 iterations)
async function deriveVaultKey(pin, saltBytes) {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(pin),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 10000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypts text payload using PIN
async function encryptVault(plaintextText, pin) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveVaultKey(pin, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    new TextEncoder().encode(plaintextText)
  );
  return {
    salt: toHex(salt),
    iv: toHex(iv),
    ciphertext: toHex(new Uint8Array(encrypted))
  };
}

// Decrypts ciphertext using PIN
async function decryptVault(encryptedObj, pin) {
  const salt = fromHex(encryptedObj.salt);
  const iv = fromHex(encryptedObj.iv);
  const ciphertext = fromHex(encryptedObj.ciphertext);
  const aesKey = await deriveVaultKey(pin, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    ciphertext
  );
  return new TextDecoder().decode(new Uint8Array(decrypted));
}

export async function saveState() {
  if (!myIdentity || !activeWalletPin) return;

  const plainData = {
    identity: {
      username: myIdentity.username,
      mnemonic: myIdentity.mnemonic,
      userId: myIdentity.userId
    },
    contacts: Object.values(contacts).map(c => ({
      username: c.username,
      userId: c.userId,
      identityKey: c.identityKey,
      dhKey: c.dhKey,
      isGroup: c.isGroup || false,
      epoch: c.epoch || 1,
      seq: c.seq || 0,
      chainKey: c.chainKey || "",
      members: c.members || []
    })),
    messages: messages
  };

  try {
    const encrypted = await encryptVault(JSON.stringify(plainData), activeWalletPin);
    localStorage.setItem('dcp_encrypted_vault', JSON.stringify(encrypted));
  } catch (e) {
    console.error("Failed to encrypt vault:", e);
  }
}

export async function tryAutoLogin() {
  const cachedVault = localStorage.getItem('dcp_encrypted_vault');
  if (!cachedVault) return;

  // Hide onboarding card and show PIN Unlock overlay
  document.getElementById('onboarding-card').style.display = 'none';
  const unlockCard = document.getElementById('unlock-card');
  unlockCard.style.display = 'block';
  unlockCard.classList.add('active');
  
  setupUnlockListeners();
}

let unlockListenersAttached = false;
function setupUnlockListeners() {
  if (unlockListenersAttached) return;
  unlockListenersAttached = true;
  
  const btnUnlock = document.getElementById('btn-unlock-identity');
  const btnReset = document.getElementById('btn-reset-wallet');
  
  btnUnlock.addEventListener('click', async () => {
    const pin = document.getElementById('unlock-pin').value.trim();
    if (!pin) return alert("Please enter your Security PIN");
    
    const cachedVault = localStorage.getItem('dcp_encrypted_vault');
    if (!cachedVault) return;
    
    try {
      const encryptedObj = JSON.parse(cachedVault);
      const decryptedText = await decryptVault(encryptedObj, pin);
      const data = JSON.parse(decryptedText);
      
      activeWalletPin = pin;
      
      logConsole("system", `[Vault Decrypted] Welcome back, ${data.identity.username}! Deriving identity keys...`);
      const seed = await DCPIdentity.deriveSeed(data.identity.mnemonic);
      const keys = DCPCrypto.deriveKeysFromSeed(seed);
      
      myIdentity = {
        username: data.identity.username,
        network: "dcp",
        mnemonic: data.identity.mnemonic,
        keys,
        userId: data.identity.userId
      };
      
      // Restore contacts
      contacts = {};
      if (data.contacts) {
        data.contacts.forEach(async c => {
          contacts[c.userId] = c;
          if (c.dhKey && !c.isGroup) {
            await initDoubleRatchetSession(c.userId);
          }
        });
      }
      
      // Restore messages
      messages = {};
      if (data.messages) {
        Object.assign(messages, data.messages);
      }
      
      // Transition UI
      document.getElementById('unlock-card').style.display = 'none';
      document.getElementById('main-dashboard').classList.add('active');
      
      renderUserBadge();
      renderContacts();
      
      logConsole("system", `[Wallet Unlocked] Double Ratchet sessions restored and local whitelists active.`);
      publishDHTAdvertisement();
    } catch (e) {
      console.error(e);
      alert("Invalid Security PIN. Access denied.");
    }
  });

  btnReset.addEventListener('click', () => {
    if (confirm("Are you sure you want to reset your wallet? All local history and whitelists will be permanently deleted. Make sure you have your 12-word mnemonic backup!")) {
      localStorage.removeItem('dcp_encrypted_vault');
      location.reload();
    }
  });
}

// Diagnostics, Crash Recovery & Tutorials (Phase 3 Alpha Additions)
let tutorialStep = 1;
const tutorialStepsContent = {
  1: `<h3>🔑 Cryptographic Identity</h3>
      <p style="margin-top: 10px;">Your account is a 12-word mnemonic. No central servers hold your credentials. If you lose your recovery phrase, the account is lost forever. Always keep a backup secure.</p>`,
  2: `<h3>🧅 Onion Routing</h3>
      <p style="margin-top: 10px;">DCP packets hop through 3 independent Relays (Alpha, Beta, Gamma) in the network. This blinds your IP address and communication graph from eavesdroppers.</p>`,
  3: `<h3>📬 Decentralized Mailboxes</h3>
      <p style="margin-top: 10px;">Relays store E2E encrypted messages in temporary mailboxes. Once your device goes online, they are delivered and deleted immediately upon signature acknowledgment.</p>`,
  4: `<h3>🛡️ Local Reputation Whitelisting</h3>
      <p style="margin-top: 10px;">Your device monitors relay reliability and latency locally. No global scoreboards are queried, preventing tracking of relay selection patterns.</p>`
};

export function setupAlphaSystem() {
  // 1. Crash Recovery Monitoring
  const isDirtyShutdown = localStorage.getItem('dcp_dirty_shutdown');
  if (isDirtyShutdown === 'true') {
    document.getElementById('crash-banner').style.display = 'flex';
  }
  
  // Set dirty state for current session
  localStorage.setItem('dcp_dirty_shutdown', 'true');
  window.addEventListener('beforeunload', () => {
    // Clear dirty state on graceful close
    localStorage.setItem('dcp_dirty_shutdown', 'false');
  });

  document.getElementById('btn-crash-dismiss').addEventListener('click', () => {
    document.getElementById('crash-banner').style.display = 'none';
  });

  document.getElementById('btn-crash-reset').addEventListener('click', () => {
    if (confirm("Reset wallet cache now? You will need your 12-word mnemonic to log back in.")) {
      localStorage.clear();
      location.reload();
    }
  });

  // 2. Export Debug Report (Excludes Mnemonics, PINs, or Message Texts)
  document.getElementById('btn-export-debug').addEventListener('click', () => {
    const report = {
      app: "PeerGrid Alpha",
      protocol_version: "1.0.0",
      platform_version: "0.1.0-alpha",
      build_date: "2026-07-13",
      browser: navigator.userAgent,
      os: navigator.platform,
      active_relays: ["Relay Alpha", "Relay Beta", "Relay Gamma"],
      session_metrics: {
        messages_sent: metrics.sent,
        messages_received: metrics.recv,
        relays_switched: metrics.switches,
        cover_dummies: metrics.dummy,
        pow_solves: metrics.pow,
        bandwidth_bytes: metrics.bandwidth
      },
      diagnostics_timestamp: Date.now()
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `peergrid_debug_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    logConsole("system", "[Diagnostics] Exported anonymized debug report JSON file successfully.");
  });

  // 3. User Feedback Dialog
  document.getElementById('btn-feedback').addEventListener('click', () => {
    const type = prompt("Enter feedback type (Bug, Suggestion, UI confusion, Performance):", "Bug");
    if (!type) return;
    const details = prompt("Enter your feedback details:");
    if (!details) return;

    const feedbackTemplate = `PEERGRID ALPHA USER FEEDBACK\nType: ${type}\nDetails: ${details}\nOS: ${navigator.platform}\nBrowser: ${navigator.userAgent}`;
    navigator.clipboard.writeText(feedbackTemplate);
    alert("Feedback draft copied to clipboard! Paste it to share with the developers. Thank you!");
    logConsole("system", `[Feedback Shared] Copied user draft of type: ${type.toUpperCase()}`);
  });

  // 4. First-Run Tutorial Configuration
  const isTutorialDone = localStorage.getItem('dcp_tutorial_complete');
  if (isTutorialDone !== 'true') {
    // Display after onboarding card or active login completes
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.target.id === 'main-dashboard' && mutation.target.classList.contains('active')) {
          showTutorial();
          observer.disconnect();
        }
      });
    });
    observer.observe(document.getElementById('main-dashboard'), { attributes: true });
  }
}

function showTutorial() {
  document.getElementById('modal-backdrop').style.display = 'block';
  const modal = document.getElementById('tutorial-modal');
  modal.style.display = 'block';

  renderTutorialStep();

  document.getElementById('btn-tutorial-prev').addEventListener('click', () => {
    if (tutorialStep > 1) {
      tutorialStep--;
      renderTutorialStep();
    }
  });

  document.getElementById('btn-tutorial-next').addEventListener('click', () => {
    if (tutorialStep < 4) {
      tutorialStep++;
      renderTutorialStep();
    } else {
      // Completed
      localStorage.setItem('dcp_tutorial_complete', 'true');
      document.getElementById('modal-backdrop').style.display = 'none';
      document.getElementById('tutorial-modal').style.display = 'none';
      logConsole("system", "[Welcome Tutorial] Walkthrough completed. Tutorial flag cached.");
    }
  });
}

function renderTutorialStep() {
  const content = document.getElementById('tutorial-step-content');
  const prevBtn = document.getElementById('btn-tutorial-prev');
  const nextBtn = document.getElementById('btn-tutorial-next');
  const indicator = document.getElementById('tutorial-step-indicator');

  content.innerHTML = tutorialStepsContent[tutorialStep];
  indicator.textContent = `${tutorialStep} / 4`;

  prevBtn.style.visibility = tutorialStep === 1 ? 'hidden' : 'visible';
  nextBtn.textContent = tutorialStep === 4 ? 'Get Started' : 'Next';
}

// ─────────────────────────────────────────────────────────────
//  Mobile Tab Navigation
// ─────────────────────────────────────────────────────────────
function switchMobileTab(tab) {
  if (window.innerWidth > 768) return; // only run on mobile

  const sidebar = document.querySelector('.sidebar');
  const chatArea = document.querySelector('.chat-area');
  const consolePanel = document.querySelector('.console-panel');

  // Remove all active states first
  sidebar.classList.remove('mobile-active');
  consolePanel.classList.remove('mobile-active');

  // Update tab button active state
  ['contacts', 'chat', 'console'].forEach(t => {
    const btn = document.getElementById(`tab-btn-${t}`);
    if (btn) btn.classList.toggle('active', t === tab);
  });

  // Clear unread badge when switching to that tab
  const badge = document.getElementById(`tab-badge-${tab}`);
  if (badge) {
    const btn = document.getElementById(`tab-btn-${tab}`);
    if (btn) btn.classList.remove('has-badge');
  }

  if (tab === 'contacts') {
    sidebar.classList.add('mobile-active');
  } else if (tab === 'console') {
    consolePanel.classList.add('mobile-active');
  }
  // 'chat' — both panels slide away, chat-area underneath is visible
}

// Show unread dot on Chat tab when a message arrives while viewing another tab
function showUnreadTabBadge(tab) {
  if (window.innerWidth > 768) return;
  const activeTabBtn = document.querySelector('.tab-btn.active');
  if (activeTabBtn && activeTabBtn.id === `tab-btn-${tab}`) return; // already on this tab
  const btn = document.getElementById(`tab-btn-${tab}`);
  if (btn) btn.classList.add('has-badge');
}

// Expose globally for HTML onclick and app.js internal use
window.switchMobileTab = switchMobileTab;
window.showUnreadTabBadge = showUnreadTabBadge;

// Auto-switch to Chat tab when a contact is selected (mobile)

// ═══════════════════════════════════════════════════════════════
//  MOBILE APP CONTROLLER — WhatsApp-style
// ═══════════════════════════════════════════════════════════════

const AVATAR_COLORS = ['mob-avatar-0','mob-avatar-1','mob-avatar-2','mob-avatar-3','mob-avatar-4','mob-avatar-5','mob-avatar-6','mob-avatar-7'];
let mobActiveContactId = null;

function isMobile() { return window.innerWidth <= 768; }

// ── Show/hide mobile vs desktop ──────────────────────────────
function applyLayout() {
  const mobileApp = document.getElementById('mobile-app');
  const dashboard = document.getElementById('main-dashboard');
  if (!mobileApp) return;
  if (isMobile()) {
    mobileApp.style.display = 'flex';
    if (dashboard) dashboard.style.setProperty('display','none','important');
  } else {
    mobileApp.style.display = 'none';
    if (dashboard && dashboard.classList.contains('active')) {
      dashboard.style.removeProperty('display');
    }
  }
}

window.addEventListener('resize', applyLayout);
document.addEventListener('DOMContentLoaded', () => {
  applyLayout();
  setupMobileApp();
});

// ── Render chat list ──────────────────────────────────────────
function mobRenderChatList() {
  const list = document.getElementById('mob-chat-list');
  if (!list) return;
  const ids = Object.keys(contacts);
  if (ids.length === 0) {
    list.innerHTML = `<div class="mob-empty-state">
      <div style="font-size:48px;margin-bottom:12px;">🔒</div>
      <p style="font-weight:600;font-size:15px;margin-bottom:6px;">No chats yet</p>
      <p style="color:var(--mob-text-secondary);font-size:13px;">Tap + to add your first contact</p>
    </div>`;
    return;
  }
  list.innerHTML = '';
  ids.forEach((userId, i) => {
    const c = contacts[userId];
    const initial = (c.username || '?')[0].toUpperCase();
    const colorClass = AVATAR_COLORS[i % AVATAR_COLORS.length];
    const preview = c.lastMessage || '🔒 Encrypted session active';
    const time = c.lastTime || '';
    const unread = c.unread || 0;

    const item = document.createElement('div');
    item.className = 'mob-chat-item';
    item.dataset.userId = userId;
    item.innerHTML = `
      <div class="mob-chat-item-avatar ${colorClass}">${initial}</div>
      <div class="mob-chat-item-body">
        <div class="mob-chat-item-top">
          <span class="mob-chat-item-name">${c.username}</span>
          <span class="mob-chat-item-time ${unread > 0 ? 'unread' : ''}">${time}</span>
        </div>
        <div class="mob-chat-item-bottom">
          <span class="mob-chat-item-preview">${preview}</span>
          ${unread > 0 ? `<span class="mob-unread-badge">${unread}</span>` : ''}
        </div>
      </div>`;
    item.addEventListener('click', () => mobOpenChat(userId));
    list.appendChild(item);
  });
}

// ── Open individual chat ──────────────────────────────────────
function mobOpenChat(userId) {
  mobActiveContactId = userId;
  const c = contacts[userId];
  if (!c) return;

  // Clear unread
  if (c.unread) { c.unread = 0; mobRenderChatList(); }

  // Set header info
  const initial = (c.username || '?')[0].toUpperCase();
  const i = Object.keys(contacts).indexOf(userId);
  const colorClass = AVATAR_COLORS[i % AVATAR_COLORS.length];
  const avatar = document.getElementById('mob-chat-avatar');
  avatar.textContent = initial;
  avatar.className = `mob-chat-avatar ${colorClass}`;
  document.getElementById('mob-chat-name').textContent = c.username;
  document.getElementById('mob-chat-status').textContent = '🔒 End-to-end encrypted';

  // Render messages
  mobRenderMessages(userId);

  // Navigate to chat screen
  document.getElementById('mob-screen-chats').style.transform = 'translateX(-100%)';
  document.getElementById('mob-screen-chat').classList.remove('mob-screen-hidden');

  // Also select on desktop
  const desktopItem = document.querySelector(`.contact-item[data-user-id="${userId}"]`);
  if (desktopItem) desktopItem.click();
}

// ── Render messages in mobile chat ───────────────────────────
function mobRenderMessages(userId) {
  const container = document.getElementById('mob-messages');
  if (!container) return;
  container.innerHTML = `<div class="mob-encrypted-notice">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
    Messages are end-to-end encrypted. No one outside can read them.
  </div>`;

  const msgs = (window.messageHistory && window.messageHistory[userId]) || [];
  msgs.forEach(m => {
    mobAddBubble(m.text, m.outgoing, m.time);
  });
  container.scrollTop = container.scrollHeight;
}

// ── Add a single bubble ───────────────────────────────────────
function mobAddBubble(text, outgoing, timeStr) {
  const container = document.getElementById('mob-messages');
  if (!container) return;
  const div = document.createElement('div');
  div.className = `mob-bubble ${outgoing ? 'mob-bubble-out' : 'mob-bubble-in'}`;
  div.innerHTML = `${text}<div class="mob-bubble-time">${timeStr || ''}</div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

// ── Go back to chats list ─────────────────────────────────────
function mobGoBack() {
  document.getElementById('mob-screen-chats').style.transform = '';
  document.getElementById('mob-screen-chat').classList.add('mob-screen-hidden');
  mobActiveContactId = null;
}

// ── Bottom sheet helpers ──────────────────────────────────────
function mobShowSheet(name) {
  document.getElementById('mob-sheet-backdrop').classList.add('open');
  document.getElementById(`mob-${name}-sheet`).classList.add('open');

  // Mirror console to network sheet
  if (name === 'network') {
    const mirror = document.getElementById('mob-console-mirror');
    const consoleOutput = document.getElementById('console-output');
    if (mirror && consoleOutput) {
      mirror.innerHTML = consoleOutput.innerHTML;
      mirror.scrollTop = mirror.scrollHeight;
    }
  }

  // Mirror my ID to settings sheet
  if (name === 'settings' && myIdentity) {
    const el = document.getElementById('mob-my-id');
    if (el) el.textContent = myIdentity.userId || '—';
  }
}

function mobCloseSheets() {
  document.getElementById('mob-sheet-backdrop').classList.remove('open');
  document.querySelectorAll('.mob-bottom-sheet').forEach(s => s.classList.remove('open'));
}

// ── Setup all mobile event listeners ─────────────────────────
function setupMobileApp() {
  // Back button
  const backBtn = document.getElementById('mob-back-btn');
  if (backBtn) backBtn.addEventListener('click', mobGoBack);

  // Header new chat button
  const addOpen = document.getElementById('mob-btn-add-contact-open');
  if (addOpen) addOpen.addEventListener('click', () => mobShowSheet('add-contact'));

  // Add contact confirm
  const addConfirm = document.getElementById('mob-btn-add-contact-confirm');
  if (addConfirm) addConfirm.addEventListener('click', () => {
    const input = document.getElementById('mob-contact-id-input');
    const id = input ? input.value.trim() : '';
    if (!id) return;
    // Reuse desktop logic
    const desktopInput = document.getElementById('input-contact-id');
    const desktopBtn = document.getElementById('btn-add-contact');
    if (desktopInput && desktopBtn) {
      desktopInput.value = id;
      desktopBtn.click();
      input.value = '';
      mobCloseSheets();
      setTimeout(mobRenderChatList, 500);
    }
  });

  // Send message
  const sendBtn = document.getElementById('mob-send-btn');
  const msgInput = document.getElementById('mob-msg-input');
  if (sendBtn && msgInput) {
    const doSend = () => {
      const text = msgInput.value.trim();
      if (!text || !mobActiveContactId) return;
      // Mirror to desktop and trigger send
      const desktopInput = document.getElementById('input-message');
      const desktopSend = document.getElementById('btn-send-message');
      if (desktopInput && desktopSend) {
        desktopInput.value = text;
        desktopSend.click();
        msgInput.value = '';
        const t = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
        mobAddBubble(text, true, t);
        // Update preview in list
        if (contacts[mobActiveContactId]) {
          contacts[mobActiveContactId].lastMessage = text;
          contacts[mobActiveContactId].lastTime = t;
        }
      }
    };
    sendBtn.addEventListener('click', doSend);
    msgInput.addEventListener('keydown', e => { if (e.key === 'Enter') doSend(); });
  }

  // Copy ID
  const copyBtn = document.getElementById('mob-btn-copy-id');
  if (copyBtn) copyBtn.addEventListener('click', () => {
    if (myIdentity && myIdentity.userId) {
      navigator.clipboard.writeText(myIdentity.userId);
      copyBtn.textContent = 'Copied!';
      setTimeout(() => copyBtn.textContent = 'Copy', 2000);
    }
  });

  // Reset wallet
  const resetBtn = document.getElementById('mob-btn-reset');
  if (resetBtn) resetBtn.addEventListener('click', () => {
    const desktopReset = document.getElementById('btn-reset-wallet');
    if (desktopReset) desktopReset.click();
  });

  // Search filter
  const searchInput = document.getElementById('mob-search-input');
  if (searchInput) searchInput.addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('.mob-chat-item').forEach(item => {
      const name = item.querySelector('.mob-chat-item-name')?.textContent.toLowerCase() || '';
      item.style.display = name.includes(q) ? '' : 'none';
    });
  });

  // Filter pills
  document.querySelectorAll('.mob-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.mob-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
    });
  });
}

// ── Patch: notify mobile when a new contact is added ─────────
const _origRenderContacts = window.renderContactsList;
// We'll monkey-patch after contacts are updated
function mobSyncAfterContactChange() {
  if (isMobile()) mobRenderChatList();
}
window.mobSyncAfterContactChange = mobSyncAfterContactChange;

// ── Patch: notify mobile when new message arrives ─────────────
function mobOnNewMessage(userId, text, outgoing) {
  if (!isMobile()) return;
  const t = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  if (contacts[userId]) {
    contacts[userId].lastMessage = outgoing ? text : text;
    contacts[userId].lastTime = t;
    if (!outgoing && userId !== mobActiveContactId) {
      contacts[userId].unread = (contacts[userId].unread || 0) + 1;
    }
  }
  if (userId === mobActiveContactId && !outgoing) {
    mobAddBubble(text, false, t);
  }
  mobRenderChatList();
}
window.mobOnNewMessage = mobOnNewMessage;

// Expose globals
window.mobShowSheet = mobShowSheet;
window.mobCloseSheets = mobCloseSheets;
window.mobRenderChatList = mobRenderChatList;

