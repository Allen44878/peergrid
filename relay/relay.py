import asyncio
import json
import os
import time
import hashlib
import secrets
import sqlite3
from websockets.server import serve
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Server Config
PORT = int(os.environ.get("PORT", 8765))
HOST = "0.0.0.0"
DB_FILE = "dcp_relay.db"

# Static Relay seeds & keys
relay_seeds = {
    "A": b"\x01" * 32,
    "B": b"\x02" * 32,
    "C": b"\x03" * 32
}
relay_keys = {
    name: x25519.X25519PrivateKey.from_private_bytes(seed)
    for name, seed in relay_seeds.items()
}

# In-Memory Session Variables
clients = {}  # { userId: websocket }
challenges = {}  # { websocket: { "salt": hex, "difficulty": int, "envelope": bytes } }
active_requests = []  # timestamps of requests in the last second for Adaptive PoW

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Mailbox table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mailbox (
            mailbox_id TEXT PRIMARY KEY,
            recipient_hash TEXT,
            packet_id TEXT UNIQUE,
            encrypted_packet BLOB,
            created_at INTEGER,
            expires_at INTEGER,
            retry_counter INTEGER DEFAULT 0,
            delivery_state TEXT DEFAULT 'Pending',
            integrity_hash TEXT
        )
    """)
    
    # DHT Registry table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dht_registry (
            lookup_key TEXT,
            advertisement_data TEXT,
            expires_at INTEGER,
            PRIMARY KEY (lookup_key, advertisement_data)
        )
    """)
    conn.commit()
    conn.close()

# Cleanup daemon: runs every 60 seconds
async def database_cleanup_daemon():
    while True:
        try:
            await asyncio.sleep(60)
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            now = int(time.time())
            
            # Expire mailbox packets
            cursor.execute("UPDATE mailbox SET delivery_state = 'Expired' WHERE expires_at < ? AND delivery_state = 'Pending'", (now,))
            # Delete expired payload bytes to save space
            cursor.execute("UPDATE mailbox SET encrypted_packet = NULL WHERE delivery_state IN ('Expired', 'Delivered') AND encrypted_packet IS NOT NULL")
            
            # Delete expired DHT advertisements (90 mins TTL)
            cursor.execute("DELETE FROM dht_registry WHERE expires_at < ?", (now,))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Cleanup Daemon Error] {str(e)}")

# Get current adaptive PoW difficulty
def get_pow_difficulty():
    global active_requests
    now = time.time()
    # Filter requests older than 1 second
    active_requests = [t for t in active_requests if now - t < 1.0]
    
    rps = len(active_requests)
    if rps < 5:
        return 8
    elif rps < 20:
        return 12
    else:
        return 18

def verify_pow(salt: str, difficulty: int, nonce: str) -> bool:
    hashable = bytes.fromhex(salt) + nonce.encode('utf-8')
    h = hashlib.sha256(hashable).digest()
    leading_zeros = 0
    for byte in h:
        if byte == 0:
            leading_zeros += 8
        else:
            leading_zeros += bin(byte)[2:].zfill(8).index('1')
            break
    return leading_zeros >= difficulty

def decrypt_onion_layer(layer_bytes: bytes, relay_name: str) -> tuple:
    if len(layer_bytes) < 32:
        raise ValueError("Layer envelope too short")
        
    ephemeral_pub_bytes = layer_bytes[:32]
    ciphertext = layer_bytes[32:]
    
    private_key = relay_keys[relay_name]
    ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared_secret = private_key.exchange(ephemeral_pub)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"DCP_ONION_ROUTING_HOP"
    )
    aes_key = hkdf.derive(shared_secret)
    
    aesgcm = AESGCM(aes_key)
    iv = ciphertext[:12]
    enc_data = ciphertext[12:]
    decrypted = aesgcm.decrypt(iv, enc_data, None)
    
    next_hop_len = int.from_bytes(decrypted[:2], byteorder='big')
    next_hop = decrypted[2:2+next_hop_len].decode('utf-8')
    inner_envelope = decrypted[2+next_hop_len:]
    
    return next_hop, inner_envelope

async def handle_onion_routing(envelope_bytes: bytes, ws):
    try:
        print(f"\n[Onion Router] Incoming packet received. Size: {len(envelope_bytes)} bytes")
        
        # Step 1: Decrypt Layer 1 (Relay A)
        next_hop_A, envelope_B = decrypt_onion_layer(envelope_bytes, "A")
        print(f"[Onion Hop 1] Relay A decrypted outer envelope. Next Hop target: {next_hop_A}")
        
        # Step 2: Decrypt Layer 2 (Relay B)
        next_hop_B, envelope_C = decrypt_onion_layer(envelope_B, "B")
        print(f"[Onion Hop 2] Relay B decrypted middle envelope. Next Hop target: {next_hop_B}")
        
        # Step 3: Decrypt Layer 3 (Relay C)
        recipient_id, final_packet = decrypt_onion_layer(envelope_C, "C")
        print(f"[Onion Hop 3] Relay C decrypted inner envelope. Recipient Identity found: {recipient_id}")
        
        # Step 4: Routing Delivery
        if recipient_id in clients:
            recipient_ws = clients[recipient_id]
            print(f"[Onion Delivery] Recipient {recipient_id} online. Streaming payload directly.")
            await recipient_ws.send(json.dumps({
                "type": "onion_packet",
                "envelope": final_packet.hex()
            }))
        else:
            # Store in Database Mailbox (RFC-0004 limits check)
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            
            # Recipient SHA-256 hash
            rec_hash = hashlib.sha256(recipient_id.encode('utf-8')).hexdigest()
            packet_id = hashlib.sha256(final_packet).hexdigest()
            
            # Check Quota: max 500 packets per recipient
            cursor.execute("SELECT count(*) FROM mailbox WHERE recipient_hash = ? AND delivery_state = 'Pending'", (rec_hash,))
            count = cursor.fetchone()[0]
            if count >= 500:
                print(f"[Onion Mailbox] Quota exceeded (500 limit). Dropping oldest packet for recipient {recipient_id}.")
                # Delete oldest packet payload and mark deleted
                cursor.execute("""
                    UPDATE mailbox SET delivery_state = 'Deleted', encrypted_packet = NULL 
                    WHERE rowid = (SELECT min(rowid) FROM mailbox WHERE recipient_hash = ? AND delivery_state = 'Pending')
                """, (rec_hash,))
            
            # Insert new packet
            now = int(time.time())
            expires = now + 24 * 3600 # 24 Hours TTL
            mailbox_id = secrets.token_hex(16)
            
            cursor.execute("""
                INSERT OR IGNORE INTO mailbox (mailbox_id, recipient_hash, packet_id, encrypted_packet, created_at, expires_at, delivery_state, integrity_hash)
                VALUES (?, ?, ?, ?, ?, ?, 'Pending', ?)
            """, (mailbox_id, rec_hash, packet_id, final_packet, now, expires, packet_id))
            
            conn.commit()
            conn.close()
            print(f"[Onion Mailbox] Recipient {recipient_id} offline. Packet cached in SQLite mailbox. Expiring in 24h.")
            
    except Exception as e:
        print(f"[Onion Router Error] Decryption failed: {str(e)}")

async def handler(websocket):
    global active_requests
    remote = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    print(f"\n[Connection opened] {remote}")
    
    try:
        async for message in websocket:
            # Record request timestamp for Adaptive PoW
            active_requests.append(time.time())
            
            data = json.loads(message)
            action = data.get("action")
            
            # Action: Register Identity
            if action == "register":
                userId = data.get("userId")
                clients[userId] = websocket
                print(f"[Register] Registered user ID: {userId} on socket {remote}")
                await websocket.send(json.dumps({
                    "status": "registered",
                    "userId": userId
                }))
                
                # Check Mailbox in SQLite
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                rec_hash = hashlib.sha256(userId.encode('utf-8')).hexdigest()
                now = int(time.time())
                
                cursor.execute("""
                    SELECT packet_id, encrypted_packet FROM mailbox 
                    WHERE recipient_hash = ? AND delivery_state = 'Pending' AND expires_at > ?
                """, (rec_hash, now))
                rows = cursor.fetchall()
                
                if rows:
                    print(f"[Mailbox Delivery] Delivering {len(rows)} stored packets to online recipient {userId}...")
                    for row in rows:
                        pid, packet_bytes = row
                        # Increment retry counter
                        cursor.execute("UPDATE mailbox SET retry_counter = retry_counter + 1 WHERE packet_id = ?", (pid,))
                        await websocket.send(json.dumps({
                            "type": "onion_packet",
                            "envelope": packet_bytes.hex()
                        }))
                conn.commit()
                conn.close()
                            
            # Action: Route Envelope (with adaptive PoW check)
            elif action == "route_onion":
                envelope_hex = data.get("envelope")
                if not envelope_hex:
                    continue
                envelope_bytes = bytes.fromhex(envelope_hex)
                
                # Check challenge
                if websocket not in challenges:
                    difficulty = get_pow_difficulty()
                    salt = secrets.token_hex(16)
                    challenges[websocket] = {
                        "salt": salt,
                        "difficulty": difficulty,
                        "envelope": envelope_bytes
                    }
                    await websocket.send(json.dumps({
                        "status": "pow_challenge",
                        "salt": salt,
                        "difficulty": difficulty
                    }))
                
            # Action: Submit PoW Solution
            elif action == "submit_pow":
                nonce = str(data.get("nonce"))
                challenge = challenges.get(websocket)
                if not challenge:
                    print(f"[PoW Error] Client {remote} submitted solution without active challenge.")
                    await websocket.send(json.dumps({
                        "status": "pow_error",
                        "message": "No active Proof of Work challenge for this session"
                    }))
                    continue
                    
                if verify_pow(challenge["salt"], challenge["difficulty"], nonce):
                    envelope = challenge["envelope"]
                    del challenges[websocket]
                    
                    # Validate first layer decryption synchronously
                    try:
                        decrypt_onion_layer(envelope, "A")
                    except Exception as e:
                        print(f"[Onion Reject] Malformed envelope from {remote}: {str(e)}")
                        await websocket.send(json.dumps({
                            "status": "error",
                            "code": "ERROR_INVALID_ENVELOPE",
                            "message": f"Malformed onion envelope: {str(e)}"
                        }))
                        continue
                    
                    asyncio.create_task(handle_onion_routing(envelope, websocket))
                else:
                    print(f"[PoW Reject] Invalid solution from client {remote}")
                    await websocket.send(json.dumps({
                        "status": "pow_error",
                        "message": "Invalid Proof of Work solution"
                    }))
                    del challenges[websocket]
            
            # Action: Submit Delivery ACK (RFC-0004 v2)
            elif action == "submit_ack":
                ack_payload = data.get("payload")
                signature_hex = data.get("signature")
                
                if not ack_payload or not signature_hex:
                    continue
                
                packet_id = ack_payload.get("packet_id")
                recipient_device_id = ack_payload.get("recipient_device_id")
                timestamp = ack_payload.get("timestamp")
                relay_session_id = ack_payload.get("relay_session_id")
                
                # Verify Timestamp (Replay protection: max 5 mins skew)
                now = int(time.time() * 1000)
                if abs(now - timestamp) > 5 * 60 * 1000:
                    print(f"[ACK Reject] Replayed ACK: Clock skew too large ({abs(now-timestamp)}ms).")
                    continue
                
                # Verify Signature using Ed25519
                try:
                    payload_bytes = json.dumps(ack_payload, separators=(',', ':')).encode('utf-8')
                    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(recipient_device_id))
                    pub_key.verify(bytes.fromhex(signature_hex), payload_bytes)
                    
                    # Valid Signature: Purge packet from mailbox
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    
                    # Check if packet exists and is Pending
                    cursor.execute("SELECT delivery_state FROM mailbox WHERE packet_id = ?", (packet_id,))
                    row = cursor.fetchone()
                    if row and row[0] == 'Pending':
                        cursor.execute("""
                            UPDATE mailbox SET delivery_state = 'Delivered', encrypted_packet = NULL 
                            WHERE packet_id = ?
                        """, (packet_id,))
                        conn.commit()
                        print(f"[Mailbox ACK] Packet {packet_id} delivered and cleared successfully.")
                    else:
                        print(f"[Mailbox ACK] Duplicate or processed ACK received for {packet_id}. Ignoring.")
                        
                    conn.close()
                except Exception as e:
                    print(f"[ACK Reject] Cryptographic verification failed: {str(e)}")

            # Action: DHT Advertisement Publish (RFC-0010)
            elif action == "dht_publish":
                lookup_key = data.get("lookup_key")
                advertisement = data.get("advertisement")
                if lookup_key and advertisement:
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    expires = int(time.time()) + 90 * 60 # 90 minutes TTL
                    cursor.execute("""
                        INSERT OR REPLACE INTO dht_registry (lookup_key, advertisement_data, expires_at)
                        VALUES (?, ?, ?)
                    """, (lookup_key, json.dumps(advertisement), expires))
                    conn.commit()
                    conn.close()
                    print(f"[DHT Register] Saved advertisement for lookup key {lookup_key[:16]}... (expires in 90m)")

            # Action: DHT Lookup query (RFC-0010)
            elif action == "dht_lookup":
                lookup_key = data.get("lookup_key")
                if lookup_key:
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    now = int(time.time())
                    cursor.execute("""
                        SELECT advertisement_data FROM dht_registry 
                        WHERE lookup_key = ? AND expires_at > ?
                    """, (lookup_key, now))
                    rows = cursor.fetchall()
                    conn.close()
                    
                    results = [json.loads(r[0]) for r in rows]
                    await websocket.send(json.dumps({
                        "type": "dht_lookup_result",
                        "lookup_key": lookup_key,
                        "results": results
                    }))
                    print(f"[DHT Lookup] Resolved key {lookup_key[:16]}... found {len(results)} matches.")

    except Exception as e:
        print(f"[Error] Socket connection error: {str(e)}")
    finally:
        deregistered = None
        for uid, ws in list(clients.items()):
            if ws == websocket:
                deregistered = uid
                del clients[uid]
                break
        if websocket in challenges:
            del challenges[websocket]
        print(f"[Connection closed] {remote} (User: {deregistered})")

async def main():
    init_db()
    # Start cleanup daemon task
    asyncio.create_task(database_cleanup_daemon())
    async with serve(handler, HOST, PORT):
        print(f"DCP Relay Node running on ws://{HOST}:{PORT}")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
