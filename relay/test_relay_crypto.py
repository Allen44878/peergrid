import os
import secrets
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def test_onion_peeling():
    print("Running Python Relay Cryptography Unit Tests...")
    
    # 1. Generate keys
    relay_priv = x25519.X25519PrivateKey.generate()
    relay_pub = relay_priv.public_key()
    
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes_raw()
    
    # 2. Derive Shared Secret (DH)
    shared_secret = ephemeral_priv.exchange(relay_pub)
    
    # 3. Derive Key (HKDF)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"DCP_ONION_ROUTING_HOP"
    )
    aes_key = hkdf.derive(shared_secret)
    
    # 4. Construct Plaintext Hop Envelope
    next_hop = "RelayB_WS_Address"
    next_hop_bytes = next_hop.encode('utf-8')
    next_hop_len = len(next_hop_bytes).to_bytes(2, byteorder='big')
    inner_payload = b"SECRET_BINARY_PACKET_PAYLOAD"
    
    unencrypted = next_hop_len + next_hop_bytes + inner_payload
    
    # 5. Encrypt (AES-GCM)
    aesgcm = AESGCM(aes_key)
    iv = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(iv, unencrypted, None)
    
    # 6. Package Layer [Ephem Pub (32B)] [IV (12B)] [Ciphertext (Var)]
    layer_bytes = ephemeral_pub_bytes + iv + ciphertext
    
    print(f"Constructed test layer size: {len(layer_bytes)} bytes")
    
    # ------------------ PEELING TEST (SIMULATE RELAY DECRYPTION) ------------------
    peeled_ephem_pub_bytes = layer_bytes[:32]
    peeled_ciphertext = layer_bytes[32:]
    
    # Compute same shared secret from relay's perspective
    peeled_ephem_pub = x25519.X25519PublicKey.from_public_bytes(peeled_ephem_pub_bytes)
    peeled_shared_secret = relay_priv.exchange(peeled_ephem_pub)
    
    assert shared_secret == peeled_shared_secret, "Shared secrets do not match!"
    
    # Derive same AES key
    peeled_hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"DCP_ONION_ROUTING_HOP"
    )
    peeled_aes_key = peeled_hkdf.derive(peeled_shared_secret)
    
    assert aes_key == peeled_aes_key, "Derived AES keys do not match!"
    
    # Decrypt AES-GCM
    peeled_aesgcm = AESGCM(peeled_aes_key)
    peeled_iv = peeled_ciphertext[:12]
    peeled_enc_data = peeled_ciphertext[12:]
    
    decrypted = peeled_aesgcm.decrypt(peeled_iv, peeled_enc_data, None)
    
    # Parse Envelope
    peeled_hop_len = int.from_bytes(decrypted[:2], byteorder='big')
    peeled_hop = decrypted[2:2+peeled_hop_len].decode('utf-8')
    peeled_payload = decrypted[2+peeled_hop_len:]
    
    print("Peeled Hop Target:", peeled_hop)
    print("Peeled Payload:", peeled_payload)
    
    assert peeled_hop == next_hop, "Hop address mismatch!"
    assert peeled_payload == inner_payload, "Payload data mismatch!"
    print("SUCCESS: Cryptographic onion routing math verified successfully!\n")

if __name__ == "__main__":
    test_onion_peeling()
