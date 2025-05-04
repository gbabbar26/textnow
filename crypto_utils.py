from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os, base64, time, json

# Persistent key storage
KEY_DIR = "keys"
if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR)

def save_private_key(private_key, username):
    with open(f"{KEY_DIR}/{username}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_public_key(public_key, username):
    with open(f"{KEY_DIR}/{username}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(username):
    with open(f"{KEY_DIR}/{username}_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key_file(username):
    with open(f"{KEY_DIR}/{username}_public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

# Generate ECDSA key pair
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize/Deserialize public keys
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def load_public_key(pem):
    return serialization.load_pem_public_key(pem.encode(), backend=default_backend())

# Sign/Verify

def sign_message(private_key, message):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

# Diffie-Hellman key agreement to derive AES key
def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

# AES-GCM encrypt/decrypt
def encrypt_message(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct)

def decrypt_message(key, ciphertext):
    data = base64.b64decode(ciphertext)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# Replay protection
def get_nonce_timestamp():
    return os.urandom(8).hex(), int(time.time())

def is_replay(nonce, timestamp, cache_file="replay_cache.json"):
    try:
        with open(cache_file, 'r') as f:
            cache = json.load(f)
    except:
        cache = {}
    now = int(time.time())
    if nonce in cache and abs(now - cache[nonce]) < 300:
        return True
    cache[nonce] = timestamp
    with open(cache_file, 'w') as f:
        json.dump(cache, f)
    return False


# === client.py ===
import socket, threading, base64, json, sys, os
from crypto_utils import *

HOST = '127.0.0.1'
PORT = 65432

if len(sys.argv) < 2:
    print("Usage: python client.py [your_name]")
    sys.exit(1)
username = sys.argv[1]

# Load or generate keys
if os.path.exists(f"keys/{username}_private.pem"):
    private_key = load_private_key(username)
    public_key = load_public_key_file(username)
else:
    private_key, public_key = generate_key_pair()
    save_private_key(private_key, username)
    save_public_key(public_key, username)

peer_public_key = None
shared_key = None
print(f"[+] {username}: Ready. Type 'exit' to quit.\n")

def receive_messages(sock):
    global peer_public_key, shared_key
    while True:
        try:
            data = sock.recv(4096)
            if data:
                message_data = json.loads(data.decode())
                if 'public_key' in message_data:
                    peer_public_key = load_public_key(message_data['public_key'])
                    shared_key = derive_shared_key(private_key, peer_public_key)
                    print(f"[System]: Received peer key and derived shared AES key.")
                    continue

                if shared_key is None:
                    print("[!] Shared key not established yet.")
                    continue

                if is_replay(message_data['nonce'], message_data['timestamp']):
                    print("[!] Replayed message detected.")
                    continue

                plaintext = decrypt_message(shared_key, message_data['ciphertext'].encode())
                signature = base64.b64decode(message_data['signature'])
                if verify_signature(peer_public_key, plaintext, signature):
                    print(f"[{message_data['sender']}]: {plaintext.decode()}")
                else:
                    print("[!] Signature verification failed.")
        except Exception as e:
            print(f"[!] Error: {e}")
            break

def start_chat():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        threading.Thread(target=receive_messages, args=(s,), daemon=True).start()
        s.sendall(json.dumps({"public_key": serialize_public_key(public_key)}).encode())

        while True:
            msg = input(f"{username}: ")
            if msg.lower() == 'exit':
                break
            if shared_key is None:
                print("[!] Cannot send: Shared key not ready.")
                continue
            msg_bytes = msg.encode()
            ciphertext = encrypt_message(shared_key, msg_bytes).decode()
            signature = base64.b64encode(sign_message(private_key, msg_bytes)).decode()
            nonce, timestamp = get_nonce_timestamp()

            payload = json.dumps({
                'sender': username,
                'ciphertext': ciphertext,
                'signature': signature,
                'nonce': nonce,
                'timestamp': timestamp
            })
            s.sendall(payload.encode())

if __name__ == "__main__":
    start_chat()

