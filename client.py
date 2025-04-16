# === client.py ===
import socket, threading, base64, json, sys, os
from crypto_utils import *

HOST = '127.0.0.1'
PORT = 65432

if len(sys.argv) < 2:
    print("Usage: python client.py [your_name]")
    sys.exit(1)
username = sys.argv[1]

# Attack simulation flags (set True to test)
ENABLE_REPLAY_ATTACK = True
ENABLE_TAMPERING_ATTACK = True
ENABLE_SPOOFING_ATTACK = True

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
sent_own_key = False
print(f"[+] {username}: Ready. Type 'exit' to quit.\n")

def receive_messages(sock):
    global peer_public_key, shared_key, sent_own_key
    buffer = ""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                continue
            buffer += data.decode()
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                message_data = json.loads(line)

                if 'public_key' in message_data:
                    peer_public_key = load_public_key(message_data['public_key'])
                    shared_key = derive_shared_key(private_key, peer_public_key)
                    print(f"[System]: Received peer key and derived shared AES key.")
                    if not sent_own_key:
                        sock.sendall((json.dumps({"public_key": serialize_public_key(public_key)}) + "\n").encode())
                        sent_own_key = True
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
        s.sendall((json.dumps({"public_key": serialize_public_key(public_key)}) + "\n").encode())

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
            }) + "\n"
            s.sendall(payload.encode())

            # === REPLAY ATTACK ===
            if ENABLE_REPLAY_ATTACK and username == "Alice":
                print("[*] Replaying the same message...")
                s.sendall(payload.encode())

            # === TAMPERING ATTACK ===
            if ENABLE_TAMPERING_ATTACK and username == "Alice":
                tampered_payload = json.loads(payload)
                tampered_payload['ciphertext'] = tampered_payload['ciphertext'][:-4] + "AAAA"
                print("[*] Sending tampered message...")
                s.sendall((json.dumps(tampered_payload) + "\n").encode())

            # === SPOOFING ATTACK ===
            if ENABLE_SPOOFING_ATTACK and username == "Alice":
                print("[*] Sending spoofed message...")
                fake_signature = base64.b64encode(os.urandom(64)).decode()
                spoof_payload = {
                    'sender': 'Mallory',
                    'ciphertext': ciphertext,
                    'signature': fake_signature,
                    'nonce': nonce + '_spoof',
                    'timestamp': timestamp
                }
                s.sendall((json.dumps(spoof_payload) + "\n").encode())

if __name__ == "__main__":
    start_chat()


# === Usage ===
# In two terminals:
# python server.py
# python client.py Alice
# python client.py Bob
