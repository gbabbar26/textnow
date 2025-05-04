# === chat_gui.py ===
import tkinter as tk
from tkinter import scrolledtext
import socket, threading, json, base64, os, sys, time, shutil, datetime
from crypto_utils import *

HOST = '127.0.0.1'
PORT = 65432
DEBUG = True  # Enable detailed crypto logs for demo
SAVE_MESSAGES = True  # Automatically save incoming payloads for testing

class ChatApp:
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.root.title(f"Secure Chat - {username}")

        self.text_area = scrolledtext.ScrolledText(root, state='disabled', width=60, height=25)
        self.text_area.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

        self.entry = tk.Entry(root, width=50)
        self.entry.grid(row=1, column=0, padx=10)
        self.entry.bind('<Return>', self.send_message)

        self.send_btn = tk.Button(root, text="Send", command=self.send_message)
        self.send_btn.grid(row=1, column=1, padx=5)

        self.clear_btn = tk.Button(root, text="Clear Logs", command=self.clear_logs)
        self.clear_btn.grid(row=1, column=2, padx=5)

        # Crypto setup
        self.peer_public_key = None
        self.shared_key = None
        self.sent_own_key = False

        if not os.path.exists(f"keys/{username}_private.pem"):
            private_key, public_key = generate_key_pair()
            save_private_key(private_key, username)
            save_public_key(public_key, username)
        self.private_key = load_private_key(username)
        self.public_key = load_public_key_file(username)

        if DEBUG:
            print(f"[DEBUG] {username} Public Key: {serialize_public_key(self.public_key)[:60]}...")

        # Socket setup
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.sock.sendall((json.dumps({"public_key": serialize_public_key(self.public_key)}) + "\n").encode())

    def display_message(self, msg, tag=None):
        self.text_area.configure(state='normal')
        self.text_area.insert(tk.END, msg + '\n')
        self.text_area.configure(state='disabled')
        self.text_area.yview(tk.END)

    def clear_logs(self):
        if os.path.exists("payloads"):
            shutil.rmtree("payloads")
        os.makedirs("payloads", exist_ok=True)
        self.display_message("[System]: Payload logs cleared.")

    def receive_messages(self):
        buffer = ""
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    continue
                buffer += data.decode()
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    message_data = json.loads(line)

                    if SAVE_MESSAGES:
                        formatted_time = datetime.datetime.now().strftime("%m-%d-%y-%H-%M-%S")
                        filename = f"payloads/{self.username}_recv_{formatted_time}.json"
                        os.makedirs("payloads", exist_ok=True)
                        with open(filename, 'w') as f:
                            json.dump(message_data, f, indent=2)

                    if 'public_key' in message_data:
                        self.peer_public_key = load_public_key(message_data['public_key'])
                        self.shared_key = derive_shared_key(self.private_key, self.peer_public_key)
                        self.display_message("[System]: Secure channel established.")
                        if DEBUG:
                            print(f"[DEBUG] Derived shared AES key: {self.shared_key.hex()}")
                        if not self.sent_own_key:
                            self.sock.sendall((json.dumps({"public_key": serialize_public_key(self.public_key)}) + "\n").encode())
                            self.sent_own_key = True
                        continue

                    if self.shared_key is None:
                        self.display_message("[!] Shared key not established.")
                        continue

                    if is_replay(message_data['nonce'], message_data['timestamp']):
                        self.display_message("[!] Replayed message detected and blocked.")
                        continue

                    plaintext = decrypt_message(self.shared_key, message_data['ciphertext'].encode())
                    signature = base64.b64decode(message_data['signature'])
                    if verify_signature(self.peer_public_key, plaintext, signature):
                        sender = message_data['sender']
                        self.display_message(f"[{sender}]: {plaintext.decode()}")
                        if DEBUG:
                            print(f"[DEBUG] Received encrypted: {message_data['ciphertext'][:40]}...")
                            print(f"[DEBUG] Verified signature: {message_data['signature'][:40]}...")
                            print(f"[DEBUG] Decrypted message: {plaintext.decode()}")
                    else:
                        self.display_message("[!] Signature verification failed.")
            except Exception as e:
                self.display_message(f"[!] Error: {e}")
                break

    def send_message(self, event=None):
        msg = self.entry.get()
        if not msg or self.shared_key is None:
            return
        self.entry.delete(0, tk.END)
        msg_bytes = msg.encode()
        ciphertext = encrypt_message(self.shared_key, msg_bytes).decode()
        signature = base64.b64encode(sign_message(self.private_key, msg_bytes)).decode()
        nonce, timestamp = get_nonce_timestamp()

        if DEBUG:
            print(f"[DEBUG] Sending message: {msg}")
            print(f"[DEBUG] Ciphertext: {ciphertext[:40]}...")
            print(f"[DEBUG] Signature: {signature[:40]}...")

        payload = json.dumps({
            'sender': self.username,
            'ciphertext': ciphertext,
            'signature': signature,
            'nonce': nonce,
            'timestamp': timestamp
        }) + "\n"
        self.sock.sendall(payload.encode())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python chat_gui.py [your_name]")
        sys.exit(1)
    name = sys.argv[1]
    root = tk.Tk()
    app = ChatApp(root, name)
    root.mainloop()
