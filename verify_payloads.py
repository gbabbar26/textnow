import tkinter as tk
from tkinter import filedialog, messagebox
import json, base64, sys
from crypto_utils import (
    load_private_key, load_public_key_file,
    decrypt_message, verify_signature, derive_shared_key
)

def run_cli():
    if len(sys.argv) < 3:
        print("Usage: python verify_tool.py cli [payload_file.json]")
        return

    payload_file = sys.argv[2]
    with open(payload_file, 'r') as f:
        payload = json.load(f)

    sender = payload['sender']
    receiver = input("Enter your username (receiver): ")

    priv_key = load_private_key(receiver)
    pub_key = load_public_key_file(sender)
    shared_key = derive_shared_key(priv_key, pub_key)

    decrypted = decrypt_message(shared_key, payload['ciphertext'].encode())
    print(f"[DECRYPTED] {decrypted.decode()}")

    signature = base64.b64decode(payload['signature'])
    if verify_signature(pub_key, decrypted, signature):
        print("[VERIFIED] Signature is valid ✅")
    else:
        print("[FAILED] Signature is invalid ❌")

def run_gui():
    class PayloadVerifierGUI:
        def __init__(self, root):
            self.root = root
            self.root.title("Payload Verifier - Secure Chat")

            self.label_user = tk.Label(root, text="Your Username:")
            self.label_user.pack()

            self.entry_user = tk.Entry(root, width=30)
            self.entry_user.pack()

            self.button_load = tk.Button(root, text="Load Payload", command=self.load_payload)
            self.button_load.pack(pady=10)

            self.text_output = tk.Text(root, height=20, width=80, state='disabled')
            self.text_output.pack(pady=10)

        def log(self, message):
            self.text_output.config(state='normal')
            self.text_output.insert(tk.END, message + '\n')
            self.text_output.config(state='disabled')
            self.text_output.see(tk.END)

        def load_payload(self):
            filepath = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
            if not filepath:
                return
            username = self.entry_user.get().strip()
            if not username:
                messagebox.showerror("Input Error", "Please enter your username (receiver).")
                return
            try:
                with open(filepath, 'r') as f:
                    payload = json.load(f)
                sender = payload['sender']
                self.log(f"[INFO] Verifying message from '{sender}'...")
                priv_key = load_private_key(username)
                pub_key = load_public_key_file(sender)
                shared_key = derive_shared_key(priv_key, pub_key)
                decrypted = decrypt_message(shared_key, payload['ciphertext'].encode())
                self.log(f"[DECRYPTED] {decrypted.decode()}")
                signature = base64.b64decode(payload['signature'])
                if verify_signature(pub_key, decrypted, signature):
                    self.log("[VERIFIED] Signature is valid ✅")
                else:
                    self.log("[FAILED] Signature is invalid ❌")
            except Exception as e:
                self.log(f"[ERROR] {e}")

    root = tk.Tk()
    app = PayloadVerifierGUI(root)
    root.mainloop()

# Entry point
if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "cli":
        run_cli()
    else:
        run_gui()
