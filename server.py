
import socket, threading

HOST = '127.0.0.1'
PORT = 65432
clients = []

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    clients.append(conn)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            for client in clients:
                if client != conn:
                    client.sendall(data)
    except:
        pass
    finally:
        print(f"[-] Connection closed from {addr}")
        clients.remove(conn)
        conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Chat server started on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
