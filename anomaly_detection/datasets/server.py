import socket
import threading

SERVER_IP = '127.0.0.1'
SERVER_PORT = 65432

def handle_client(conn, addr):
    print(f"[SERVER] Connected by {addr}")
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[SERVER] Received: {data.decode()}")
            conn.sendall(data)  # Echo back
        except ConnectionResetError:
            break
    conn.close()
    print(f"[SERVER] Connection closed: {addr}")

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((SERVER_IP, SERVER_PORT))
    s.listen()
    print(f"[SERVER] Listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        conn, addr = s.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[SERVER] Active Connections: {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()
