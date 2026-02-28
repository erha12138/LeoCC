import socket
import threading
import sys

# === PEP 配置 ===
PEP_IP = '0.0.0.0'
PEP_PORT = 9999  # PEP 监听端口 (发送端 连接这里)

# 从命令行参数获取 Client (小黑屋) 的 IP
if len(sys.argv) < 2:
    print("Usage: python3 pep_proxy.py <CLIENT_IP_INSIDE_MAHIMAHI>")
    sys.exit(1)

DEST_IP = sys.argv[1]
DEST_PORT = 5201 # iperf3 server 的默认端口

def forward(source, destination, direction):
    """ 数据转发逻辑 """
    try:
        while True:
            # 增大 buffer 以提高转发效率
            data = source.recv(32768)
            if not data: break
            destination.sendall(data)
    except:
        pass # 连接断开处理
    finally:
        source.close()
        destination.close()

def start_pep():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((PEP_IP, PEP_PORT))
    server_socket.listen(5)
    
    print(f"[*] PEP Running: Listening on {PEP_PORT}, Forwarding to {DEST_IP}:{DEST_PORT}")
    print(f"[*] Ready. Please start the Sender now.")

    while True:
        try:
            sender_conn, addr = server_socket.accept()
            print(f"[*] Connection from Sender: {addr}")

            # 建立到内部 Client 的连接
            try:
                client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_conn.connect((DEST_IP, DEST_PORT))
            except Exception as e:
                print(f"[!] Cannot connect to Client inside Mahimahi: {e}")
                sender_conn.close()
                continue

            # 开启双向转发
            # Thread 1: Server -> PEP -> Client (数据流)
            threading.Thread(target=forward, args=(sender_conn, client_conn, "downlink")).start()
            # Thread 2: Client -> PEP -> Server (ACK流)
            threading.Thread(target=forward, args=(client_conn, sender_conn, "uplink")).start()

        except KeyboardInterrupt:
            break

if __name__ == '__main__':
    start_pep()