import socket
import threading
import sys
import time
from collections import deque

# === PEP 配置 ===
PEP_IP = '0.0.0.0'
PEP_PORT = 9999  # PEP 监听端口 (发送端 连接这里)

# === ACK 欺骗（Split-TCP）配置 ===
# 说明：
# - inner 为发送端（iperf3 client），连接到 PEP:9999
# - outer 为接收端（iperf3 server），PEP 连接到 <DEST_IP>:5201
# - 本实现采用 Split-TCP：PEP 终止两段 TCP。
#   对 inner 来说，PEP 的 TCP 栈会“提前 ACK”它已接收进缓冲区的数据（即 ACK 欺骗效果）。
# - PEP 再把数据按设定速率从缓冲区转发到 outer，以模拟/控制下游链路。

DEFAULT_DEST_PORT = 5201
CHUNK_SIZE = 32 * 1024  # 单次 recv/send 的块大小

# socket 缓冲区（OS 级别）；通常会被内核翻倍，这里给一个“合理偏大”的值
SOCK_RCVBUF = 4 * 1024 * 1024
SOCK_SNDBUF = 4 * 1024 * 1024

# 应用层缓冲区（PEP 内部排队）；越大越能“更久地提前 ACK”
APP_BUFFER_BYTES = 32 * 1024 * 1024

# inner->outer 转发限速（字节/秒）。0 表示不限速
FORWARD_RATE_BPS = 20 * 1024 * 1024  # 20 MB/s 约等于 160 Mbps


MAX_LISTEN_CONNECTIONS = 5

def _parse_args():
    if len(sys.argv) < 2:
        print(
            "Usage: python3 pepproxy.py <DEST_IP> [DEST_PORT] [RATE_MBPS] [APP_BUF_MB]\n"
            "  DEST_IP: outer(接收端) iperf3 server 的 IP（例如 100.64.0.1）\n"
            "  DEST_PORT: 默认 5201\n"
            "  RATE_MBPS: inner->outer 转发速率上限，默认 160 (Mbps)，0 表示不限速\n"
            "  APP_BUF_MB: PEP 应用层缓冲区大小，默认 32 (MB)"
        )
        sys.exit(1)

    dest_ip = sys.argv[1]
    dest_port = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_DEST_PORT
    rate_mbps = float(sys.argv[3]) if len(sys.argv) >= 4 else 160.0
    app_buf_mb = int(sys.argv[4]) if len(sys.argv) >= 5 else 32

    rate_bps = 0 if rate_mbps <= 0 else int(rate_mbps * 1024 * 1024 / 8)
    app_buf_bytes = max(1 * 1024 * 1024, app_buf_mb * 1024 * 1024)
    return dest_ip, dest_port, rate_bps, app_buf_bytes


class ByteQueue:
    """按“总字节数”限额的线程安全缓冲队列（producer/consumer）。"""

    def __init__(self, max_bytes: int):
        self._max = max_bytes
        self._cur = 0
        self._q = deque()
        self._cv = threading.Condition()
        self._closed = False

    def close(self):
        with self._cv:
            self._closed = True
            self._cv.notify_all()

    def put(self, b: bytes):
        if not b:
            return
        with self._cv:
            while not self._closed and self._cur + len(b) > self._max:
                self._cv.wait(timeout=0.2)
            if self._closed:
                return
            self._q.append(b)
            self._cur += len(b)
            self._cv.notify_all()

    def get(self):
        with self._cv:
            while not self._closed and not self._q:
                self._cv.wait(timeout=0.2)
            if self._q:
                b = self._q.popleft()
                self._cur -= len(b)
                self._cv.notify_all()
                return b
            return None


class TokenBucket:
    """简单令牌桶限速（字节/秒）。rate=0 表示不限速。"""

    def __init__(self, rate_bps: int, burst_bytes: int):
        self.rate = max(0, int(rate_bps))
        self.capacity = max(1, int(burst_bytes))
        self.tokens = float(self.capacity)
        self.t = time.monotonic()

    def consume(self, nbytes: int):
        if self.rate <= 0:
            return
        need = float(nbytes)
        while True:
            now = time.monotonic()
            dt = now - self.t
            self.t = now
            self.tokens = min(self.capacity, self.tokens + dt * self.rate)
            if self.tokens >= need:
                self.tokens -= need
                return
            # 不足则睡眠补令牌
            short = (need - self.tokens) / self.rate
            time.sleep(min(0.05, max(0.001, short)))


def _tune_socket(s: socket.socket):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_RCVBUF)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_SNDBUF)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def _reader(sock_in: socket.socket, q: ByteQueue):
    try:
        while True:
            data = sock_in.recv(CHUNK_SIZE)
            if not data:
                break
            q.put(data)
    except Exception:
        pass
    finally:
        q.close()
        try:
            sock_in.shutdown(socket.SHUT_RD)
        except Exception:
            pass
        try:
            sock_in.close()
        except Exception:
            pass


def _writer(sock_out: socket.socket, q: ByteQueue, rate_bps: int):
    bucket = TokenBucket(rate_bps=rate_bps, burst_bytes=256 * 1024)
    try:
        while True:
            data = q.get()
            if data is None:
                break
            bucket.consume(len(data))
            sock_out.sendall(data)
    except Exception:
        pass
    finally:
        q.close()
        try:
            sock_out.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        try:
            sock_out.close()
        except Exception:
            pass


def _pipe_bidirectional(inner_conn: socket.socket, outer_conn: socket.socket, rate_bps: int, app_buf_bytes: int):
    """
    inner -> outer: 采用 ByteQueue + 限速（ACK 欺骗的关键在于：inner 的 TCP 会被 PEP 提前 ACK）
    outer -> inner: 直接透传（通常是 iperf3 server 的控制/统计输出）
    """
    q = ByteQueue(max_bytes=app_buf_bytes)
    t1 = threading.Thread(target=_reader, args=(inner_conn, q), daemon=True)
    t2 = threading.Thread(target=_writer, args=(outer_conn, q, rate_bps), daemon=True)
    t1.start()
    t2.start()

    # 反向流量：outer -> inner
    def _reverse():
        try:
            while True:
                data = outer_conn.recv(CHUNK_SIZE)
                if not data:
                    break
                inner_conn.sendall(data)
        except Exception:
            pass
        finally:
            q.close()
            try:
                inner_conn.close()
            except Exception:
                pass
            try:
                outer_conn.close()
            except Exception:
                pass

    threading.Thread(target=_reverse, daemon=True).start()

def start_pep():
    dest_ip, dest_port, rate_bps, app_buf_bytes = _parse_args()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((PEP_IP, PEP_PORT))
    server_socket.listen(MAX_LISTEN_CONNECTIONS)
    
    print(f"[*] PEP Running (ACK spoofing via Split-TCP)")
    print(f"[*] Listening on {PEP_IP}:{PEP_PORT} (inner -> PEP)")
    print(f"[*] Connecting to {dest_ip}:{dest_port} (PEP -> outer)")
    print(f"[*] Config: CHUNK={CHUNK_SIZE}B, OS_RCVBUF={SOCK_RCVBUF}B, OS_SNDBUF={SOCK_SNDBUF}B")
    print(f"[*] Config: APP_BUFFER={app_buf_bytes}B, FORWARD_RATE={rate_bps if rate_bps>0 else 'unlimited'} B/s")
    print(f"[*] Ready. Please start the Sender now.")

    while True:
        try:
            sender_conn, addr = server_socket.accept()
            _tune_socket(sender_conn)
            print(f"[*] Connection from inner(Sender): {addr}")

            # 建立到 outer(接收端) 的连接
            try:
                client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                _tune_socket(client_conn)
                client_conn.connect((dest_ip, dest_port))
            except Exception as e:
                print(f"[!] Cannot connect to outer: {e}")
                sender_conn.close()
                continue

            _pipe_bidirectional(sender_conn, client_conn, rate_bps=rate_bps, app_buf_bytes=app_buf_bytes)

        except KeyboardInterrupt:
            break

if __name__ == '__main__':
    start_pep()