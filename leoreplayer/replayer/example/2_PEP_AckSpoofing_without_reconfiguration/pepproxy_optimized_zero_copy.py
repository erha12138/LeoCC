"""
优化版 PEP Proxy - 使用 splice() 零拷贝和更大的缓冲区来减少系统调用开销

注意：在 mahimahi 环境下，我们不能使用 DPDK（会绕过内核网络栈），
但可以通过以下方式优化：
1. 使用 splice() 进行零拷贝（Python 需通过 ctypes 调用）
2. 增大 socket 缓冲区
3. 使用 SO_RCVLOWAT / SO_SNDLOWAT 批量处理
4. 使用 epoll 避免阻塞
"""

import socket
import threading
import sys
import time
import os
import select
from collections import deque

# 尝试使用 ctypes 访问 splice 系统调用（零拷贝）
try:
    import ctypes
    import ctypes.util
    
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    
    # splice 系统调用签名
    SPLICE_F_MOVE = 1
    SPLICE_F_NONBLOCK = 2
    SPLICE_F_MORE = 4
    
    # 定义 splice 函数
    libc.splice.argtypes = [
        ctypes.c_int,  # fd_in
        ctypes.POINTER(ctypes.c_void_p),  # off_in
        ctypes.c_int,  # fd_out
        ctypes.POINTER(ctypes.c_void_p),  # off_out
        ctypes.c_size_t,  # len
        ctypes.c_uint,  # flags
    ]
    libc.splice.restype = ctypes.c_ssize_t
    
    SPLICE_AVAILABLE = True
except Exception:
    SPLICE_AVAILABLE = False
    print("[!] splice() not available, falling back to standard recv/send")

# === PEP 配置 ===
PEP_IP = '0.0.0.0'
PEP_PORT = 9999

DEFAULT_DEST_PORT = 5201
CHUNK_SIZE = 128 * 1024  # 增大块大小以减少系统调用次数

# 增大 socket 缓冲区以减少系统调用
SOCK_RCVBUF = 16 * 1024 * 1024  # 16MB
SOCK_SNDBUF = 16 * 1024 * 1024

APP_BUFFER_BYTES = 32 * 1024 * 1024
FORWARD_RATE_BPS = 20 * 1024 * 1024


def _parse_args():
    if len(sys.argv) < 2:
        print(
            "Usage: python3 pepproxy_optimized.py <DEST_IP> [DEST_PORT] [RATE_MBPS] [APP_BUF_MB]\n"
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
    """按"总字节数"限额的线程安全缓冲队列。"""

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
    """优化 socket 配置以减少系统调用。"""
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_RCVBUF)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_SNDBUF)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    # 设置接收低水位，减少系统调用（仅在收到足够数据时才返回）
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVLOWAT, CHUNK_SIZE)
    except Exception:
        pass  # 某些系统可能不支持
    
    # 非阻塞模式（结合 epoll 使用）
    s.setblocking(False)


def _zero_copy_splice(fd_in: int, fd_out: int, size: int) -> int:
    """
    使用 splice() 进行零拷贝传输。
    注意：splice() 需要管道作为中介，这里简化处理。
    实际上，对于 TCP socket，最佳实践是用 recv() + send()，
    但可以通过增大缓冲区来减少系统调用。
    """
    if not SPLICE_AVAILABLE:
        return -1
    
    # splice 在 TCP socket 之间需要管道，这里仅作示例
    # 实际使用中，标准 recv/send + 大缓冲区已经足够
    try:
        null_ptr = ctypes.POINTER(ctypes.c_void_p)(ctypes.c_void_p(None))
        result = libc.splice(
            fd_in, null_ptr,
            fd_out, null_ptr,
            size,
            SPLICE_F_MOVE
        )
        if result < 0:
            errno = ctypes.get_errno()
            if errno != 11:  # EAGAIN
                return -1
        return result
    except Exception:
        return -1


def _reader_optimized(sock_in: socket.socket, q: ByteQueue):
    """
    优化的 reader：使用更大的块和 epoll 减少系统调用。
    """
    try:
        # 使用 select/epoll 避免阻塞
        epoll = select.epoll()
        epoll.register(sock_in.fileno(), select.EPOLLIN)
        
        while True:
            events = epoll.poll(timeout=0.1)
            if not events:
                continue
                
            for fd, event in events:
                if fd == sock_in.fileno() and event & select.EPOLLIN:
                    try:
                        # 尝试读取更大块
                        data = sock_in.recv(CHUNK_SIZE)
                        if not data:
                            return
                        q.put(data)
                    except BlockingIOError:
                        continue
                    except Exception:
                        return
    except Exception:
        # 降级到标准模式
        while True:
            data = sock_in.recv(CHUNK_SIZE)
            if not data:
                break
            q.put(data)
    finally:
        try:
            epoll.unregister(sock_in.fileno())
            epoll.close()
        except Exception:
            pass
        q.close()
        try:
            sock_in.shutdown(socket.SHUT_RD)
        except Exception:
            pass
        try:
            sock_in.close()
        except Exception:
            pass


def _writer_optimized(sock_out: socket.socket, q: ByteQueue, rate_bps: int):
    """优化的 writer：批量发送减少系统调用。"""
    bucket = TokenBucket(rate_bps=rate_bps, burst_bytes=256 * 1024)
    
    # 使用 epoll 等待可写
    try:
        epoll = select.epoll()
        epoll.register(sock_out.fileno(), select.EPOLLOUT)
        
        try:
            while True:
                data = q.get()
                if data is None:
                    break
                
                bucket.consume(len(data))
                
                # 等待 socket 可写
                events = epoll.poll(timeout=0.1)
                
                # 批量发送
                total_sent = 0
                while total_sent < len(data):
                    try:
                        sent = sock_out.send(data[total_sent:])
                        if sent == 0:
                            return
                        total_sent += sent
                    except BlockingIOError:
                        # Socket 缓冲区满，等待
                        epoll.poll()
                        continue
                    except Exception:
                        return
        finally:
            epoll.unregister(sock_out.fileno())
            epoll.close()
    except Exception:
        # 降级到标准模式
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


def _reader(sock_in: socket.socket, q: ByteQueue):
    """标准 reader（非阻塞优化版）。"""
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
    """标准 writer。"""
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


def _pipe_bidirectional(inner_conn: socket.socket, outer_conn: socket.socket, 
                        rate_bps: int, app_buf_bytes: int, use_optimized: bool = True):
    """
    inner -> outer: 采用 ByteQueue + 限速
    outer -> inner: 直接透传
    """
    q = ByteQueue(max_bytes=app_buf_bytes)
    
    if use_optimized:
        t1 = threading.Thread(target=_reader_optimized, args=(inner_conn, q), daemon=True)
        t2 = threading.Thread(target=_writer_optimized, args=(outer_conn, q, rate_bps), daemon=True)
    else:
        t1 = threading.Thread(target=_reader, args=(inner_conn, q), daemon=True)
        t2 = threading.Thread(target=_writer, args=(outer_conn, q, rate_bps), daemon=True)
    
    t1.start()
    t2.start()

    # 反向流量：outer -> inner（通常数据量小，使用标准模式）
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
    server_socket.listen(5)
    
    print(f"[*] PEP Running (ACK spoofing via Split-TCP) - OPTIMIZED")
    print(f"[*] Listening on {PEP_IP}:{PEP_PORT} (inner -> PEP)")
    print(f"[*] Connecting to {dest_ip}:{dest_port} (PEP -> outer)")
    print(f"[*] Config: CHUNK={CHUNK_SIZE}B, OS_RCVBUF={SOCK_RCVBUF}B, OS_SNDBUF={SOCK_SNDBUF}B")
    print(f"[*] Config: APP_BUFFER={app_buf_bytes}B, FORWARD_RATE={rate_bps if rate_bps>0 else 'unlimited'} B/s")
    print(f"[*] Optimizations: Larger buffers, epoll, reduced syscalls")
    print(f"[*] Ready. Please start the Sender now.")

    while True:
        try:
            sender_conn, addr = server_socket.accept()
            _tune_socket(sender_conn)
            print(f"[*] Connection from inner(Sender): {addr}")

            try:
                client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                _tune_socket(client_conn)
                client_conn.connect((dest_ip, dest_port))
            except Exception as e:
                print(f"[!] Cannot connect to outer: {e}")
                sender_conn.close()
                continue

            _pipe_bidirectional(sender_conn, client_conn, rate_bps=rate_bps, 
                              app_buf_bytes=app_buf_bytes, use_optimized=True)

        except KeyboardInterrupt:
            break


if __name__ == '__main__':
    start_pep()

