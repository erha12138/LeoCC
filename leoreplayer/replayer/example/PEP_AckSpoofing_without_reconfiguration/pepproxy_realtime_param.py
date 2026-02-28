import socket
import threading
import sys
import time
import os
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

# === 缓冲区占用记录配置 ===
# 获取脚本所在目录，日志文件保存在脚本目录下的 data 文件夹
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR = os.path.join(SCRIPT_DIR, "data")
# # 确保 data 目录存在
# os.makedirs(DATA_DIR, exist_ok=True)
BUFFER_LOG_INTERVAL = 0.1  # 记录间隔（秒）

# === 每条管道的上下文 & 动态速率算法接口 ===

def format_bytes(bytes_count: int) -> str:
    """
    将字节数转换为易读格式（MB、KB、B）
    
    参数:
        bytes_count: 字节数
    
    返回:
        格式化的字符串，如 "32.5 MB", "1024 KB", "512 B"
    """
    if bytes_count >= 1024 * 1024:
        # MB
        mb = bytes_count / (1024 * 1024)
        return f"{mb:.2f} MB"
    elif bytes_count >= 1024:
        # KB
        kb = bytes_count / 1024
        return f"{kb:.2f} KB"
    else:
        # B
        return f"{bytes_count} B"


class PipeContext:
    """
    每条 inner->outer 管道的上下文信息。
    你可以在 compute_dynamic_rate_bps() 里使用这些信息实现自己的算法。
    """
    def __init__(self, conn_id: int, initial_rate_bps: int, app_buf_bytes: int, queue: "ByteQueue", bucket: "TokenBucket", log_file_path: str = None, offset_ms: int = 12000):
        self.conn_id = conn_id
        self.initial_rate_bps = initial_rate_bps
        self.app_buf_bytes = app_buf_bytes
        self.queue = queue
        self.bucket = bucket
        self.created_at = time.monotonic()
        self.bytes_from_inner = 0
        self.bytes_to_outer = 0
        self._last_rate_check = self.created_at
        self._last_bytes_from_inner = 0  # 用于计算 inner 瞬时速率
        self._last_log_time = self.created_at
        # 平滑速率控制：记录当前实际速率和目标速率
        self._current_rate_bps = initial_rate_bps
        self._target_rate_bps = initial_rate_bps
        # 缓冲区占用日志文件
        self.log_file_path = log_file_path
        self.log_file = None
        self.offset_ms = offset_ms
        if log_file_path:
            try:
                abs_path = os.path.abspath(log_file_path)
                
                # 确保目录存在
                log_dir = os.path.dirname(abs_path)
                os.makedirs(log_dir, exist_ok=True)
                
                # 直接覆盖写入（'w' 模式），每次运行都是新文件
                self.log_file = open(log_file_path, 'w', buffering=1)  # 行缓冲，立即写入
                
                # 写入表头
                header = "# Time(s)\tBuffer_Used\tBuffer_Max\tOccupancy(%)\tRate(Mbps)\n"
                self.log_file.write(header)
                self.log_file.flush()  # 确保立即写入
                
                # 验证文件确实被创建了
                if os.path.exists(log_file_path):
                    file_size = os.path.getsize(log_file_path)
                    print(f"[*] Buffer log file created: {abs_path} ({file_size} bytes)", file=sys.stderr)
                    print(f"[*] Buffer log file created: {abs_path} ({file_size} bytes)")
                else:
                    print(f"[!] ERROR: File was not created: {abs_path}", file=sys.stderr)
                    print(f"[!] ERROR: File was not created: {abs_path}")
            except Exception as e:
                import traceback
                error_msg = f"[!] ERROR: Failed to create log file {log_file_path}: {e}"
                print(error_msg, file=sys.stderr)
                print(error_msg)
                print(f"[!] Traceback: {traceback.format_exc()}", file=sys.stderr)
                print(f"[!] Traceback: {traceback.format_exc()}")
                self.log_file = None
        else:
            print(f"[!] WARNING: log_file_path is None!", file=sys.stderr)
            print(f"[!] WARNING: log_file_path is None!")
        # 可选：你可以在算法里用这个字段自定义状态
        self.user_state = {}
    
    def close(self):
        """关闭日志文件"""
        if self.log_file:
            try:
                self.log_file.close()
            except Exception:
                pass
            self.log_file = None
        # 这里也可以在需要时做一些额外的清理工作

    # === 动态调节接口：应用层缓冲区 ===
    def set_app_buffer_limit(self, new_max_bytes: int):
        """
        动态调整本条连接对应的应用层缓冲区上限（单位：字节）。
        - 线程安全：内部通过 ByteQueue 自带的锁来更新。
        - new_max_bytes 会同时更新：
          * ctx.app_buf_bytes（记录值）
          * ctx.queue 的最大字节数限制
        """
        if new_max_bytes <= 0:
            return
        self.app_buf_bytes = new_max_bytes
        # ByteQueue 自己保证线程安全
        if hasattr(self.queue, "set_max_bytes"):
            self.queue.set_max_bytes(new_max_bytes)


def compute_dynamic_rate_bps(ctx: PipeContext) -> float:
    """
    将转发速率匹配为 inner 的发送速率：用 bytes_from_inner 在最近一个周期内的增量
    除以时间间隔得到 inner_rate_bps，作为目标转发速率（float，保留小数）。
    若间隔过短或 inner 无新数据，则保持当前/初始速率。
    """
    now = time.monotonic()
    dt = now - ctx._last_rate_check
    if dt < 0.01:
        return float(ctx._current_rate_bps or ctx.initial_rate_bps)
    delta = ctx.bytes_from_inner - ctx._last_bytes_from_inner
    inner_rate_bps = delta / dt
    if inner_rate_bps <= 0:
        return float(ctx._current_rate_bps or ctx.initial_rate_bps)
    return inner_rate_bps

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

    data_top_dir = sys.argv[5] if len(sys.argv) >= 6 else None
    data_file_name = sys.argv[6] if len(sys.argv) >= 7 else None
    offset_ms = int(sys.argv[7]) if len(sys.argv) >= 8 else 12000
    alg = sys.argv[8] if len(sys.argv) >= 9 else None
    running_time = int(sys.argv[9]) if len(sys.argv) >= 10 else None
    out_dir = sys.argv[10] if len(sys.argv) >= 11 else None
    return dest_ip, dest_port, rate_bps, app_buf_bytes, data_top_dir, data_file_name, offset_ms, alg, running_time, out_dir


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
                self._cv.wait(timeout=0.1)
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

    def current_bytes(self):
        """线程安全地获取当前队列中的字节数"""
        with self._cv:
            return self._cur

    def max_bytes(self):
        """获取缓冲区最大字节数"""
        return self._max

    def set_max_bytes(self, new_max: int):
        """
        动态调整队列可占用的最大字节数上限。
        - 若 new_max 小于当前已用字节数 _cur，则不会丢数据，只是禁止新的 put 直到 _cur <= new_max。
        - 通过条件变量保证线程安全。
        """
        if new_max <= 0:
            return
        with self._cv:
            self._max = new_max
            # 通知可能在等待空间的生产者 / 等待数据的消费者
            self._cv.notify_all()


class TokenBucket:
    """简单令牌桶限速（字节/秒）。rate=0 表示不限速，支持运行时动态调整。rate 支持 float。"""

    def __init__(self, rate_bps, burst_bytes: int):
        self.rate = max(0.0, float(rate_bps))
        self.capacity = max(1, int(burst_bytes))
        self.tokens = float(self.capacity)
        self.t = time.monotonic()

    def set_rate(self, rate_bps):
        """更新当前限速（字节/秒），支持 int 或 float。"""
        self.rate = max(0.0, float(rate_bps))

    def consume(self, nbytes: int):
        if self.rate <= 0:
            # rate<=0 视为不限速，直接返回
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


def _log_buffer_occupancy(ctx: PipeContext, timestamp: float):
    """
    记录缓冲区占用到日志文件
    
    参数:
        ctx: PipeContext，包含队列和日志文件信息
        timestamp: 当前时间戳（monotonic）
    """
    if not ctx.log_file:
        return
    
    try:
        # 获取缓冲区状态
        queue_bytes = ctx.queue.current_bytes()
        max_bytes = ctx.queue.max_bytes()
        occupancy_pct = (queue_bytes / max_bytes * 100) if max_bytes > 0 else 0.0
        
        # 计算运行时间（秒）
        elapsed_time = timestamp - ctx.created_at
        
        # 计算当前速率（Mbps）
        current_rate_mbps = (ctx._current_rate_bps * 8) / (1024 * 1024) if ctx._current_rate_bps > 0 else 0.0
        
        # 写入日志：时间(秒) | 已用缓冲区 | 最大缓冲区 | 占用率(%) | 当前速率(Mbps)
        # 使用易读格式
        buffer_used_str = format_bytes(queue_bytes)
        buffer_max_str = format_bytes(max_bytes)
        
        log_line = (
            f"{elapsed_time:.2f}\t"
            f"{buffer_used_str}\t"
            f"{buffer_max_str}\t"
            f"{occupancy_pct:.2f}\t"
            f"{current_rate_mbps:.2f}\n"
        )
        
        ctx.log_file.write(log_line)
        ctx.log_file.flush()  # 确保立即写入磁盘
    except Exception as e:
        # 记录失败时输出错误信息，方便调试
        import traceback
        print(f"[!] Error writing to log file {ctx.log_file_path}: {e}")
        print(f"[!] Traceback: {traceback.format_exc()}")


def _tune_socket(s: socket.socket):
    """
    为新建的 TCP 连接设置默认的 socket 参数。
    若后续需要针对某条连接做“实时调节”，可以调用下面的
    `set_socket_rcvbuf` / `set_socket_sndbuf` 接口。
    """
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_RCVBUF)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_SNDBUF)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


# === 动态调节接口：socket 缓冲区 ===

def set_socket_rcvbuf(sock: socket.socket, new_rcvbuf: int):
    """
    动态调整某条连接的接收缓冲区大小（SO_RCVBUF）。
    - new_rcvbuf: 期望的缓冲区大小（单位：字节，>0）
    - 注意：内核实际值可能会被翻倍，这是正常现象。
    """
    if not sock or new_rcvbuf <= 0:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(new_rcvbuf))
    except OSError:
        # 某些平台/状态下可能失败，直接忽略即可
        pass


def set_socket_sndbuf(sock: socket.socket, new_sndbuf: int):
    """
    动态调整某条连接的发送缓冲区大小（SO_SNDBUF）。
    - new_sndbuf: 期望的缓冲区大小（单位：字节，>0）
    - 注意：内核实际值可能会被翻倍，这是正常现象。
    """
    if not sock or new_sndbuf <= 0:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(new_sndbuf))
    except OSError:
        pass


def _reader(sock_in: socket.socket, q: ByteQueue, ctx: PipeContext):
    try:
        while True:
            data = sock_in.recv(CHUNK_SIZE)
            if not data:
                break
            ctx.bytes_from_inner += len(data)
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


def _writer(sock_out: socket.socket, q: ByteQueue, ctx: PipeContext):
    """
    单条 inner->outer 管道的发送线程：
    - 使用 ctx.bucket 做限速；
    - 周期性调用 compute_dynamic_rate_bps(ctx) 更新速率；
    - 使用平滑过渡避免速率突变导致的延迟峰值；
    - 每0.1秒记录缓冲区占用到日志文件；
    - 顺便更新 ctx.bytes_to_outer 统计。
    """
    bucket = ctx.bucket
    RATE_UPDATE_INTERVAL = 0.1  # 秒：多久检查一次算法是否需要调整速率
    
    try:
        while True:
            data = q.get()
            if data is None:
                break
            n = len(data)

            # 调用限速
            bucket.consume(n)

            # 发送数据
            sock_out.sendall(data)

            # 更新统计
            ctx.bytes_to_outer += n

            # 周期性调用算法决策新的速率，并平滑过渡
            now = time.monotonic()
            if now - ctx._last_rate_check >= RATE_UPDATE_INTERVAL:
                # 获取算法计算的目标速率（匹配 inner 发送速率）
                target_rate_bps = compute_dynamic_rate_bps(ctx)
                ctx._target_rate_bps = target_rate_bps
                ctx._current_rate_bps = target_rate_bps
                bucket.set_rate(target_rate_bps)
                ctx._last_bytes_from_inner = ctx.bytes_from_inner
                ctx._last_rate_check = now
            

                
                
                # 记录缓冲区占用到日志文件（每0.1秒）
            if now - ctx._last_log_time >= BUFFER_LOG_INTERVAL:
                _log_buffer_occupancy(ctx, now)
                ctx._last_log_time = now    
            

    except Exception:
        pass
    finally:
        q.close()
        # 关闭日志文件
        ctx.close()
        try:
            sock_out.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        try:
            sock_out.close()
        except Exception:
            pass


def _pipe_bidirectional(inner_conn: socket.socket, outer_conn: socket.socket, rate_bps: int, app_buf_bytes: int, conn_id: int = None, DATA_DIR: str = None, offset_ms: int = 12000):
    """
    inner -> outer: 采用 ByteQueue + 限速（ACK 欺骗的关键在于：inner 的 TCP 会被 PEP 提前 ACK）
    outer -> inner: 直接透传（通常是 iperf3 server 的控制/统计输出）
    
    参数:
        conn_id: 连接ID，用于生成日志文件名。如果为None，使用 id(inner_conn)
    """
    # 为该管道创建队列和令牌桶 + 上下文
    q = ByteQueue(max_bytes=app_buf_bytes)
    bucket = TokenBucket(rate_bps=rate_bps, burst_bytes=256 * 1024)

    # 为每条管道创建独立的日志文件（使用 conn_id 区分）
    if conn_id is None:
        conn_id = id(inner_conn)
    # 日志文件名格式：{conn_id}.log，保存在 data 目录
    log_file_path = os.path.join(DATA_DIR, f"Buffer_Occupancy_{conn_id}.log") if DATA_DIR else None
    print(f"[DEBUG] Creating log file for conn_id={conn_id}: {log_file_path}", file=sys.stderr)
    print(f"[DEBUG] Creating log file for conn_id={conn_id}: {log_file_path}")
    ctx = PipeContext(conn_id=conn_id, initial_rate_bps=rate_bps, app_buf_bytes=app_buf_bytes, queue=q, bucket=bucket, log_file_path=log_file_path, offset_ms=offset_ms)

    # 立即记录一次初始状态（连接建立时）
    if ctx.log_file:
        try:
            _log_buffer_occupancy(ctx, time.monotonic())
        except Exception as e:
            print(f"[!] ERROR: Failed to log initial state to {ctx.log_file_path}: {e}")

    t1 = threading.Thread(target=_reader, args=(inner_conn, q, ctx), daemon=True)
    t2 = threading.Thread(target=_writer, args=(outer_conn, q, ctx), daemon=True)
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
            # 关闭日志文件
            ctx.close()
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
    dest_ip, dest_port, rate_bps, app_buf_bytes, data_top_dir, data_file_name, offset_ms, alg, running_time, out_dir = _parse_args()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((PEP_IP, PEP_PORT))
    server_socket.listen(MAX_LISTEN_CONNECTIONS)
    
    # 连接计数器，用于生成友好的日志文件名
    connection_counter = 0
    
    # 日志输出目录：优先使用 run.sh 传入的 RUN_DATA_DIR（可按 ALG/TIME 区分，避免覆盖）
    if out_dir:
        DATA_DIR = out_dir
    elif data_top_dir is not None and data_file_name is not None and alg and running_time is not None:
        DATA_DIR = os.path.join(SCRIPT_DIR, "data", f"{data_top_dir}_{data_file_name}", f"{alg}_{running_time}")
    else:
        DATA_DIR = os.path.join(SCRIPT_DIR, "data", f"{data_top_dir}_{data_file_name}")
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        pass
    
    
    print(f"[*] PEP Running (ACK spoofing via Split-TCP)")
    print(f"[*] Listening on {PEP_IP}:{PEP_PORT} (inner -> PEP)")
    print(f"[*] Connecting to {dest_ip}:{dest_port} (PEP -> outer)")
    print(f"[*] Config: CHUNK={CHUNK_SIZE}B, OS_RCVBUF={SOCK_RCVBUF}B, OS_SNDBUF={SOCK_SNDBUF}B")
    print(f"[*] Config: APP_BUFFER={app_buf_bytes}B, FORWARD_RATE={rate_bps if rate_bps>0 else 'unlimited'} B/s")
    if DATA_DIR:
        abs_data_dir = os.path.abspath(DATA_DIR)
        print(f"[*] Buffer occupancy logging: {abs_data_dir}/<conn_id>.log (every {BUFFER_LOG_INTERVAL}s)")
    print(f"[*] Ready. Please start the Sender now.")

    while True:
        try:
            
            sender_conn, addr = server_socket.accept()

            try:
                _tune_socket(sender_conn)
            except Exception as e:
                import traceback
                print(f"[!] ERROR in _tune_socket: {e}", file=sys.stderr, flush=True)
                print(f"[!] ERROR in _tune_socket: {e}", flush=True)
                print(f"[!] Traceback: {traceback.format_exc()}", file=sys.stderr, flush=True)
                print(f"[!] Traceback: {traceback.format_exc()}", flush=True)
                raise
            connection_counter += 1
            print(f"[*] Connection #{connection_counter} from inner(Sender): {addr}", file=sys.stderr)
            print(f"[*] Connection #{connection_counter} from inner(Sender): {addr}")

            # 建立到 outer(接收端) 的连接
            try:
                client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                _tune_socket(client_conn)
                client_conn.connect((dest_ip, dest_port))
                print(f"[*] Connected to outer: {dest_ip}:{dest_port}", file=sys.stderr)
                print(f"[*] Connected to outer: {dest_ip}:{dest_port}")
            except Exception as e:
                import traceback
                print(f"[!] Cannot connect to outer: {e}", file=sys.stderr)
                print(f"[!] Cannot connect to outer: {e}")
                print(f"[!] Traceback: {traceback.format_exc()}", file=sys.stderr)
                print(f"[!] Traceback: {traceback.format_exc()}")
                sender_conn.close()
                continue

            print(f"[*] Creating pipe for connection #{connection_counter}...", file=sys.stderr)
            print(f"[*] Creating pipe for connection #{connection_counter}...")
            _pipe_bidirectional(sender_conn, client_conn, rate_bps=rate_bps, app_buf_bytes=app_buf_bytes, conn_id=connection_counter, DATA_DIR=DATA_DIR)
            print(f"[*] Pipe created for connection #{connection_counter}", file=sys.stderr)
            print(f"[*] Pipe created for connection #{connection_counter}")

        except KeyboardInterrupt:
            print("[DEBUG] KeyboardInterrupt received", file=sys.stderr)
            print("[DEBUG] KeyboardInterrupt received")
            break
        except Exception as e:
            import traceback
            print(f"[!] ERROR in main loop: {e}", file=sys.stderr)
            print(f"[!] ERROR in main loop: {e}")
            print(f"[!] Traceback: {traceback.format_exc()}", file=sys.stderr)
            print(f"[!] Traceback: {traceback.format_exc()}")
            # 继续运行，不要因为一个连接失败就退出
            continue

if __name__ == '__main__':
    start_pep()
    