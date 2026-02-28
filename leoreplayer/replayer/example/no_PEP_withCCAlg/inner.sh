DIR=$(cd "$(dirname "$0")"; pwd)
DEV=ingress

echo "[inner.sh] ===== Starting inner.sh ====="
echo "[inner.sh] Parameters: RUNNING_TIME=$1, ALG=$2"
echo "[inner.sh] Current network interfaces:"
ip -br link | head -10

# 输出目录：默认 data/<TRACE>/<ALG>_<TIME>/，也可由第5个参数显式指定
OUT_DIR="${5:-$DIR/data/${3}_${4}/${2}_${1}}"
mkdir -p "$OUT_DIR"

# 等待 ingress 接口创建
echo "[inner.sh] Waiting for $DEV interface..."
for i in {1..20}; do
    if ip link show $DEV >/dev/null 2>&1; then
        echo "[inner.sh] Interface $DEV found!"
        break
    fi
    if [ $i -eq 20 ]; then
        echo "[inner.sh] Error: Interface $DEV not found after 10 seconds"
        echo "[inner.sh] Available interfaces:"
        ip -br link
        exit 1
    fi
    sleep 0.5
done

# 检查接口状态
echo "[inner.sh] Interface $DEV status:"
ip link show $DEV

# 检查路由
echo "[inner.sh] Current routes:"
ip route

# 检查 IP 地址
echo "[inner.sh] IP addresses:"
ip addr show $DEV || echo "[inner.sh] No IP address on $DEV"

echo "[inner.sh] Starting tcpdump on $DEV..."
tcpdump -i $DEV -s 66 -w "$OUT_DIR/inner_${2}_${1}.pcap" &
CAP=$!

# 等待一下确保接口就绪
sleep 1

echo "[inner.sh] Starting iperf3 client: connecting to 100.64.0.1 with algorithm $2 for $1 seconds"
echo "[inner.sh] Testing connectivity to 100.64.0.1..."
ping -c 2 100.64.0.1 || echo "[inner.sh] Warning: Cannot ping 100.64.0.1, but continuing..."

echo "[inner.sh] Checking if iperf3 server is reachable on port 5201..."
if timeout 3 bash -c "echo > /dev/tcp/100.64.0.1/5201" 2>/dev/null; then
    echo "[inner.sh] Port 5201 is reachable"
else
    echo "[inner.sh] Warning: Port 5201 is not reachable, but trying iperf3 anyway..."
fi

echo "[inner.sh] Running iperf3 client (this may take a moment)..."
# 添加重试机制，因为连接可能因为时序问题失败
MAX_RETRIES=3
RETRY_COUNT=0
SUCCESS=false

# 获取本地 IP（ingress 接口的 IP）
LOCAL_IP=$(ip -4 addr show ingress 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=""
    echo "[inner.sh] Warning: Could not determine local IP, not using --bind"
else
    echo "[inner.sh] Using local IP: $LOCAL_IP for binding"
fi

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if [ $RETRY_COUNT -gt 0 ]; then
        echo "[inner.sh] Retry attempt $RETRY_COUNT/$MAX_RETRIES..."
        sleep 2  # 增加重试间隔
    fi
    
    # 使用 -i 1 显示每秒的统计信息
    # 添加 -p 5201 明确指定端口
    # 如果可能，绑定到本地 IP
    if [ -n "$LOCAL_IP" ]; then
        CMD="iperf3 -c 100.64.0.1 -p 5201 -C $2 -t $1 -i 1 --forceflush --bind $LOCAL_IP"
    else
        CMD="iperf3 -c 100.64.0.1 -p 5201 -C $2 -t $1 -i 1 --forceflush"
    fi
    
    echo "[inner.sh] Executing: $CMD"
    if $CMD 2>&1; then
        SUCCESS=true
        break
    else
        EXIT_CODE=$?
        echo "[inner.sh] iperf3 attempt $((RETRY_COUNT + 1)) failed with exit code $EXIT_CODE"
        RETRY_COUNT=$((RETRY_COUNT + 1))
    fi
done

if [ "$SUCCESS" = false ]; then
    echo "[inner.sh] Error: iperf3 client failed after $MAX_RETRIES attempts"
    echo "[inner.sh] Checking network connectivity again..."
    ping -c 2 100.64.0.1 || echo "[inner.sh] Cannot ping 100.64.0.1"
    echo "[inner.sh] Checking if iperf3 server is reachable on port 5201..."
    timeout 2 bash -c "echo > /dev/tcp/100.64.0.1/5201" 2>/dev/null && echo "[inner.sh] Port 5201 is open" || echo "[inner.sh] Port 5201 is not reachable"
    kill $CAP 2>/dev/null || true
    exit 1
fi

echo "[inner.sh] iperf3 client completed successfully"
kill $CAP 2>/dev/null || true
echo "[inner.sh] ===== inner.sh completed ====="