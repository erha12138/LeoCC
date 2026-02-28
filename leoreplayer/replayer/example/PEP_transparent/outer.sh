DIR=$(cd "$(dirname "$0")"; pwd)
echo "[outer.sh] ===== Starting outer.sh ====="
echo "[outer.sh] Waiting for delay-* interface creation..."

# 设置超时，避免无限等待
TIMEOUT=30
ELAPSED=0

while [ $ELAPSED -lt $TIMEOUT ]; do
    # 获取最新的 delay-* 接口（选择数字最大的）
    ALL_DEVS=$(ip -br link | grep -o 'delay-[[:digit:]]*' | sort -t- -k2 -n)
    DEV=$(echo "$ALL_DEVS" | tail -1)
    
    # Debug: Print all interfaces and the matched interface
    if [ $((ELAPSED % 5)) -eq 0 ]; then
        echo "[outer.sh] [DEBUG] Available interfaces:" $(ip -br link | awk '{print $1}')
        echo "[outer.sh] [DEBUG] All delay interfaces:" $ALL_DEVS
        echo "[outer.sh] [DEBUG] Selected interface: $DEV"
    fi
    
    if [ -n "$DEV" ] && ip link show ${DEV} >/dev/null 2>&1; then
        # 尝试将接口设置为 UP（如果需要）
        ip link set ${DEV} up 2>/dev/null || true
        echo "[outer.sh] Network Interface Created: $DEV"
        break
    fi
    
    echo "[outer.sh] Waiting for Network Interface Creation ... (${ELAPSED}s/${TIMEOUT}s)"
    sleep 0.5
    ELAPSED=$((ELAPSED + 1))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "[outer.sh] Error: Timeout waiting for delay-* interface"
    echo "[outer.sh] Available interfaces:" $(ip -br link | awk '{print $1}')
    exit 1
fi

# 修复路由添加：先删除旧路由（如果存在），再添加新路由
echo "[outer.sh] Setting up routing..."
# 尝试删除可能存在的路由
ip route del 100.64.0.0/24 2>/dev/null || true
ip route del 100.64.0.0/24 dev $DEV 2>/dev/null || true
sleep 0.5

# 添加路由
if ip route add 100.64.0.0/24 dev $DEV 2>/dev/null; then
    echo "[outer.sh] Route added successfully: 100.64.0.0/24 -> $DEV"
else
    echo "[outer.sh] Warning: Failed to add route, checking existing routes..."
    ip route | grep "100.64.0" || echo "[outer.sh] No existing route to 100.64.0.0/24"
    echo "[outer.sh] Continuing anyway..."
fi

# 显示当前路由表（用于调试）
echo "[outer.sh] Current routes to 100.64.0.0/24:"
ip route | grep "100.64.0" || echo "[outer.sh] No routes to 100.64.0.0/24 found"

tcpdump -w $DIR/outer.pcap -s 66 -i $DEV &
CAP=$!

sleep $1
kill $CAP 2>/dev/null || true
