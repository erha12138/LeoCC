DIR=$(cd "$(dirname "$0")"; pwd)
ALG=cubic
RUNNING_TIME=10
PACKET_LENGTH=500
UPLINK_LOSS_RATE=0.002
DELAY_INTERVAL=10
TRACE_BW_PATH=$DIR/bw_example.txt
TRACE_DELAY_PATH=$DIR/delay_example.txt

# 清理旧的 delay-* 接口和路由（之前运行留下的残留）
echo "Cleaning up old delay-* interfaces and routes..."
for dev in $(ip -br link | grep -o 'delay-[[:digit:]]*'); do
    echo "  Removing old interface: $dev"
    # 删除接口相关的路由
    ip route | grep "dev $dev" | while read route; do
        ip route del $route 2>/dev/null || true
    done
    # 删除接口
    ip link delete $dev 2>/dev/null || true
done
# 清理所有 100.64.0.0/24 相关的路由（除了我们需要的）
ip route | grep "100.64.0" | grep -v "dev delay-" | while read route; do
    ip route del $route 2>/dev/null || true
done
sleep 1

# 确保之前的 iperf3 进程被彻底清理
echo "Cleaning up old iperf3 processes..."
pkill -9 iperf3 2>/dev/null || true
# 也清理可能的残留进程
killall -9 iperf3 2>/dev/null || true
sleep 2

# 检查端口 5201 是否被占用
if lsof -i :5201 2>/dev/null | grep -q LISTEN; then
    echo "Warning: Port 5201 is still in use, trying to free it..."
    fuser -k 5201/tcp 2>/dev/null || true
    sleep 1
fi

# 启动 iperf3 服务器
echo "Starting iperf3 server..."
# 使用 -B 0.0.0.0 确保监听所有接口，包括 mm-delay 创建的接口
# 使用 -1 只接受一个连接，避免多个客户端连接问题（但这不是问题根源）
iperf3 -s -D -B 0.0.0.0
sleep 3  # 增加等待时间，确保服务器完全启动

# 验证服务器是否真的在监听
for i in {1..5}; do
    if ss -tlnp 2>/dev/null | grep -q ":5201" || netstat -tlnp 2>/dev/null | grep -q ":5201"; then
        echo "iperf3 server is listening on port 5201"
        break
    fi
    if [ $i -eq 5 ]; then
        echo "Warning: Cannot verify iperf3 server is listening"
    fi
    sleep 1
done

# 检查 iperf3 是否在运行（应该只有一个）
IPERF_COUNT=$(pgrep -x iperf3 | wc -l)
if [ "$IPERF_COUNT" -eq 0 ]; then
    echo "Error: iperf3 server failed to start"
    exit 1
elif [ "$IPERF_COUNT" -gt 1 ]; then
    echo "Warning: Multiple iperf3 processes found ($IPERF_COUNT), cleaning up..."
    pkill -9 iperf3
    sleep 1
    iperf3 -s -D -B 0.0.0.0
    sleep 2
fi

IPERF_PID=$(pgrep -x iperf3 | head -1)
echo "iperf3 server started successfully (PID: $IPERF_PID)"
echo "iperf3 server listening on:"
ss -tlnp 2>/dev/null | grep ":5201" || netstat -tlnp 2>/dev/null | grep ":5201" || echo "  (cannot check listening ports)"

# 启动 outer.sh 在后台
bash $DIR/outer.sh $RUNNING_TIME &
OUTER_PID=$!

# 等待一下让 outer.sh 开始等待接口
sleep 0.5

# 运行 mm-delay 链，这会创建网络接口并执行 inner.sh
echo "Starting mm-delay chain..."
echo "Command: mm-delay $DELAY_INTERVAL $TRACE_DELAY_PATH mm-loss uplink $UPLINK_LOSS_RATE mm-link $TRACE_BW_PATH $TRACE_BW_PATH"
echo "  --uplink-queue droptail --uplink-queue-args packets=$PACKET_LENGTH"
echo "  --downlink-queue droptail --downlink-queue-args packets=$PACKET_LENGTH"
echo "  bash $DIR/inner.sh $RUNNING_TIME $ALG"

mm-delay $DELAY_INTERVAL $TRACE_DELAY_PATH mm-loss uplink $UPLINK_LOSS_RATE mm-link $TRACE_BW_PATH $TRACE_BW_PATH \
--uplink-queue droptail --uplink-queue-args packets=$PACKET_LENGTH --downlink-queue droptail --downlink-queue-args packets=$PACKET_LENGTH \
bash $DIR/inner.sh $RUNNING_TIME $ALG

EXIT_CODE=$?
echo "mm-delay chain completed with exit code: $EXIT_CODE"

# Cleanup
echo "Cleaning up..."
pkill iperf3 2>/dev/null || true
wait $OUTER_PID 2>/dev/null || true

# 清理本次运行创建的 delay-* 接口（可选，如果需要保留可以注释掉）
echo "Cleaning up delay-* interfaces created in this run..."
for dev in $(ip -br link | grep -o 'delay-[[:digit:]]*'); do
    echo "  Removing interface: $dev"
    ip route | grep "dev $dev" | while read route; do
        ip route del $route 2>/dev/null || true
    done
    ip link delete $dev 2>/dev/null || true
done