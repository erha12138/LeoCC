DIR=$(cd "$(dirname "$0")"; pwd)
ALG=cubic
RUNNING_TIME=100
PACKET_LENGTH=500
UPLINK_LOSS_RATE=0.002
DELAY_INTERVAL=10

DATA_FILE_NAME=3
DATA_TOP_DIR=A
OFFSET_MS=10240  # 这个就是reconfiguration的时间点
# 本次实验输出目录：data/<TRACE>/<ALG>_<TIME>/
RUN_TAG="${ALG}_${RUNNING_TIME}"
RUN_DATA_DIR="$DIR/data/${DATA_TOP_DIR}_${DATA_FILE_NAME}/${RUN_TAG}"
mkdir -p "$RUN_DATA_DIR"
# traces 目录位于仓库根目录：/home/erha/LeoCC/traces
DATA_DIR=$DIR/../../../../traces
# traces 目录结构为：<X>_uplink/<id>/{bw_<z>.txt,delay_<id>.txt}
DATA_FILE=${DATA_TOP_DIR}_uplink/$DATA_FILE_NAME
TRACE_BW_PATH=$DATA_DIR/$DATA_FILE/bw_$DATA_FILE_NAME.txt
TRACE_DELAY_PATH=$DATA_DIR/$DATA_FILE/delay_$DATA_FILE_NAME.txt

# 启动前检查 trace 文件是否存在，避免 mm-delay 里才报错
if [ ! -f "$TRACE_DELAY_PATH" ]; then
    echo "Error: delay trace not found: $TRACE_DELAY_PATH"
    exit 1
fi
if [ ! -f "$TRACE_BW_PATH" ]; then
    echo "Error: bw trace not found: $TRACE_BW_PATH"
    exit 1
fi

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
killall -9 iperf3 2>/dev/null || true
sleep 2

# 清理端口 9999 (PEP proxy) 和 5201 (iperf3)
echo "Cleaning up ports 9999 and 5201..."
sudo fuser -k -n tcp 9999 2>/dev/null || true
fuser -k 5201/tcp 2>/dev/null || true
sleep 1

# 清理旧的 PEP proxy 进程
echo "Cleaning up old PEP proxy processes..."
pkill -f "pepproxy.py" 2>/dev/null || true
sleep 1

# 启动 iperf3 服务器
echo "Starting iperf3 server..."
iperf3 -s -D -B 0.0.0.0
sleep 3

# 检查 iperf3 是否在运行
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








# ================================================
# ================================================
# ================================================




# Start PEPPROXY
echo "Starting PEP proxy on port 9999..."
# args: <DEST_IP> [DEST_PORT] [RATE_MBPS] [APP_BUF_MB]
# 这里给一个比较“稳”的默认：160Mbps 转发 + 32MB PEP 缓冲
python3 $DIR/pepproxy_realtime_param.py 100.64.0.1 5201 6 8 $DATA_TOP_DIR $DATA_FILE_NAME $OFFSET_MS $ALG $RUNNING_TIME "$RUN_DATA_DIR" &
PEPPROXY_PID=$!
sleep 1

# 检查 PEP proxy 是否启动
if ! kill -0 $PEPPROXY_PID 2>/dev/null; then
    echo "Error: PEP proxy failed to start"
    pkill iperf3
    exit 1
fi
echo "PEP proxy started successfully (PID: $PEPPROXY_PID)"

# 启动 outer.sh 在后台
bash $DIR/outer.sh $RUNNING_TIME $ALG $DATA_TOP_DIR $DATA_FILE_NAME "$RUN_DATA_DIR" &
OUTER_PID=$!

# 等待一下让 outer.sh 开始等待接口
sleep 0.5

# 运行 mm-delay 链
echo "Starting mm-delay chain..."
mm-delay $DELAY_INTERVAL $TRACE_DELAY_PATH mm-loss uplink $UPLINK_LOSS_RATE mm-link $TRACE_BW_PATH $TRACE_BW_PATH \
--uplink-queue droptail --uplink-queue-args packets=$PACKET_LENGTH --downlink-queue droptail --downlink-queue-args packets=$PACKET_LENGTH \
bash $DIR/inner.sh $RUNNING_TIME $ALG $DATA_TOP_DIR $DATA_FILE_NAME "$RUN_DATA_DIR"





# ================================================
# ================================================
# ================================================








EXIT_CODE=$?
echo "mm-delay chain completed with exit code: $EXIT_CODE"

# Cleanup
echo "Cleaning up..."
pkill iperf3 2>/dev/null || true
kill $PEPPROXY_PID 2>/dev/null || true
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