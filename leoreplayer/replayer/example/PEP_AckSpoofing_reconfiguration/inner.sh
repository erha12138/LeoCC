DIR=$(cd "$(dirname "$0")"; pwd)
DEV=ingress

# 输出目录：默认 data/<TRACE>/<ALG>_<TIME>/，也可由第5个参数显式指定
OUT_DIR="${5:-$DIR/data/${3}_${4}/${2}_${1}}"
mkdir -p "$OUT_DIR"
tcpdump -i "$DEV" -s 66 -w "$OUT_DIR/inner_${2}_${1}.pcap" &
CAP=$!

iperf3 -c 100.64.0.1 -p 9999 -C $2 -t $1

# tcpdump 可能提前退出，kill 失败不应导致整条 mm-link 链失败
if [ -n "$CAP" ] && kill -0 "$CAP" 2>/dev/null; then
    kill "$CAP" 2>/dev/null || true
fi
wait "$CAP" 2>/dev/null || true
