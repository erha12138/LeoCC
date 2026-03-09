#!/bin/bash
#
# 合并 1_no_PEP_withCCAlg, 2_PEP_AckSpoofing_without_reconfiguration,
# 3_PEP_AckSpoofing_reconfiguration 下的 inner pcap 为 mergecap.pcap
#
# 各 pcap 按顺序打上标签后合并（1_no_PEP -> 2_PEP_without_reconfig -> 3_PEP_reconfig）
# 合并时使用 -a 按顺序拼接，便于按 packet 范围区分来源
#

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
EXAMPLE_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
OUTPUT_DIR="$SCRIPT_DIR"
OUTPUT_PCAP="$OUTPUT_DIR/mergecap.pcap"
LABELS_FILE="$OUTPUT_DIR/mergecap_labels.txt"

# 实验目录（优先 1_1_no_PEP_withCCAlg，不存在则用 1_no_PEP_withCCAlg）

DIR1="$EXAMPLE_DIR/1_no_PEP_withCCAlg"
DIR2="$EXAMPLE_DIR/2_PEP_AckSpoofing_without_reconfiguration"
DIR3="$EXAMPLE_DIR/3_PEP_AckSpoofing_reconfiguration"

# data/A_3/cubic_100 下的 inner pcap（不同实验可能用 inner.pcap 或 inner_cubic_100.pcap）
DATA_SUBDIR="data/A_3/cubic_100"

find_inner_pcap() {
    local dir="$1"
    local base="$dir/$DATA_SUBDIR"
    if [ -f "$base/inner.pcap" ]; then
        echo "$base/inner.pcap"
    elif [ -f "$base/inner_cubic_100.pcap" ]; then
        echo "$base/inner_cubic_100.pcap"
    else
        echo ""
    fi
}

# 检查 mergecap 是否可用
if ! command -v mergecap &>/dev/null; then
    echo "Error: mergecap not found. Install wireshark/tshark: sudo apt install wireshark-common"
    exit 1
fi

# 查找各实验的 inner pcap
PCAP1=$(find_inner_pcap "$DIR1")
PCAP2=$(find_inner_pcap "$DIR2")
PCAP3=$(find_inner_pcap "$DIR3")

if [ -z "$PCAP1" ]; then
    echo "Error: inner pcap not found in $DIR1/$DATA_SUBDIR/"
    exit 1
fi
if [ -z "$PCAP2" ]; then
    echo "Error: inner pcap not found in $DIR2/$DATA_SUBDIR/"
    exit 1
fi
if [ -z "$PCAP3" ]; then
    echo "Error: inner pcap not found in $DIR3/$DATA_SUBDIR/"
    exit 1
fi

echo "[merge_pcap] Found inner pcaps:"
echo "  1_no_PEP:                    $PCAP1"
echo "  2_PEP_AckSpoofing_without:   $PCAP2"
echo "  3_PEP_AckSpoofing_reconfig:  $PCAP3"

# 创建带标签的临时文件（用于 mergecap 输入，便于识别）
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

LABEL1="$TMP_DIR/1_no_PEP_withCCAlg.pcap"
LABEL2="$TMP_DIR/2_PEP_AckSpoofing_without_reconfiguration.pcap"
LABEL3="$TMP_DIR/3_PEP_AckSpoofing_reconfiguration.pcap"

cp "$PCAP1" "$LABEL1"
cp "$PCAP2" "$LABEL2"
cp "$PCAP3" "$LABEL3"





# mergecap -a: 按顺序拼接（不按时间戳交错），便于按 packet 范围区分
# -w: 输出文件
echo "[merge_pcap] Merging pcaps..."
mergecap -a -w "$OUTPUT_PCAP" "$LABEL1" "$LABEL2" "$LABEL3"

# 生成标签说明文件（记录各段 packet 范围）
echo "[merge_pcap] Generating labels file..."
_count_packets() {
    tcpdump -r "$1" -n 2>/dev/null | wc -l || echo "0"
}
n1=$(_count_packets "$LABEL1")
n2=$(_count_packets "$LABEL2")
n3=$(_count_packets "$LABEL3")
{
    echo "# mergecap.pcap 标签说明"
    echo "# 本文件由 merge_inner_pcap.sh 生成"
    echo "#"
    echo "# Packet 顺序（mergecap -a 拼接，不按时间戳交错）:"
    echo "#   1. 1_no_PEP_withCCAlg                     (packet 1 - $n1)"
    echo "#   2. 2_PEP_AckSpoofing_without_reconfiguration  (packet $((n1+1)) - $((n1+n2)))"
    echo "#   3. 3_PEP_AckSpoofing_reconfiguration      (packet $((n1+n2+1)) - $((n1+n2+n3)))"
    echo "#"
    echo "1_no_PEP_withCCAlg:                    $n1 packets"
    echo "2_PEP_AckSpoofing_without_reconfig:    $n2 packets"
    echo "3_PEP_AckSpoofing_reconfiguration:     $n3 packets"
} > "$LABELS_FILE"

echo "[merge_pcap] Done. Output: $OUTPUT_PCAP"
echo "[merge_pcap] Labels:       $LABELS_FILE"
