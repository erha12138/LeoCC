#!/usr/bin/env python3
"""
Read inner/outer pcap from PEP_innerClinet_transparent and plot
- Per-second throughput (Mbps) for inner and outer captures
- One-way delay (outer -> inner) by matching TCP packets on (src, dst, seq, len)

Outputs are saved under example/plot/PEP_transparent_cubic/.
"""

import os
from collections import defaultdict
from glob import glob
from pathlib import Path
from typing import List, Optional, Tuple

import matplotlib.pyplot as plt
from scapy.all import PcapReader, IP, TCP  # type: ignore


ROOT = Path(__file__).resolve().parents[1]


# TARGET_DIR = "PEP_AckSpoofing_reconfiguration"
TARGET_DIR = "no_PEP_Alg"
TARGET_DATA_DIR = "A_3"
ALG = "cubic"
TIME_LENGTH = 100

def _resolve_target_dir(root: Path, target_dir: str) -> str:
    """Resolve minor naming variants (extra underscore) under example/."""
    if (root / target_dir).exists():
        return target_dir
    candidates = []
    if "__" in target_dir:
        candidates.append(target_dir.replace("__", "_"))
    else:
        candidates.append(target_dir.replace("_reconfiguration", "__reconfiguration"))
    for cand in candidates:
        if (root / cand).exists():
            print(f"[plot.py] Warning: {target_dir} not found; using {cand} instead.")
            return cand
    return target_dir


TARGET_DIR = _resolve_target_dir(ROOT, TARGET_DIR)
print(f"TARGET_DIR: {TARGET_DIR}")
PCAP_DIR = ROOT / TARGET_DIR

# 输出图目录（保持不变）：plot/<TARGET_DIR>/<TRACE>/<ALG>_<TIME>/
OUT_DIR = ROOT / "plot" / TARGET_DIR / TARGET_DATA_DIR / f"{ALG}_{TIME_LENGTH}"


def _resolve_run_pcap_paths(pcap_dir: Path):
    """
    Resolve where pcaps are stored.

    New layout (recommended):
      data/<TRACE>/<ALG>_<TIME>/{inner_*.pcap, outer_*.pcap}
    Backward-compatible layouts:
      data/<TRACE>/{inner_*.pcap, outer_*.pcap}
      data/{inner_*.pcap, outer_*.pcap}  (old no_PEP_Alg)
    """
    candidates = [
        pcap_dir / "data" / TARGET_DATA_DIR / f"{ALG}_{TIME_LENGTH}",
        pcap_dir / "data" / TARGET_DATA_DIR,
        pcap_dir / "data",
    ]
    for run_dir in candidates:
        inner = run_dir / f"inner_{ALG}_{TIME_LENGTH}.pcap"
        outer = run_dir / f"outer_{ALG}_{TIME_LENGTH}.pcap"
        if inner.exists() and outer.exists():
            return run_dir, inner, outer
    # fallback to the newest layout path
    run_dir = candidates[0]
    return run_dir, run_dir / f"inner_{ALG}_{TIME_LENGTH}.pcap", run_dir / f"outer_{ALG}_{TIME_LENGTH}.pcap"


RUN_DIR, INNER_PCAP, OUTER_PCAP = _resolve_run_pcap_paths(PCAP_DIR)

# Buffer Occupancy 日志目录：与本次运行目录一致（便于按 ALG/TIME 区分）
PEP_ACK_DIR = RUN_DIR

print(f"INNER_PCAP: {INNER_PCAP}")
print(f"OUTER_PCAP: {OUTER_PCAP}")
print(f"PEP_ACK_DIR: {PEP_ACK_DIR}")

def ensure_output_dir() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)


def iter_tcp_packets(path: Path):
    """Stream TCP packets with timestamps to avoid loading the whole pcap into memory."""
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP in pkt and TCP in pkt:
                yield pkt.time, pkt[IP], pkt[TCP]


def compute_throughput_mbps(path: Path, bin_size: float = 0.2):
    """
    Return (times, mbps, first_ts) using IP total length (ip.len).
    This is robust even when snaplen is small (e.g., 66 bytes).
    """
    bins = defaultdict(int)
    start_time = None

    for ts, ip, _tcp in iter_tcp_packets(path):
        if start_time is None:
            start_time = ts
        rel = ts - start_time
        bin_idx = int(rel // bin_size)
        ip_len = getattr(ip, "len", None)
        if ip_len is None:
            # Fallback: best-effort using captured payload length
            ip_len = len(bytes(ip))
        bins[bin_idx] += ip_len  # bytes

    if start_time is None:
        return [], [], None

    max_bin = max(bins.keys(), default=0)
    times = [i * bin_size for i in range(max_bin + 1)]
    mbps = [(bins[i] * 8) / 1e6 for i in range(max_bin + 1)]
    return times, mbps, start_time


def compute_one_way_delay_ms(sender_path: Path, receiver_path: Path):
    """
    Match TCP packets and compute per-packet delay = receiver_ts - sender_ts.
    Returns (send_times, delays_ms) where send_times are relative to the first
    matched outer packet (so x 轴是发送时间线，y 轴是该包的时延)。

    Primary key: (src, dst, seq, ack, payload_len).
    Fallback key: (seq, payload_len) to tolerate地址/NAT变化。
    只统计有 payload 的 TCP 包（忽略纯 ACK），更符合“数据包时延”语义。
    """
    # 方向过滤：数据流 client->PEP->server。
    # - inner (sender): client->PEP，dport=9999
    # - outer (receiver): PEP->server，dport=5201
    # 需同时接受 5201 和 9999，否则 inner 里所有包会被过滤掉，sender 索引为空 → 无法匹配。
    def is_forward(tcp) -> bool:
        return tcp.dport in (5201, 9999)

    def make_key(ip, tcp, strict: bool):
        payload_len = len(tcp.payload)
        if strict:
            return (ip.src, ip.dst, tcp.seq, tcp.ack, payload_len)
        return (tcp.seq, payload_len)

    # Build strict and loose indexes
    strict_index = {}
    loose_index = {}
    sender_total = 0
    first_sender_ts = None

    for ts, ip, tcp in iter_tcp_packets(sender_path):
        if not is_forward(tcp):
            continue
        sender_total += 1
        payload_len = len(tcp.payload)
        if payload_len == 0:
            continue  # skip pure ACKs
        if first_sender_ts is None:
            first_sender_ts = ts
        # store strict
        strict_key = make_key(ip, tcp, True)
        strict_index.setdefault(strict_key, ts)
        # store loose
        loose_key = make_key(ip, tcp, False)
        loose_index.setdefault(loose_key, ts)

    delays = []  # list of (outer_rel_time, delay_ms)
    matches_strict = matches_loose = receiver_total = 0

    for ts, ip, tcp in iter_tcp_packets(receiver_path):
        if not is_forward(tcp):
            continue
        receiver_total += 1
        payload_len = len(tcp.payload)
        if payload_len == 0:
            continue  # skip pure ACKs

        strict_key = make_key(ip, tcp, True)
        loose_key = make_key(ip, tcp, False)

        if strict_key in strict_index:
            base_ts = strict_index[strict_key]
            matches_strict += 1
        elif loose_key in loose_index:
            base_ts = loose_index[loose_key]
            matches_loose += 1
        else:
            continue

        if first_sender_ts is None:
            continue

        delay_ms = (ts - base_ts) * 1000.0
        # 负值通常意味着匹配错包/方向不一致，直接丢弃
        if delay_ms < 0:
            continue
        send_rel = base_ts - first_sender_ts
        delays.append((send_rel, delay_ms))

    delays.sort(key=lambda x: x[0])
    times = [t for t, _ in delays]
    values = [d for _, d in delays]

    # Basic diagnostics
    print(f"[delay] sender packets: {sender_total}, receiver packets: {receiver_total}")
    print(f"[delay] strict matches: {matches_strict}, loose matches: {matches_loose}, total: {len(delays)}")

    return times, values


def compute_retrans_and_ooo(path: Path) -> Tuple[List[float], List[float], Optional[float], Optional[float]]:
    """
    对单个 pcap，按流(4 元组)统计：
    - 重传：相同 (seq, payload_len) 再次出现，视为重传（作为丢包的代理）
    - 乱序：若当前 seq < 已见的最大 (seq+len)，说明更大 seq 的包先到，当前包乱序

    只统计正向数据（dport 5201 或 9999）且 payload>0。
    返回 (retrans_ts, ooo_ts, first_ts, last_ts)，时间为绝对时间戳。
    """
    def is_forward(tcp) -> bool:
        return tcp.dport in (5201, 9999)

    flows = defaultdict(list)  # (src,dst,sport,dport) -> [(ts, seq, payload_len), ...]
    first_ts_global = None
    last_ts_global = None

    for ts, ip, tcp in iter_tcp_packets(path):
        if not is_forward(tcp):
            continue
        plen = len(tcp.payload)
        if plen == 0:
            continue
        key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        flows[key].append((ts, int(tcp.seq), plen))
        if first_ts_global is None:
            first_ts_global = ts
        last_ts_global = ts

    if first_ts_global is None:
        return [], [], None, None

    retrans_ts: List[float] = []
    ooo_ts: List[float] = []

    for _key, pkts in flows.items():
        pkts.sort(key=lambda x: x[0])
        seen_seq_len = set()  # (seq, len) 首次见
        max_end = 0
        for ts, seq, plen in pkts:
            # 重传：相同 (seq, len) 再次出现
            if (seq, plen) in seen_seq_len:
                retrans_ts.append(ts)
            else:
                seen_seq_len.add((seq, plen))
            # 乱序：当前 seq 小于已见的 max(seq+len)
            if max_end > 0 and seq < max_end:
                ooo_ts.append(ts)
            max_end = max(max_end, seq + plen)

    return retrans_ts, ooo_ts, first_ts_global, last_ts_global


def _bin_events(events: List[float], ref: float, bin_size: float, max_rel: float):
    """将事件时间戳按 bin 聚合为 (times, counts)。times 为 bin 左边界相对 ref 的秒数。"""
    bins = defaultdict(int)
    for t in events:
        rel = t - ref
        if rel < 0:
            continue
        idx = int(rel // bin_size)
        bins[idx] += 1
    n = max(1, int(max_rel / bin_size) + 1)
    times = [i * bin_size for i in range(n)]
    counts = [bins[i] for i in range(n)]
    return times, counts


def plot_loss_and_ooo(
    inner_retrans: List[float], inner_ooo: List[float], inner_first: float, inner_last: float,
    outer_retrans: List[float], outer_ooo: List[float], outer_first: float, outer_last: float,
    bin_size: float = 0.2,
):
    """
    画丢包（以重传为代理）与乱序的时序图：2 个子图，每个子图中 inner / outer 两条线。
    """
    ensure_output_dir()
    ref = min([x for x in (inner_first, outer_first) if x is not None], default=0.0)
    max_rel = max(
        (inner_last - ref) if inner_last is not None else 0.0,
        (outer_last - ref) if outer_last is not None else 0.0,
        max([t - ref for t in inner_retrans + inner_ooo], default=0.0),
        max([t - ref for t in outer_retrans + outer_ooo], default=0.0),
        1.0,
    )

    tin, rin = _bin_events(inner_retrans, ref, bin_size, max_rel)
    _, oin = _bin_events(inner_ooo, ref, bin_size, max_rel)
    tout, rout = _bin_events(outer_retrans, ref, bin_size, max_rel)
    _, oout = _bin_events(outer_ooo, ref, bin_size, max_rel)

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6), sharex=True)

    ax1.plot(tin, rin, label="Inner Retransmission", alpha=0.9)
    ax1.plot(tout, rout, label="Outer Retransmission", alpha=0.9)
    ax1.set_ylabel("Retransmission Times")
    ax1.set_title("Times vs Retransmission Times")
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    ax2.plot(tin, oin, label="Inner Outer of Order", alpha=0.9)
    ax2.plot(tout, oout, label="Outer Outer of Order", alpha=0.9)
    ax2.set_xlabel("Time (s)")
    ax2.set_ylabel("Outer of Order Packets Number")
    ax2.set_title("Outer of Order")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(OUT_DIR / "loss_ooo_timeline.png", dpi=200)
    plt.close()


# ===================== Buffer Occupancy 日志解析 & 绘图 =====================

def _parse_size_to_mb(size_str: str) -> float:
    """
    把 Buffer_Used 里的字符串（例如 "5.25 MB" / "512 KB" / "123 B"）转成 MB 的 float。
    """
    size_str = size_str.strip()
    if not size_str:
        return 0.0
    parts = size_str.split()
    if len(parts) != 2:
        return 0.0
    value, unit = parts
    try:
        v = float(value)
    except ValueError:
        return 0.0

    unit = unit.upper()
    if unit.startswith("MB"):
        return v
    if unit.startswith("KB"):
        return v / 1024.0
    if unit.endswith("B"):  # B
        return v / (1024.0 * 1024.0)
    return 0.0


def load_buffer_log(path: Path) -> Tuple[List[float], List[float], List[float]]:
    """
    读取一份 Buffer_Occupancy_*.log，返回:
      times: List[float]      # Time(s)
      buf_mb: List[float]     # Buffer_Used (MB)
      rates: List[float]      # Rate(Mbps)
    """
    times: List[float] = []
    buf_mb: List[float] = []
    rates: List[float] = []

    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            try:
                t = float(parts[0])
                buf_str = parts[1]
                rate = float(parts[4])
            except ValueError:
                continue

            times.append(t)
            buf_mb.append(_parse_size_to_mb(buf_str))
            rates.append(rate)

    return times, buf_mb, rates


def plot_buffer_and_rate(times, buf_mb, rates, out_prefix: str = "Buffer_Occupancy"):
    """
    画两张图：
      - {out_prefix}_buffer.png : Time vs Buffer_Used(MB)
      - {out_prefix}_rate.png   : Time vs Rate(Mbps)
    """
    ensure_output_dir()

    # 图 1：缓冲区占用
    plt.figure(figsize=(10, 4))
    plt.plot(times, buf_mb, label="Buffer used (MB)")
    plt.xlabel("Time (s)")
    plt.ylabel("Buffer used (MB)")
    plt.title("PEP Buffer Occupancy over time")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT_DIR / f"{out_prefix}_buffer.png", dpi=200)
    plt.close()

    # 图 2：发送速率
    plt.figure(figsize=(10, 4))
    plt.plot(times, rates, label="Send rate (Mbps)")
    plt.xlabel("Time (s)")
    plt.ylabel("Send rate (Mbps)")
    plt.title("PEP Send Rate over time")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT_DIR / f"{out_prefix}_rate.png", dpi=200)
    plt.close()


def plot_throughput(inner_data, outer_data):
    times_in, mbps_in = inner_data
    times_out, mbps_out = outer_data

    plt.figure(figsize=(10, 5))
    plt.plot(times_in, mbps_in, label="Inner throughput (Mbps)")
    plt.plot(times_out, mbps_out, label="Outer throughput (Mbps)", alpha=0.7)
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (Mbps)")
    plt.title("Throughput over time")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT_DIR / "throughput.png", dpi=200)
    plt.close()


def plot_delay(delays):
    times, values = delays
    plt.figure(figsize=(10, 5))
    if times and values:
        plt.plot(times, values, marker=".", linestyle="none", markersize=2, alpha=0.6)
    else:
        # 无匹配点时说明原因，避免空白图令人困惑
        plt.text(
            0.5, 0.5,
            "One-way delay: N/A\n\n"
            "在 PEP Ack Spoofing (Split-TCP) 下，inner 与 outer 是两条独立 TCP 连接，\n"
            "PEP 重新序列号发送，inner 的 (seq, len) 与 outer 无法对应，\n"
            "故无法通过 pcap 包匹配计算时延。\n\n"
            "若需时延，可在 PEP 内打点记录「从 inner 收到」与「向 outer 发出」的时间差并写日志。",
            transform=plt.gca().transAxes, ha="center", va="center", fontsize=10,
            bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.8),
        )
    plt.xlabel("Time (s)")
    plt.ylabel("One-way delay (ms)")
    plt.title("One-way delay (inner → outer)")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT_DIR / "delay.png", dpi=200)
    plt.close()


def main():
    ensure_output_dir()

    if not INNER_PCAP.exists() or not OUTER_PCAP.exists():
        raise FileNotFoundError(f"Missing pcap files under {PCAP_DIR}")

    print("Computing throughput...")
    tin, min_t, sin = compute_throughput_mbps(INNER_PCAP)
    tout, mout, sout = compute_throughput_mbps(OUTER_PCAP)

    # 对齐时间轴：以最早的首包时间为 0
    ref = min([t for t in (sin, sout) if t is not None], default=None)
    if ref is not None:
        tin = [t + (sin - ref) for t in tin]
        tout = [t + (sout - ref) for t in tout]
    inner_tp = (tin, min_t)
    outer_tp = (tout, mout)

    print("Computing one-way delay (inner -> outer)...")
    delays = compute_one_way_delay_ms(INNER_PCAP, OUTER_PCAP)

    print(f"Saving throughput/delay plots to {OUT_DIR}")
    plot_throughput(inner_tp, outer_tp)
    plot_delay(delays)

    # ====== 丢包（重传）与乱序时序 ======
    print("Computing retrans (loss proxy) and out-of-order...")
    in_ret, in_ooo, in_first, in_last = compute_retrans_and_ooo(INNER_PCAP)
    out_ret, out_ooo, out_first, out_last = compute_retrans_and_ooo(OUTER_PCAP)
    print(f"[loss/ooo] Inner: {len(in_ret)} retrans, {len(in_ooo)} ooo; Outer: {len(out_ret)} retrans, {len(out_ooo)} ooo")
    plot_loss_and_ooo(in_ret, in_ooo, in_first, in_last, out_ret, out_ooo, out_first, out_last)
    print(f"Saving loss/ooo timeline to {OUT_DIR / 'loss_ooo_timeline.png'}")

    # ====== 额外：读取 PEP_AckSpoofing 的 Buffer_Occupancy 日志并画图 ======
    if PEP_ACK_DIR.exists():
        log_paths = sorted(
            Path(p) for p in glob(str(PEP_ACK_DIR / "Buffer_Occupancy_*.log"))
        )
        if log_paths:
            for latest_log in log_paths:
                print(f"Loading buffer log from {latest_log}")
                times_buf, buf_mb, rates = load_buffer_log(latest_log)
                if times_buf:
                    print(f"Saving buffer/rate plots to {OUT_DIR}")
                    # 输出文件名前缀使用 log 文件名（不含扩展名）
                    out_prefix = latest_log.stem
                    plot_buffer_and_rate(times_buf, buf_mb, rates, out_prefix=out_prefix)
                else:
                    print(f"Buffer log {latest_log} is empty, skip buffer/rate plots")
        else:
            print(f"No Buffer_Occupancy_*.log found under {PEP_ACK_DIR}, skip buffer/rate plots")
    else:
        print(f"PEP_AckSpoofing data dir {PEP_ACK_DIR} does not exist, skip buffer/rate plots")

    print("Done.")


if __name__ == "__main__":
    main()

