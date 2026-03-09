#!/usr/bin/env python3
"""
遍历 traces/A_download 下所有 trace 目录，
在每个 reconfiguration 周期内画出「包间隔」的散点图。
横轴：包序号（1-based，后一个包的编号）
纵轴：包间隔 = time[i+1] - time[i]（ms）

reconfiguration 周期检测逻辑与 plot_delay_reconfig_periods.py 一致。
"""

import os
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
A_DOWNLOAD_DIR = os.path.join(BASE_DIR, "A_download")


def load_delay_series(delay_path: str) -> Tuple[List[float], List[Tuple[int, int]]]:
    """
    读取 delay_{id}.txt，返回 delay_series 和 delay_values（用于周期检测）。
    """
    delay_series: List[float] = []
    delay_values: List[Tuple[int, int]] = []

    with open(delay_path, "r") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                delay_series.append(None)
                continue
            try:
                v = float(line)
            except ValueError:
                delay_series.append(None)
                continue

            delay_series.append(v)
            delay_values.append((int(v), idx))

    return delay_series, delay_values


def find_reconfig_offset_index(delay_values: List[Tuple[int, int]]) -> int:
    """复用 extract_reconfiguration.py 的思路，返回最佳相位 offset_index。"""
    if not delay_values:
        raise ValueError("empty delay_values")

    delay_values_15s = delay_values[:1500]
    if not delay_values_15s:
        raise ValueError("not enough delay data in first 15s")

    sorted_delay_values = sorted(delay_values, key=lambda x: x[0], reverse=True)[:100]
    large_value_index = {position for _, position in sorted_delay_values}

    possibility = [0] * len(delay_values_15s)
    for k, (_, position) in enumerate(delay_values_15s):
        i = position
        while i < 12000:
            i += 1500
            for j in range(-10, 11):
                if i + j in large_value_index:
                    possibility[k] += 1
                    break

    max_possibility = max(possibility)
    max_poss_indices = [i for i, p in enumerate(possibility) if p == max_possibility]

    if len(max_poss_indices) == 1:
        best_k = max_poss_indices[0]
    else:
        max_delay_in_candidates = max(delay_values_15s[i][0] for i in max_poss_indices)
        max_delay_indices = [
            i for i in max_poss_indices
            if delay_values_15s[i][0] == max_delay_in_candidates
        ]
        if len(max_delay_indices) == 1:
            best_k = max_delay_indices[0]
        else:
            avg_index = sum(max_delay_indices) / len(max_delay_indices)
            best_k = round(avg_index)

    return delay_values_15s[best_k][1]


def split_delay_by_periods(
    delay_series: List[float], offset_index: int, period_len: int = 1500
) -> Dict[int, Tuple[List[float], List[float]]]:
    """按 reconfiguration 周期切分，返回 {period_idx: (times_s, delays_ms)}。"""
    periods: Dict[int, Tuple[List[float], List[float]]] = {}

    for idx, v in enumerate(delay_series):
        if v is None:
            continue
        if idx < offset_index:
            continue

        rel = idx - offset_index
        if rel < 0:
            continue

        period_idx = rel // period_len
        offset_in_period = rel % period_len
        t_in_period_s = offset_in_period / 100.0

        if period_idx not in periods:
            periods[period_idx] = ([], [])

        periods[period_idx][0].append(t_in_period_s)
        periods[period_idx][1].append(v)

    return periods


def compute_inter_packet_intervals(
    times_s: List[float], _delays_ms: List[float]
) -> Tuple[List[int], List[float]]:
    """
    计算相邻包之间的时间间隔：interval[i] = time[i+1] - time[i]。
    横坐标取「第几个包」（1-based，后一个包的序号）。
    返回 (packet_indices, intervals_ms)。intervals 单位毫秒。
    """
    if len(times_s) < 2:
        return [], []

    packet_indices: List[int] = []
    intervals_ms: List[float] = []

    for i in range(len(times_s) - 1):
        interval_s = times_s[i + 1] - times_s[i]
        interval_ms = interval_s * 1000.0
        packet_indices.append(i + 2)  # 后一个包是第 (i+2) 个（1-based）
        intervals_ms.append(interval_ms)

    return packet_indices, intervals_ms


def plot_trace_intervals(trace_dir: str, trace_id: str) -> None:
    """
    对单个 trace，在每个 reconfiguration 周期内画出「包间隔」的散点图。
    """
    delay_path = os.path.join(trace_dir, f"delay_{trace_id}.txt")
    if not os.path.isfile(delay_path):
        print(f"[skip] {trace_dir}: delay_{trace_id}.txt not found")
        return

    print(f"[trace] {trace_id} in {trace_dir}")

    delay_series, delay_values = load_delay_series(delay_path)
    if not delay_values:
        print(f"[warn] {trace_dir}: no valid delay data")
        return

    try:
        offset_index = find_reconfig_offset_index(delay_values)
    except ValueError as e:
        print(f"[warn] {trace_dir}: {e}")
        return

    offset_time_s = offset_index / 100.0
    print(f"  - estimated reconfiguration offset: index={offset_index}, t={offset_time_s:.2f}s")

    periods = split_delay_by_periods(delay_series, offset_index, period_len=1500)
    if not periods:
        print(f"[warn] {trace_dir}: no periods found after offset")
        return

    for period_idx in sorted(periods.keys()):
        times_s, delays_ms = periods[period_idx]
        if len(times_s) < 2:
            print(f"  [skip] period {period_idx}: need at least 2 samples for interval")
            continue

        packet_indices, intervals_ms = compute_inter_packet_intervals(times_s, delays_ms)
        if not packet_indices:
            continue

        fig, ax = plt.subplots(figsize=(8, 4))
        ax.scatter(packet_indices, intervals_ms, s=10, color="tab:purple", alpha=0.7)

        ax.set_xlabel("Packet index (1-based)")
        ax.set_ylabel("Inter-packet interval (ms)\n(time[i+1] - time[i])")
        ax.set_title(
            f"Trace {trace_id} - Inter-packet interval, period {period_idx}\n"
            f"(global start ≈ {offset_time_s + period_idx * 15.0:.2f}s)"
        )
        ax.grid(True, linestyle="--", alpha=0.5)

        out_path = os.path.join(
            trace_dir,
            f"trace_{trace_id}_inter_interval_reconfig_period_{period_idx:02d}.png",
        )
        fig.tight_layout()
        fig.savefig(out_path, dpi=150)
        plt.close(fig)
        print(f"  [ok] saved period {period_idx} figure to {out_path}")


def main() -> None:
    if not os.path.isdir(A_DOWNLOAD_DIR):
        print(f"Error: A_download directory not found under {BASE_DIR}")
        return

    subdirs = sorted(
        d for d in os.listdir(A_DOWNLOAD_DIR)
        if os.path.isdir(os.path.join(A_DOWNLOAD_DIR, d))
    )
    if not subdirs:
        print("No subdirectories in A_download")
        return

    for name in subdirs:
        trace_dir = os.path.join(A_DOWNLOAD_DIR, name)
        trace_id = name
        plot_trace_intervals(trace_dir, trace_id)


if __name__ == "__main__":
    main()
