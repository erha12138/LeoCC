#!/usr/bin/env python3
"""
遍历 traces/A_download 下所有 trace 目录，
对于每个 trace，根据时延文件 delay_{id}.txt 里推断的 reconfiguration 周期，
在每个周期内画出时延随「周期内时间」的走势（散点图），
并把图像保存到对应的 trace 目录下。

reconfiguration 周期的检测方法参考 extract_reconfiguration.py：
 - 假设每个周期长度为 1500 个采样点（即 15s，每行是 10ms）
 - 在前 15s 内寻找一个“相位” offset
 - 之后按 15s 为周期，在这个相位附近寻找大时延峰值
"""

import os
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
A_DOWNLOAD_DIR = os.path.join(BASE_DIR, "A_download")

# 移动平均窗口大小（以采样点为单位），每个采样点是 10ms
# 例如 100 表示 1 秒的平滑窗口
MOVING_AVG_WINDOW_SAMPLES = 10


def load_delay_series(delay_path: str) -> Tuple[List[float], List[Tuple[int, int]]]:
    """
    读取 delay_{id}.txt，返回：
    - delay_series: 按行顺序的时延（ms），无效行用 None 占位
    - delay_values: 列表 [(delay_int, index), ...]，用于做 reconfiguration 检测

    每一行对应一个 10ms 区间，因此 index * 0.01 即为秒数。
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
            # 与 extract_reconfiguration.py 一致，使用整数值参与周期检测
            delay_values.append((int(v), idx))

    return delay_series, delay_values


def find_reconfig_offset_index(delay_values: List[Tuple[int, int]]) -> int:
    """
    复用 extract_reconfiguration.py 中的思路，返回一个“最佳相位” offset_index（基于行号）。

    delay_values: [(value_int, position_index), ...]
    """
    if not delay_values:
        raise ValueError("empty delay_values")

    # 前 15s（1500 个采样点）作为候选相位
    delay_values_15s = delay_values[:1500]
    if not delay_values_15s:
        raise ValueError("not enough delay data in first 15s")

    # 所有数据里选出前 100 个最大值的下标集合，作为“高时延”位置
    sorted_delay_values = sorted(delay_values, key=lambda x: x[0], reverse=True)[:100]
    large_value_index = {position for _, position in sorted_delay_values}

    # 在前 15s 的每个候选点，考察其后若干个 15s 周期里是否经常出现在高时延附近
    possibility = [0] * len(delay_values_15s)
    for k, (_, position) in enumerate(delay_values_15s):
        i = position
        # 最长考察到 12000（大约 120s），与 extract_reconfiguration.py 一致
        while i < 12000:
            i += 1500  # 假定周期为 1500 采样点（15s）
            for j in range(-10, 11):  # 在该周期相位的 ±10 个采样点内寻找高时延
                if i + j in large_value_index:
                    possibility[k] += 1
                    break

    # 和 extract_reconfiguration.py 中的 find_best_index 一样的决策逻辑
    max_possibility = max(possibility)
    max_poss_indices = [i for i, p in enumerate(possibility) if p == max_possibility]

    if len(max_poss_indices) == 1:
        best_k = max_poss_indices[0]
    else:
        max_delay_in_candidates = max(delay_values_15s[i][0] for i in max_poss_indices)
        max_delay_indices = [
            i
            for i in max_poss_indices
            if delay_values_15s[i][0] == max_delay_in_candidates
        ]
        if len(max_delay_indices) == 1:
            best_k = max_delay_indices[0]
        else:
            avg_index = sum(max_delay_indices) / len(max_delay_indices)
            best_k = round(avg_index)

    # 返回对应的原始位置（行号）
    return delay_values_15s[best_k][1]


def split_delay_by_periods(
    delay_series: List[float], offset_index: int, period_len: int = 1500
) -> Dict[int, Tuple[List[float], List[float]]]:
    """
    按 reconfiguration 周期把时延序列切分：
    - offset_index: 第一个周期的相位起点（行号）
    - period_len: 周期长度，默认 1500 个采样点（15s）

    返回：
    - {period_idx: (times_in_period_s, delays_ms)}
      其中 times_in_period_s 是相对于该周期起点的时间（秒，0~15）。
    """
    periods: Dict[int, Tuple[List[float], List[float]]] = {}

    for idx, v in enumerate(delay_series):
        if v is None:
            continue
        # 在 offset 之前的数据不认为属于任何周期，直接跳过
        if idx < offset_index:
            continue

        rel = idx - offset_index
        if rel < 0:
            continue

        period_idx = rel // period_len
        offset_in_period = rel % period_len

        t_in_period_s = offset_in_period / 100.0  # 每行 10ms -> 0.01s

        if period_idx not in periods:
            periods[period_idx] = ([], [])

        periods[period_idx][0].append(t_in_period_s)
        periods[period_idx][1].append(v)

    return periods


def moving_average(
    times: List[float], values: List[float], window_size: int
) -> Tuple[List[float], List[float]]:
    """
    简单的移动平均平滑：
    - 在每个点附近取一个长度为 window_size 的窗口
    - 平均该窗口内的 delay，时间取该窗口内时间的平均值
    """
    n = len(values)
    if n == 0 or window_size <= 1 or n <= window_size:
        # 点太少或者窗口太大，就直接返回原始数据
        return times, values

    half = window_size // 2
    smooth_t: List[float] = []
    smooth_v: List[float] = []

    for i in range(n):
        left = max(0, i - half)
        right = min(n, i + half + 1)
        window_vals = values[left:right]
        window_times = times[left:right]

        smooth_v.append(sum(window_vals) / len(window_vals))
        smooth_t.append(sum(window_times) / len(window_times))

    return smooth_t, smooth_v


def plot_trace_reconfig_periods(trace_dir: str, trace_id: str) -> None:
    """
    对单个 trace：
    1. 读取 delay_{trace_id}.txt
    2. 根据 delay 序列估计 reconfiguration 周期相位 offset
    3. 按周期切分，并为每个周期画一张 delay vs. 周期内时间 的散点图
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
        if not times_s:
            continue

        fig, ax = plt.subplots(figsize=(8, 4))
        # 原始散点，展示细节
        ax.scatter(times_s, delays_ms, s=10, color="tab:orange", label="raw delay")

        # 平滑均值折线，展示趋势（默认 1 秒窗口）
        smooth_t, smooth_v = moving_average(
            times_s, delays_ms, window_size=MOVING_AVG_WINDOW_SAMPLES
        )
        ax.plot(smooth_t, smooth_v, color="tab:blue", linewidth=1.5, label="1s moving average")

        ax.set_xlabel("Time within reconfiguration period (s)")
        ax.set_ylabel("One-way delay (ms)")
        ax.set_title(
            f"Trace {trace_id} - Reconfiguration period {period_idx}\n"
            f"(global start ≈ {offset_time_s + period_idx * 15.0:.2f}s)"
        )
        ax.grid(True, linestyle="--", alpha=0.5)
        ax.legend(loc="upper right")
        ax.set_xlim(0, 15)

        out_path = os.path.join(
            trace_dir,
            f"trace_{trace_id}_delay_reconfig_period_{period_idx:02d}.png",
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
        d for d in os.listdir(A_DOWNLOAD_DIR) if os.path.isdir(os.path.join(A_DOWNLOAD_DIR, d))
    )
    if not subdirs:
        print("No subdirectories in A_download")
        return

    for name in subdirs:
        trace_dir = os.path.join(A_DOWNLOAD_DIR, name)
        trace_id = name  # 假设子目录名就是 trace 编号
        plot_trace_reconfig_periods(trace_dir, trace_id)


if __name__ == "__main__":
    main()

