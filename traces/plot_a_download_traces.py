#!/usr/bin/env python3
"""
遍历 traces/A_download 下所有 trace 目录，
为每个 trace 画出带宽和时延随时间变化的图，并保存在对应的 trace 目录内。

带宽来源：bw_{id}.txt
  - 每一行是某个毫秒的时间戳 t（整数，单位 ms）
  - 同一个时间戳 t 连续出现 N 行，表示该毫秒的带宽为 12 * N Mbps

时延来源：delay_{id}.txt
  - 第 i 行对应第 i 个 10ms 区间 [10(i-1), 10i) ms
  - 该行的值是该区间的单向时延（毫秒）
"""

import os
from collections import Counter

import matplotlib.pyplot as plt


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
A_DOWNLOAD_DIR = os.path.join(BASE_DIR, "A_download")


def load_bandwidth_trace(bw_path):
    """
    从 bw_{id}.txt 解析出 (time_s, bw_mbps) 序列。
    """
    counts = Counter()
    with open(bw_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                t_ms = int(line)
            except ValueError:
                continue
            counts[t_ms] += 1

    if not counts:
        return [], []

    times_ms = sorted(counts.keys())
    times_s = [t / 1000.0 for t in times_ms]
    bw_mbps = [12.0 * counts[t] for t in times_ms]
    return times_s, bw_mbps


def load_delay_trace(delay_path):
    """
    从 delay_{id}.txt 解析出 (time_s, delay_ms) 序列。
    使用每个 10ms 区间的起点时间作为横坐标。
    """
    times_s = []
    delays_ms = []
    with open(delay_path, "r") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                d_ms = float(line)
            except ValueError:
                continue
            t_start_ms = (idx - 1) * 10.0
            times_s.append(t_start_ms / 1000.0)
            delays_ms.append(d_ms)
    return times_s, delays_ms


def plot_one_trace(trace_dir, trace_id):
    """
    为单个 trace 画图并保存。
    这里按 10 秒一张图切分时间轴：每个窗口 [k*10, (k+1)*10) 秒一张图。
    """
    bw_path = os.path.join(trace_dir, f"bw_{trace_id}.txt")
    delay_path = os.path.join(trace_dir, f"delay_{trace_id}.txt")

    if not os.path.isfile(bw_path) or not os.path.isfile(delay_path):
        print(f"[skip] {trace_dir}: bw/delay file not found")
        return

    print(f"[plot] trace {trace_id} in {trace_dir}")

    bw_t, bw_mbps = load_bandwidth_trace(bw_path)
    d_t, d_ms = load_delay_trace(delay_path)

    if not bw_t and not d_t:
        print(f"[warn] {trace_dir}: no data to plot")
        return

    # 确定整条 trace 的时间范围（秒）
    max_t = 0.0
    if bw_t:
        max_t = max(max_t, max(bw_t))
    if d_t:
        max_t = max(max_t, max(d_t))

    if max_t <= 0:
        print(f"[warn] {trace_dir}: max_t <= 0")
        return

    window_len = 10.0  # 每个窗口 10 秒
    num_windows = int(max_t // window_len) + 1

    for w in range(num_windows):
        start = w * window_len
        end = start + window_len

        # 选取这个时间窗口内的数据
        bw_t_win = [t for t in bw_t if start <= t < end]
        bw_v_win = [v for t, v in zip(bw_t, bw_mbps) if start <= t < end]

        d_t_win = [t for t in d_t if start <= t < end]
        d_v_win = [v for t, v in zip(d_t, d_ms) if start <= t < end]

        # 如果这个窗口里既没有带宽也没有时延数据，就跳过
        if not bw_t_win and not d_t_win:
            continue

        fig, (ax_bw, ax_delay) = plt.subplots(
            2, 1, figsize=(10, 6), sharex=True, constrained_layout=True
        )

        if bw_t_win:
            ax_bw.plot(bw_t_win, bw_v_win, color="tab:blue")
            ax_bw.set_ylabel("Bandwidth (Mbps)")
            ax_bw.grid(True, linestyle="--", alpha=0.5)
        else:
            ax_bw.text(
                0.5, 0.5, "No bandwidth data",
                ha="center", va="center", transform=ax_bw.transAxes,
            )

        if d_t_win:
            ax_delay.scatter(d_t_win, d_v_win, color="tab:orange", s=10)
            ax_delay.set_ylabel("One-way delay (ms)")
            ax_delay.grid(True, linestyle="--", alpha=0.5)
        else:
            ax_delay.text(
                0.5, 0.5, "No delay data",
                ha="center", va="center", transform=ax_delay.transAxes,
            )

        ax_delay.set_xlabel("Time (s)")
        fig.suptitle(f"Trace {trace_id}: Bandwidth & Delay ({start:.1f}-{end:.1f}s)")

        # 文件名中带上时间窗口，仍然保存在原 trace 目录下
        out_path = os.path.join(
            trace_dir,
            f"trace_{trace_id}_bw_delay_{int(start):04d}_{int(end):04d}.png",
        )
        fig.savefig(out_path, dpi=150)
        plt.close(fig)
        print(f"[ok] saved figure to {out_path}")


def main():
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
        # 假设子目录名就是 trace 编号（如 '1', '2', ...）
        trace_id = name
        plot_one_trace(trace_dir, trace_id)


if __name__ == "__main__":
    main()

