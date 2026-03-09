#!/usr/bin/env python3
"""
从 traces/ping_trace 下的 ping 日志中提取 RTT，并按 15 秒窗口画散点图。

输入文件格式示例（带时间戳的 ping 输出）：
  [1771030800.030183] 64 bytes from ... icmp_seq=1 ttl=63 time=25.3 ms

输出：
  在对应 trace 目录（如 traces/ping_trace/01/）下生成若干 png，
  每 15 秒一张图，便于观察细节。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

import matplotlib.pyplot as plt


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PING_TRACE_DIR = os.path.join(BASE_DIR, "ping_trace")

WINDOW_LEN_S = 15.0

# 只解析包含 RTT 的正常回包行
PING_LINE_RE = re.compile(
    r"^\[(?P<ts>[0-9]+\.[0-9]+)\].*?\btime=(?P<rtt>[0-9.]+)\s*ms\b"
)


@dataclass(frozen=True)
class PingSample:
    ts_s: float
    rtt_ms: float


def iter_ping_samples(path: str) -> Iterable[PingSample]:
    with open(path, "r") as f:
        for line in f:
            m = PING_LINE_RE.match(line.strip())
            if not m:
                continue
            try:
                ts_s = float(m.group("ts"))
                rtt_ms = float(m.group("rtt"))
            except ValueError:
                continue
            yield PingSample(ts_s=ts_s, rtt_ms=rtt_ms)


def load_samples(paths: List[str]) -> List[PingSample]:
    samples: List[PingSample] = []
    for p in paths:
        samples.extend(iter_ping_samples(p))
    samples.sort(key=lambda s: s.ts_s)
    return samples


def split_into_windows(
    samples: List[PingSample], window_len_s: float
) -> List[Tuple[float, float, List[PingSample]]]:
    """
    返回 [(win_start, win_end, samples_in_window), ...]。
    窗口从第一条样本时间向下取整到 window_len_s 的边界开始。
    """
    if not samples:
        return []

    t0 = samples[0].ts_s
    # 对齐到窗口边界，便于不同 trace 对比
    win_start = (t0 // window_len_s) * window_len_s
    win_end = win_start + window_len_s

    windows: List[Tuple[float, float, List[PingSample]]] = []
    buf: List[PingSample] = []

    for s in samples:
        while s.ts_s >= win_end:
            windows.append((win_start, win_end, buf))
            buf = []
            win_start = win_end
            win_end = win_start + window_len_s
        buf.append(s)

    windows.append((win_start, win_end, buf))
    return windows


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def plot_window(
    out_path: str,
    trace_id: str,
    win_start: float,
    win_end: float,
    samples: List[PingSample],
) -> None:
    # x 轴使用窗口内相对时间（0~15s），更方便看细节
    xs = [s.ts_s - win_start for s in samples]
    ys = [s.rtt_ms for s in samples]

    fig, ax = plt.subplots(figsize=(9, 4))
    ax.scatter(xs, ys, s=10, color="tab:blue", alpha=0.7)
    ax.set_xlabel("Time within window (s)")
    ax.set_ylabel("RTT (ms)")
    ax.set_title(f"Trace {trace_id} RTT ({win_start:.3f} - {win_end:.3f} s epoch)")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.set_xlim(0, WINDOW_LEN_S)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def list_trace_dirs(base_dir: str) -> List[str]:
    if not os.path.isdir(base_dir):
        return []
    subdirs = [
        os.path.join(base_dir, d)
        for d in sorted(os.listdir(base_dir))
        if os.path.isdir(os.path.join(base_dir, d))
    ]
    return subdirs


def list_txt_files(trace_dir: str) -> List[str]:
    return sorted(
        os.path.join(trace_dir, f)
        for f in os.listdir(trace_dir)
        if f.endswith(".txt") and os.path.isfile(os.path.join(trace_dir, f))
    )


def trace_id_from_dir(trace_dir: str) -> str:
    return os.path.basename(trace_dir.rstrip("/"))


def plot_one_trace(trace_dir: str) -> None:
    trace_id = trace_id_from_dir(trace_dir)
    txts = list_txt_files(trace_dir)
    if not txts:
        print(f"[skip] {trace_dir}: no .txt ping logs")
        return

    samples = load_samples(txts)
    if not samples:
        print(f"[warn] {trace_dir}: no RTT samples parsed")
        return

    windows = split_into_windows(samples, WINDOW_LEN_S)
    if not windows:
        print(f"[warn] {trace_dir}: no windows")
        return

    ensure_dir(trace_dir)
    print(f"[trace] {trace_id}: {len(samples)} samples, {len(windows)} windows")

    for i, (win_start, win_end, win_samples) in enumerate(windows):
        if not win_samples:
            continue
        out_path = os.path.join(trace_dir, f"trace_{trace_id}_rtt_{i:04d}.png")
        plot_window(out_path, trace_id, win_start, win_end, win_samples)


def main() -> None:
    trace_dirs = list_trace_dirs(PING_TRACE_DIR)
    if not trace_dirs:
        print(f"Error: ping_trace directory not found or empty under {BASE_DIR}")
        return

    for d in trace_dirs:
        plot_one_trace(d)


if __name__ == "__main__":
    main()

