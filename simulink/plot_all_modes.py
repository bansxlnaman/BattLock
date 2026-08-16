"""
Generate publication-ready plots for all 12 BattLock attack modes.

Input:  simulink/frames_verified_all.csv
Outputs:
    - simulink/integration_plot_all.png   (overview grid)
    - simulink/modes_overview.png         (attack-mode summary bar chart)

Run with:
    PYTHONPATH=. python simulink/plot_all_modes.py
"""

import csv
import os
import sys

import matplotlib.pyplot as plt
import numpy as np

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

DESCRIPTIONS = {
    0: "Normal",
    1: "Replay",
    2: "Spoof Sig",
    3: "Voltage Inj",
    4: "Drop Sig",
    5: "Spoof + Inj",
    6: "MITM",
    7: "Delay",
    8: "Fuzzing",
    9: "Session Hijack",
    10: "Evasion",
    11: "Cert Tamper",
}

COLORS = {
    "auth": "#2ca02c",
    "replay": "#d62728",
    "injection": "#ff7f0e",
    "soc": "#1f77b4",
}


def read_verified(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({k: float(v) for k, v in row.items()})
    return rows


def per_mode_summary(rows):
    modes = sorted({int(r["mode"]) for r in rows})
    summary = {}
    for m in modes:
        group = [r for r in rows if int(r["mode"]) == m]
        summary[m] = {
            "py_auth": max(r["py_auth"] for r in group),
            "py_replay": max(r["py_replay"] for r in group),
            "py_injection": max(r["py_injection"] for r in group),
            "model_auth": max(r["model_auth"] for r in group),
            "model_replay": max(r["model_replay"] for r in group),
            "model_injection": max(r["model_injection"] for r in group),
        }
    return summary


def plot_mode_grid(rows, out_path):
    modes = sorted({int(r["mode"]) for r in rows})
    n = len(modes)
    cols = 4
    rows_n = int(np.ceil(n / cols))

    fig, axes = plt.subplots(rows_n, cols, figsize=(18, 10), sharey=True)
    axes = axes.flatten()

    for idx, m in enumerate(modes):
        ax = axes[idx]
        g = [r for r in rows if int(r["mode"]) == m]
        t = [r["time"] for r in g]

        t = [r["time"] for r in g]
        ax.step(t, [r["py_auth"] for r in g],
                where="post", color=COLORS["auth"], linewidth=1.8, label="auth")
        ax.step(t, [r["py_replay"] for r in g],
                where="post", color=COLORS["replay"], linewidth=1.5, label="replay")
        ax.step(t, [r["py_injection"] for r in g],
                where="post", color=COLORS["injection"], linewidth=1.5, label="injection")
        ax.step(t, [r["model_soc"] / 85.0 for r in g],
                where="post", color=COLORS["soc"], linewidth=1.2,
                linestyle="--", label="SOC/85")

        ax.set_ylim(-0.2, 1.4)
        ax.set_title(f"mode {m}: {DESCRIPTIONS[m]}", fontsize=10)
        ax.set_xlabel("time (s)", fontsize=8)
        ax.grid(True, alpha=0.3)
        if idx == 0:
            ax.legend(loc="upper right", fontsize=7)

    for idx in range(n, len(axes)):
        axes[idx].axis("off")

    fig.suptitle("BattLock verification verdicts across all attack modes", fontsize=14)
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(out_path, dpi=200)
    plt.close()
    print(f"Wrote {out_path}")


def plot_summary_bars(summary, out_path):
    modes = sorted(summary.keys())
    labels = [DESCRIPTIONS[m] for m in modes]
    x = np.arange(len(modes))
    width = 0.25

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - width, [summary[m]["py_auth"] for m in modes], width,
           label="auth OK", color=COLORS["auth"])
    ax.bar(x, [summary[m]["py_replay"] for m in modes], width,
           label="replay detected", color=COLORS["replay"])
    ax.bar(x + width, [summary[m]["py_injection"] for m in modes], width,
           label="injection detected", color=COLORS["injection"])

    ax.set_ylabel("flag (max over mode)")
    ax.set_title("BattLock attack-mode summary: Python verifier outcomes")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.legend()
    ax.set_ylim(0, 1.2)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()
    print(f"Wrote {out_path}")


def main():
    simdir = os.path.join(repo_root, "simulink")
    verified_csv = os.path.join(simdir, "frames_verified_all.csv")
    rows = read_verified(verified_csv)
    summary = per_mode_summary(rows)

    plot_mode_grid(rows, os.path.join(simdir, "integration_plot_all.png"))
    plot_summary_bars(summary, os.path.join(simdir, "modes_overview.png"))


if __name__ == "__main__":
    main()
