"""Generate paper figures from all evaluation results."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib  # type: ignore[import-not-found]

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # type: ignore[import-not-found]
import numpy as np

RESULTS_DIR = Path(__file__).parent
FIGURES_DIR = Path(__file__).parent.parent / "paper" / "figures"


def load_csv(result_dir: Path) -> list[dict]:
    """Load results.csv from a result directory."""
    csv_path = result_dir / "results.csv"
    if not csv_path.exists():
        return []
    rows = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def collect_all_results() -> list[dict]:
    """Collect results from all result directories."""
    all_rows = []
    for d in sorted(RESULTS_DIR.iterdir()):
        if d.is_dir() and d.name.startswith("results_"):
            rows = load_csv(d)
            all_rows.extend(rows)
    return all_rows


def fig_leak_rates(rows: list[dict]) -> None:
    """Bar chart: exact leak rate per option per workload."""
    # Select the key options for the main figure.
    key_options = {
        "baseline": "Baseline",
        "B": "B (NER)",
        "B+C": "B+C",
        "A(local)": "A",
        "A+B(cloud)": "A+B",
        "A+B+C(cloud)": "A+B+C",
    }

    workloads = ["wl1_pii", "wl2_secrets", "wl3_implicit", "wl4_code"]
    wl_labels = ["WL1\nPII", "WL2\nSecrets", "WL3\nImplicit", "WL4\nCode"]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(workloads))
    n_opts = len(key_options)
    width = 0.8 / n_opts
    colors = plt.cm.Set2(np.linspace(0, 1, n_opts))

    for i, (opt_key, opt_label) in enumerate(key_options.items()):
        rates = []
        for wl in workloads:
            matching = [r for r in rows if r["option"] == opt_key and r["workload"] == wl]
            if matching:
                rates.append(float(matching[0]["exact_leak_rate"]))
            else:
                rates.append(0.0)
        ax.bar(x + i * width, rates, width, label=opt_label, color=colors[i])

    ax.set_xlabel("Workload", fontsize=12)
    ax.set_ylabel("Exact Leak Rate", fontsize=12)
    ax.set_title("Residual Exact Leak Rate per Option per Workload", fontsize=13)
    ax.set_xticks(x + width * (n_opts - 1) / 2)
    ax.set_xticklabels(wl_labels)
    ax.legend(loc="upper right", fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "leak_rates.pdf")
    fig.savefig(FIGURES_DIR / "leak_rates.png", dpi=150)
    plt.close(fig)
    print("  leak_rates.pdf")


def fig_leak_by_kind(rows: list[dict]) -> None:
    """Horizontal bar chart: Option B (NER) leak rate by annotation kind on WL1."""
    # Read the leak breakdown from the NER results.
    breakdown_path = RESULTS_DIR / "results_b_ner_v2" / "leak_breakdown.md"
    if not breakdown_path.exists():
        breakdown_path = RESULTS_DIR / "results_ner" / "leak_breakdown.md"
    if not breakdown_path.exists():
        print("  (skipped leak_by_kind — no breakdown file)")
        return

    kinds = []
    rates = []
    for line in breakdown_path.read_text().splitlines():
        if line.startswith("|") and not line.startswith("| Kind") and not line.startswith("|---"):
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) == 2:
                kinds.append(parts[0])
                rates.append(float(parts[1]))

    if not kinds:
        print("  (skipped leak_by_kind — empty)")
        return

    # Sort by rate descending.
    paired = sorted(zip(rates, kinds), reverse=True)
    rates_sorted = [p[0] for p in paired]
    kinds_sorted = [p[1] for p in paired]

    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ["#d32f2f" if r > 0.5 else "#ff9800" if r > 0.1 else "#4caf50" for r in rates_sorted]
    y = np.arange(len(kinds_sorted))
    ax.barh(y, rates_sorted, color=colors, edgecolor="white")
    ax.set_yticks(y)
    ax.set_yticklabels(kinds_sorted, fontsize=10)
    ax.set_xlabel("Exact Leak Rate", fontsize=12)
    ax.set_title("Option B (NER) Leak Rate by Annotation Kind (WL1)", fontsize=13)
    ax.set_xlim(0, 1.05)
    ax.invert_yaxis()
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "leak_by_kind.pdf")
    fig.savefig(FIGURES_DIR / "leak_by_kind.png", dpi=150)
    plt.close(fig)
    print("  leak_by_kind.pdf")


def fig_pareto(rows: list[dict]) -> None:
    """Scatter: exact leak rate vs latency for WL1."""
    pareto_options = ["B", "B+C", "B+H(e=4.0)", "A(local)", "A+B(cloud)", "A+B+C(cloud)"]
    wl = "wl1_pii"

    fig, ax = plt.subplots(figsize=(8, 5))
    for opt in pareto_options:
        matching = [r for r in rows if r["option"] == opt and r["workload"] == wl]
        if not matching:
            continue
        r = matching[0]
        leak = float(r["exact_leak_rate"])
        lat = float(r["latency_ms_median"]) if r["latency_ms_median"] else 0
        ax.scatter(lat, leak, s=100, zorder=5)
        label = opt.replace("(local)", "").replace("(e=", " e=").replace(")", "")
        ax.annotate(label, (lat, leak), textcoords="offset points", xytext=(8, 4), fontsize=9)

    ax.set_xlabel("Median Latency (ms)", fontsize=12)
    ax.set_ylabel("Exact Leak Rate", fontsize=12)
    ax.set_title("Privacy-Latency Pareto Frontier (WL1 PII)", fontsize=13)
    ax.set_ylim(-0.02, 0.5)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "pareto.pdf")
    fig.savefig(FIGURES_DIR / "pareto.png", dpi=150)
    plt.close(fig)
    print("  pareto.pdf")


def main() -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    rows = collect_all_results()
    print(f"Loaded {len(rows)} result rows")
    fig_leak_rates(rows)
    fig_leak_by_kind(rows)
    fig_pareto(rows)
    print("Done.")


if __name__ == "__main__":
    main()
