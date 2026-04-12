"""Generate all workloads and write to evals/workloads/."""

from __future__ import annotations

from pathlib import Path

from .generators.wl1_pii import generate_wl1
from .generators.wl2_secrets import generate_wl2
from .generators.wl3_implicit import generate_wl3
from .generators.wl4_code import generate_wl4
from .schema import write_workload

WORKLOADS_DIR = Path(__file__).parent / "workloads"


def generate_all() -> dict[str, int]:
    """Generate all workloads. Returns {name: count} dict."""
    results: dict[str, int] = {}

    wl1 = generate_wl1(n=500)
    write_workload(wl1, WORKLOADS_DIR / "wl1_pii" / "annotations.jsonl")
    results["wl1_pii"] = len(wl1)

    wl2 = generate_wl2(n=300)
    write_workload(wl2, WORKLOADS_DIR / "wl2_secrets" / "annotations.jsonl")
    results["wl2_secrets"] = len(wl2)

    wl3 = generate_wl3(n=200)
    write_workload(wl3, WORKLOADS_DIR / "wl3_implicit" / "annotations.jsonl")
    results["wl3_implicit"] = len(wl3)

    wl4 = generate_wl4(n=300)
    write_workload(wl4, WORKLOADS_DIR / "wl4_code" / "annotations.jsonl")
    results["wl4_code"] = len(wl4)

    return results


if __name__ == "__main__":
    counts = generate_all()
    total_annotations = 0
    for name, count in counts.items():
        print(f"  {name}: {count} samples")
    print(f"  Total: {sum(counts.values())} samples")
