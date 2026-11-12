"""Upload the LLM-Redactor Leak Benchmark to Hugging Face Datasets.

Run with:  uv run --extra hf python scripts/upload_hf_dataset.py

The card's counts and annotation kinds are computed from the workload files
at upload time (they were hard-coded, and the kind lists had drifted).
"""

import json
from pathlib import Path

from datasets import Dataset, Features, Sequence, Value
from huggingface_hub import HfApi

REPO_ID = "jayluxferro/llm-redactor-leak-benchmark"
WORKLOADS_DIR = Path(__file__).resolve().parent.parent / "evals" / "workloads"

WORKLOADS = {
    "wl1_pii": "PII (names, emails, phones, addresses, SSNs)",
    "wl2_secrets": "Secrets (API keys, passwords, tokens, hostnames)",
    "wl3_implicit": "Implicit identity (indirect references to people/orgs)",
    "wl4_code": "Code (internal functions, database names, project names)",
}

DATASET_CARD = """\
---
language:
  - en
license: mit
pretty_name: LLM-Redactor Leak Benchmark
size_categories:
  - 1K<n<10K
task_categories:
  - token-classification
tags:
  - privacy
  - pii
  - redaction
  - llm
  - secrets-detection
  - ner
configs:
  - config_name: default
    data_files:
      - split: train
        path: data/train-*.parquet
  - config_name: wl1_pii
    data_files:
      - split: train
        path: wl1_pii/train-*.parquet
  - config_name: wl2_secrets
    data_files:
      - split: train
        path: wl2_secrets/train-*.parquet
  - config_name: wl3_implicit
    data_files:
      - split: train
        path: wl3_implicit/train-*.parquet
  - config_name: wl4_code
    data_files:
      - split: train
        path: wl4_code/train-*.parquet
---

# LLM-Redactor Leak Benchmark

A benchmark of **<<N_SAMPLES>> synthetic prompts** with **<<N_ANNOTATIONS>> ground-truth
annotations** spanning four workload classes, designed to evaluate
privacy-preserving techniques for outbound LLM requests.

Released alongside the paper:

> **LLM-Redactor: An Empirical Evaluation of Eight Techniques for
> Privacy-Preserving LLM Requests**
>
> Justice Owusu Agyemang, Jerry John Kponyo, Elliot Amponsah,
> Godfred Manu Addo Boakye, Kwame Opuni-Boachie Obour Agyekum
>
> [arXiv:2604.12064](https://arxiv.org/abs/2604.12064)

## Workload classes

| Config | Samples | Description |
|--------|---------|-------------|
<<WORKLOAD_TABLE>>

## Usage

```python
from datasets import load_dataset

# Load everything
ds = load_dataset("jayluxferro/llm-redactor-leak-benchmark")

# Load a single workload
pii = load_dataset("jayluxferro/llm-redactor-leak-benchmark", "wl1_pii")
```

## Schema

Each sample has the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique identifier (e.g. `wl1_0042`) |
| `text` | `string` | The input prompt to evaluate |
| `workload` | `string` | Workload class (`wl1_pii`, `wl2_secrets`, `wl3_implicit`, `wl4_code`) |
| `annotations` | `list[object]` | Ground-truth sensitive spans |
| `annotations[].start` | `int` | Start character offset |
| `annotations[].end` | `int` | End character offset |
| `annotations[].kind` | `string` | Sensitivity type (`person`, `email`, `api_key`, `implicit`) |
| `annotations[].text` | `string` | The verbatim sensitive span |

## Annotation kinds

<<KIND_LISTS>>

## Citation

```bibtex
@misc{agyemang2026llmredactor,
  title={LLM-Redactor: An Empirical Evaluation of Eight Techniques for \
Privacy-Preserving LLM Requests},
  author={Agyemang, Justice Owusu and Kponyo, Jerry John and Amponsah, \
Elliot and Boakye, Godfred Manu Addo and Agyekum, Kwame Opuni-Boachie Obour},
  year={2026},
  url={https://arxiv.org/abs/2604.12064}
}
```

## License

MIT
"""


def load_workload(name: str) -> list[dict]:
    """Load a single workload JSONL file and add the workload column."""
    path = WORKLOADS_DIR / name / "annotations.jsonl"
    rows = []
    with open(path) as f:
        for line in f:
            record = json.loads(line)
            record["workload"] = name
            rows.append(record)
    return rows


def render_card(workloads: dict[str, list[dict]]) -> str:
    """The dataset card, with every number and kind list taken from the data."""
    rows = [r for wl in workloads.values() for r in wl]
    table = "\n".join(
        f"| `{name}` | {len(workloads[name])} | {WORKLOADS[name]} |" for name in workloads
    )
    kinds = "\n\n".join(
        f"**{name}:** "
        + ", ".join(f"`{k}`" for k in sorted({a["kind"] for r in wl for a in r["annotations"]}))
        for name, wl in workloads.items()
    )
    return (
        DATASET_CARD.replace("<<N_SAMPLES>>", f"{len(rows):,}")
        .replace("<<N_ANNOTATIONS>>", f"{sum(len(r['annotations']) for r in rows):,}")
        .replace("<<WORKLOAD_TABLE>>", table)
        .replace("<<KIND_LISTS>>", kinds)
    )


def main():
    features = Features(
        {
            "id": Value("string"),
            "text": Value("string"),
            "workload": Value("string"),
            "annotations": Sequence(
                {
                    "start": Value("int32"),
                    "end": Value("int32"),
                    "kind": Value("string"),
                    "text": Value("string"),
                }
            ),
        }
    )

    # Build per-workload datasets and a combined one
    splits = {}
    all_rows = []
    loaded = {name: load_workload(name) for name in WORKLOADS}
    for wl_name, rows in loaded.items():
        splits[wl_name] = Dataset.from_list(rows, features=features)
        all_rows.extend(rows)
        print(f"  {wl_name}: {len(rows)} samples")

    print(f"  Total: {len(all_rows)} samples")

    # Build a combined dataset too
    combined = Dataset.from_list(all_rows, features=features)

    # Push as a DatasetDict with per-workload configs
    # First push the combined default config
    combined.push_to_hub(REPO_ID, private=False)
    print(f"  Uploaded default config (all {len(all_rows)} samples)")

    # Push each workload as a named config
    for wl_name, ds in splits.items():
        ds.push_to_hub(REPO_ID, config_name=wl_name)
        print(f"  Uploaded config: {wl_name}")

    # Upload the dataset card (overwrites auto-generated one)
    api = HfApi()
    api.upload_file(
        path_or_fileobj=render_card(loaded).encode(),
        path_in_repo="README.md",
        repo_id=REPO_ID,
        repo_type="dataset",
    )
    print("  Uploaded dataset card")

    print(f"\nDone! https://huggingface.co/datasets/{REPO_ID}")


if __name__ == "__main__":
    main()
