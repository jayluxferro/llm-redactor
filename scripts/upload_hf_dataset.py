"""Upload the LLM-Redactor Leak Benchmark to Hugging Face Datasets."""

import json
from pathlib import Path

from datasets import Dataset, DatasetDict, Features, Sequence, Value
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

A benchmark of **1,300 synthetic prompts** with **4,014 ground-truth
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
| `wl1_pii` | 500 | Names, emails, phone numbers, addresses, SSNs, employee IDs |
| `wl2_secrets` | 300 | API keys, AWS credentials, passwords, hostnames in configs/code |
| `wl3_implicit` | 200 | Indirect references that identify people or organisations |
| `wl4_code` | 300 | Internal function names, database schemas, project names |

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
| `annotations[].kind` | `string` | Sensitivity type (e.g. `person`, `email`, `api_key`, `implicit`) |
| `annotations[].text` | `string` | The verbatim sensitive span |

## Annotation kinds

**WL1 (PII):** `person`, `email`, `phone`, `address`, `ssn`, `employee_id`, `org_name`

**WL2 (Secrets):** `aws_access_key`, `aws_secret_key`, `api_key`, `password`, `hostname`

**WL3 (Implicit):** `implicit`, `org_name`

**WL4 (Code):** `project_name`, `org_name`, `internal_function`, `database_name`, `table_name`, `api_key`, `hostname`

## Citation

```bibtex
@article{agyemang2026llmredactor,
  title={LLM-Redactor: An Empirical Evaluation of Eight Techniques for Privacy-Preserving LLM Requests},
  author={Agyemang, Justice Owusu and Kponyo, Jerry John and Amponsah, Elliot and Boakye, Godfred Manu Addo and Agyekum, Kwame Opuni-Boachie Obour},
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
    for wl_name in WORKLOADS:
        rows = load_workload(wl_name)
        splits[wl_name] = Dataset.from_list(rows, features=features)
        all_rows.extend(rows)
        print(f"  {wl_name}: {len(rows)} samples")

    print(f"  Total: {len(all_rows)} samples")

    # Build a combined dataset too
    combined = Dataset.from_list(all_rows, features=features)

    # Push as a DatasetDict with per-workload configs
    # First push the combined default config
    combined.push_to_hub(REPO_ID, private=False)
    print("  Uploaded default config (all 1300 samples)")

    # Push each workload as a named config
    for wl_name, ds in splits.items():
        ds.push_to_hub(REPO_ID, config_name=wl_name)
        print(f"  Uploaded config: {wl_name}")

    # Upload the dataset card (overwrites auto-generated one)
    api = HfApi()
    api.upload_file(
        path_or_fileobj=DATASET_CARD.encode(),
        path_in_repo="README.md",
        repo_id=REPO_ID,
        repo_type="dataset",
    )
    print("  Uploaded dataset card")

    print(f"\nDone! https://huggingface.co/datasets/{REPO_ID}")


if __name__ == "__main__":
    main()
