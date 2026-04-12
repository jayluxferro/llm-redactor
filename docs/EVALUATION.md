# Evaluation

## Research questions

**RQ1**: What is the residual leak rate of each option (A–H) on a
ground-truth-labelled benchmark?

**RQ2**: How much does each option degrade response quality vs. a
baseline that sends the raw request?

**RQ3**: How does the privacy-utility trade-off vary by workload?

**RQ4**: Do combinations of options compose super-linearly,
linearly, or sub-linearly on residual leak rate?

**RQ5**: What is the minimum-viable detector quality for Option B
to be deployable at a given threat model's leak-rate budget?

## Workloads

Each workload is a set of input prompts with **ground-truth
annotations** identifying which spans are sensitive.

### WL1 — PII-heavy prose

Natural-language documents with embedded PII (names, emails, phone
numbers, addresses, employee IDs). Source: synthetic generation
from a template + public-corpus paraphrases. ~500 prompts, each
with annotated spans.

### WL2 — Secret-heavy configuration

Configuration files, logs, and code snippets containing API keys,
bearer tokens, certificates, and credentials. Source: synthetic
generation using pattern families from `POLICY.md`. ~300 prompts,
each with annotated spans.

### WL3 — Implicit-identity prose

Natural-language prose that identifies an individual or organisation
*without* using PII-span-level markers. ("the CFO of the company
whose product shipped last week", "our 2026 Q2 internal
retrospective document"). Source: hand-written + LLM-generated
with human review. ~200 prompts.

### WL4 — Proprietary code

Code containing internal function names, variable names,
database schema, and comments referencing internal projects.
Source: synthetic + scrubbed captures. ~300 prompts.

Each workload's ground truth lives in
`evals/workloads/<name>/annotations.jsonl`.

## Metrics

### Privacy metrics

- **Leak rate**: fraction of ground-truth sensitive spans that
  survived the pipeline and appear verbatim in the outgoing request
  to the cloud target.
- **Partial leak rate**: fraction of sensitive spans that appear
  partially (substring match of ≥ 4 chars).
- **Semantic leak rate**: fraction of sensitive *meaning* that
  survives, measured by a judge-model comparing original and
  redacted text.
- **False positive rate**: fraction of non-sensitive spans
  incorrectly redacted (causes quality loss).

### Utility metrics

- **Answer quality delta**: blind pairwise preference between the
  baseline response and the redacted-path response, measured by a
  judge model.
- **Task success rate**: for task-oriented prompts, fraction of
  responses that correctly accomplish the task (with human or
  judge-model grading).
- **Self-consistency**: fraction of multi-run prompts where the
  answer agrees with the baseline's answer on the key facts.

### Cost metrics

- **Added latency**: pipeline overhead per request, median + p95.
- **Added tokens**: local model tokens consumed by detection /
  rephrasing / validation, per request.
- **Dollar delta**: cloud tokens saved or added vs. baseline.

## Per-option matrix

For each option we report:

```
option, workload, leak_rate, partial_leak_rate, semantic_leak_rate,
fp_rate, quality_delta, task_success_delta, self_consistency,
latency_ms_median, latency_ms_p95, local_tokens, cloud_tokens,
cost_delta_usd
```

Plus pairwise combinations: `{A+B}`, `{B+C}`, `{B+D}`, `{B+H}`,
`{C+H}`, and the full stack `{A+B+C+D+H}`.

Total: 8 singletons + 5 pairs + 1 full-stack = 14 configurations
per workload × 4 workloads = 56 runs.

Each run processes all prompts in the workload and emits a CSV
row per prompt. ~1300 prompts × 56 configurations ≈ 73,000 sample
evaluations.

## Detector-level evaluation

Options A, D, F, G, E don't care about the detector. Options B, C,
H depend on it. For those three, we evaluate the **detector
independently** on WL1 + WL2:

- **Precision**: sensitive spans flagged / total spans flagged.
- **Recall**: sensitive spans flagged / ground-truth sensitive
  spans.
- **F1** per kind (email, phone, api_key, etc.).

The detector recall directly bounds Option B's leak rate.

## Judge models

- **Quality judge**: a different family from the cloud target so
  bias is minimized. (If cloud target is GPT-4o-mini, judge with
  Claude 3.5 Haiku, and vice versa.)
- **Leak judge**: a rule-based deterministic checker for WL1/WL2
  (string + regex match against annotations). Judge model is only
  used for WL3 (implicit identity).

## Reproducibility

- Every run records: software version (git SHA), detector
  versions, local model version, cloud model version, workload
  hash, wall-clock timestamp, config hash.
- Seeds fixed where possible. Local model temperature = 0 for
  deterministic detection.

## What success looks like

The paper is publishable if:

1. **Option B reaches ≤ 5% leak rate on WL1 + WL2** with ≤ 10%
   quality delta.
2. **Option C provides an additional ≥ 30% leak-rate reduction on
   WL3** over Option B alone.
3. **At least one combination is Pareto-better** than any single
   option on at least one workload.
4. **The detector's recall floor is quantified** — we can say "B
   works iff the detector reaches ≥ N% recall".
5. **Options E/F/G are documented as research** with a small demo
   showing a tiny-model FHE or split-inference pipeline running
   end-to-end, even if not production-viable.

## Ethics and data handling

- No real user prompts. Workloads are synthetic or scrubbed.
- All identifiers in the ground-truth annotations are fabricated.
- The paper's reproducibility artefact is a Docker image (or
  similar) containing all workloads + runner + scoring scripts.
- We follow responsible disclosure if we discover a specific
  failure mode in a commercial product (e.g. a specific vendor's
  SDK bypassing our proxy) — notify the vendor 30 days before
  publication.
