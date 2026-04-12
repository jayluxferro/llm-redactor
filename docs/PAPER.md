# Paper outline

Working title:

> **LLM-Redactor: An Empirical Evaluation of Eight Techniques for
> Privacy-Preserving LLM Requests**

Target venue: **arXiv cs.CR** (primary), **cs.LG** (cross-list).
Long-term: a security venue (USENIX Security, PETS, CCS) once the
paper has been on arXiv for a few months.

## Abstract (target: 200 words)

Coding agents and LLM-powered applications routinely send
potentially sensitive content to cloud LLM APIs where it may be
logged, used for training, or subject to subpoena. We present a
systematic empirical evaluation of eight techniques for
privacy-preserving LLM requests: local-only inference, redaction
with placeholder restoration, semantic rephrasing, Trusted
Execution Environments, split inference, fully homomorphic
encryption, multi-party computation, and differential-privacy
noise. We implement all eight (or a tractable subset for the
research-stage options) in an open-source shim that speaks both
MCP and the OpenAI-compatible HTTP surface, and we evaluate them
across four workload classes using ground-truth-labelled leak
benchmarks. Our headline finding is **TBD**. We quantify the
residual leak rate of each technique and show that no single
option dominates across all workloads, motivating a
workload-aware approach. We release our implementation,
benchmarks, and evaluation harness to enable reproduction and
extension.

## Outline

### 1. Introduction

- Cloud LLM APIs have become infrastructure for developer
  workflows. Every prompt is potentially logged, retained, or
  used for training.
- Existing privacy tools focus on either network-level
  encryption (TLS) or organisation-level DLP (commit scanners).
  Neither addresses the in-prompt leakage problem.
- Eight distinct techniques exist in the literature and in
  practice; no prior work has measured them head-to-head.
- Contributions:
  - A taxonomy of eight techniques organised by their privacy
    property, utility cost, and practicality today.
  - A reference implementation and a ground-truth-labelled
    benchmark.
  - Residual leak rates per technique and per combination.
  - A decision rule for practitioners.

### 2. Background and Threat Model

(Fill from `docs/THREAT_MODEL.md`.)

### 3. Related Work

- **Presidio** and PII detection literature~\cite{TODO-presidio}.
- **Homomorphic encryption** for ML: CryptoNets, HE-Transformer,
  Zama's fhEVM~\cite{TODO}.
- **MPC for inference**: CrypTen, SecureML, MP-SPDZ.
- **Split learning / federated inference**: SplitNN, Petals.
- **TEE-based ML**: Graviton, Slalom, Apple Private Cloud Compute,
  NVIDIA H100 CC mode.
- **Differential privacy for language**: DP-SGD, DP prompt
  engineering.
- **Prior surveys on LLM privacy**~\cite{TODO}.

### 4. The Eight Options

(Fill from `docs/OPTIONS.md`.)

### 5. System Design

(Fill from `docs/ARCHITECTURE.md`.)

### 6. Evaluation Setup

(Fill from `docs/EVALUATION.md`.)

### 7. Results

- **7.1 Per-option leak rates** on WL1 (PII) and WL2 (secrets).
- **7.2 Semantic leak rates** on WL3 (implicit identity).
- **7.3 Quality deltas** per option per workload.
- **7.4 Combinations** and the Pareto frontier.
- **7.5 Detector recall floor** for Option B.
- **7.6 TEE attestation experiment**: end-to-end demo with AWS
  Nitro Enclave serving a Llama-3 model, attested from a client.
- **7.7 Research-stage demos**: small-model FHE classifier;
  first-layer MPC embedding lookup.

### 8. Discussion

- Which option to pick at which threat model budget.
- Limitations of each technique (residual leaks, side channels,
  adversarial inputs).
- Where the gap between "practical" and "cryptographically strong"
  currently lives, and how it's shrinking.

### 9. Limitations

- Detector quality bounds Option B and C; we have not trained a
  custom detector, only used off-the-shelf (presidio + regex).
- Research-stage options are demonstrated, not deployed.
- Judge-model quality evaluation has the usual caveats.
- Workloads are synthetic or scrubbed; real-world captures would
  strengthen external validity.

### 10. Conclusion

Practical privacy tooling for LLM requests is eight-options-deep
and the optimal choice depends on the threat model. We provide the
first common-benchmark comparison and an open-source
implementation.

### Appendices

- **A**. Full metric tables per workload.
- **B**. Detector precision/recall per kind.
- **C**. TEE attestation protocol details.
- **D**. FHE demo details (small classifier).
- **E**. Reproducibility checklist.
- **F**. Responsible disclosure timeline.

## Schedule

Rough milestones from project start:

| Day | Milestone |
|---:|---|
| 0–4 | Scaffold, implement Option B end-to-end, WL1 ready |
| 4–8 | Option C + WL3 |
| 8–12 | Option A integration (via local-splitter) + WL2 |
| 12–16 | Option H + first full singleton evaluation |
| 16–20 | Option D end-to-end demo (AWS Nitro) |
| 20–25 | Options E, F, G research-stage demos |
| 25–30 | Full evaluation matrix |
| 30–35 | Paper first draft |
| 35–40 | Internal review, figures, polish |
| 40–45 | arXiv submission |

This is optimistic; real schedule will likely be 1.5–2× longer
because of infra hiccups, detector tuning, and the TEE demo
(Nitro setup is non-trivial).
