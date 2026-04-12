---
name: next steps
description: Staged task list for building out llm-redactor
type: project
---

# Next steps

## Status at scaffold time

- Research brief: complete (`docs/`)
- Agent handoff docs: complete
- Paper skeleton: LaTeX stub committed
- Code: not started
- Workloads / benchmarks: not started

## Stage 1 — Scaffold

1. `pyproject.toml`. Runtime deps:
   - `httpx`
   - `mcp`
   - `fastapi` + `uvicorn`
   - `pyyaml`
   - `presidio-analyzer` + `presidio-anonymizer`
   - `spacy` + `en_core_web_sm` (for presidio NER)
   - `typer` + `rich`
   - `tiktoken` (for token counting)
2. `src/llm_redactor/` skeleton (`__init__.py`, `config.py`,
   `transport/`, `detect/`, `redact/`, `rephrase/`, `noise/`,
   `pipeline/`).
3. `tests/` with pytest.
4. `README.md` update once installable.

Ask Jay which build backend he prefers (`hatch`, `uv`, `poetry`)
before committing.

## Stage 2 — Option B: redact + restore MVP

The smallest valuable deliverable. Build this end-to-end first.

1. `src/llm_redactor/detect/regex.py` — inherits pattern families
   from `docs/POLICY.md` (same as `resilient-write`'s policy).
2. `src/llm_redactor/detect/ner.py` — presidio wrapper.
3. `src/llm_redactor/detect/orchestrator.py` — runs all detectors
   and merges spans.
4. `src/llm_redactor/redact/placeholder.py` — typed placeholder
   generator, in-memory reverse map.
5. `src/llm_redactor/redact/restore.py` — response-path substitution.
6. `src/llm_redactor/pipeline/option_b.py` — wraps the above as
   the pipeline stage.
7. `src/llm_redactor/transport/http_proxy.py` — FastAPI
   OpenAI-compatible proxy forwarding to a cloud target.
8. `src/llm_redactor/transport/mcp_server.py` — MCP stdio shell.
9. End-to-end integration test: start the proxy, POST a chat
   completion with an email address in the prompt, verify the
   outgoing request (captured by a mock server) has `{EMAIL_1}`,
   verify the final response has the email restored.

## Stage 3 — Ground-truth workloads

Build the benchmark before building more options. Without the
benchmark, we can't measure any option.

1. `evals/workloads/wl1_pii/` — synthetic prose with embedded
   PII, 500 samples. Generate with a template system and a public
   -corpus of common names / emails / phone formats. Each sample
   carries a `annotations.jsonl` record listing the ground-truth
   span positions and kinds.
2. `evals/workloads/wl2_secrets/` — synthetic configs and
   code snippets with embedded credentials. 300 samples.
3. `evals/workloads/wl3_implicit/` — hand-written + LLM-generated
   prose with implicit identity, 200 samples. These need human
   review for ground-truth — budget for that.
4. `evals/workloads/wl4_code/` — synthetic proprietary-looking
   code snippets. 300 samples.

Each workload has a README describing the generation method and
the annotation schema. Workloads are committed as small JSONL
files.

## Stage 4 — Evaluation harness

1. `evals/runner.py` — runs a single option on a single workload
   and emits a CSV row per sample.
2. `evals/leak_meter.py` — computes leak rate, partial leak rate,
   and semantic leak rate (uses judge model for WL3).
3. `evals/utility_meter.py` — judge-model A/B comparison of the
   response vs. baseline.
4. `evals/report.py` — aggregates and produces figures.

## Stage 5 — First measurement of Option B

Run B on WL1 and WL2 and report:

- Leak rate
- False positive rate (over-redaction)
- Quality delta
- Latency overhead

This is the first real paper-worthy data point. Share with Jay
before moving on.

## Stage 6 — Option C: rephrase

1. `src/llm_redactor/rephrase/local_model.py` — Ollama-based
   rewriting prompt.
2. `src/llm_redactor/rephrase/validator.py` — checks key term
   preservation.
3. `src/llm_redactor/pipeline/option_c.py` — pipeline stage.
4. Measure on WL3 (implicit identity) — where B alone is weakest.

## Stage 7 — Option A integration

Integrate with `local-splitter`'s T1 classifier (via shared
library or HTTP call to the sibling project's classifier
endpoint). Measure the fraction of requests that can avoid the
cloud entirely.

## Stage 8 — Option H: DP noise

1. `src/llm_redactor/noise/dp.py` — word-level substitution with
   ε calibration.
2. Measure on WL1 — utility loss at several ε values.

## Stage 9 — Option D: TEE demo

This is the biggest non-trivial engineering task.

1. Stand up a Nitro Enclave with a vLLM server running Llama-3.
2. Implement client-side attestation verification.
3. Implement the `transport/tee.py` router.
4. Measure latency overhead vs. non-TEE cloud.
5. Document the attestation protocol in the paper.

Budget a full week for this stage.

## Stage 10 — Options E, F, G: research demos

Each is a small, isolated experiment for the paper's results
section, not a full implementation.

1. **E (split inference)**: Use Petals to demo a 7B split
   across two hosts. Measure activation-inversion risk by
   running the activations through a known inversion attack.
2. **F (FHE)**: Build a small sensitive-vs-non-sensitive
   classifier under Zama's Concrete ML. Measure latency.
3. **G (MPC)**: Use CrypTen for first-layer embedding lookup.
   Measure latency.

Each demo produces a figure + a paragraph in the paper.

## Stage 11 — Full evaluation matrix

Run all 8 options × 4 workloads × per-option combinations.
Produce the paper's results tables and figures.

## Stage 12 — Paper first draft

Fill out the LaTeX stubs in `paper/paper.tex`. Send to Jay for
review.

## Stage 13 — Polish + arXiv submission

Related work section, limitations section, responsible
disclosure if needed, figures, abstract tuning. Submit.

## Hard rules

- **Every option must be independently togglable**.
- **Every privacy claim must match the threat model** in
  `docs/THREAT_MODEL.md`.
- **Reverse map never persists to disk**.
- **No real user prompts** in any workload.
- **Refuse, don't guess**, in strict mode.
- **Responsible disclosure** if a vendor bypass is discovered.

## When to push back on scope

If Jay asks you to:
- **"Add a commit-time secret scanner"** → push back. Different
  tool, different scope. Out of the threat model.
- **"Encrypt the on-disk reverse map so we can persist it"** →
  push back. Persistence is a worse leak channel than the cloud
  itself.
- **"Make Option B the only option"** → push back. The research
  contribution is the comparison.
- **"Skip the research demos and just ship B"** → push back.
  The paper is the deliverable, and without E/F/G we lose the
  breadth claim.
