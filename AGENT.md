# AGENT.md — briefing for the next agent

You are picking up work on **llm-redactor**, a privacy-preserving
shim for outbound LLM requests. This document is the handoff.

Read this file, then the six files under `docs/`, then the five
files under `.agent/memory/`. Then propose your first action and
wait for the user to confirm.

## What this project is

`llm-redactor` intercepts outbound LLM API calls and applies a
privacy-preserving transformation before anything leaves the device.
On the response path, it restores whatever the transformation
removed so the user gets a coherent answer back.

There are **eight options** (A through H), each representing a
different point on the practicality-vs-privacy spectrum:

| | Option | Practical today? |
|---|---|---|
| **A** | Local inference only | Yes (limits model quality) |
| **B** | Redact + restore pipeline | Yes (imperfect detection) |
| **C** | Local semantic rephrase | Yes (quality-dependent) |
| **D** | TEE-hosted inference | Partial (limited endpoints) |
| **E** | Split inference | Research / open-weight only |
| **F** | Fully homomorphic encryption | Research / tiny models |
| **G** | Multi-party computation | Research |
| **H** | Differential privacy noise | Yes (lossy for qualitative) |

The research question is: **given a concrete threat model, which
option (or combination) gives the best privacy-utility trade-off
and at what cost?**

This is a **research-first** project. The code exists to support an
evaluation, and the evaluation exists to support a paper. The paper
is the deliverable.

## Current status

- **Design**: frozen for all eight options. See `docs/OPTIONS.md`.
- **Code**: not started.
- **Evaluation harness**: not started. See `docs/EVALUATION.md`.
- **Paper skeleton**: `paper/paper.tex` with section stubs, LaTeX.

The MVP you should build first is **Option B (redact + restore)**
because it's the most immediately deployable, has the clearest
threat model, and is the only option that works with *any* cloud
endpoint without requiring special hardware or research-stage
protocols. Option C (rephrase) is the natural second. Option A
(local-only) should be integrated as a routing decision (skip the
redactor entirely if the request can be served locally).

## Compatibility contract

The shim must work with:

1. **Any OpenAI-compatible API** — the `/v1/chat/completions` shape.
   This is the lingua franca.
2. **Anthropic's native API** (since a lot of users use Claude
   directly). Consider wrapping via LiteLLM to keep the core code
   vendor-agnostic.
3. **Ollama** for the optional local-inference path (Option A).

The shim must **not** require a specific vendor SDK. Build against
the raw HTTP contract with `httpx`.

## Your first 30 minutes

1. Read `README.md`, `AGENT.md` (this file), `docs/ARCHITECTURE.md`.
2. Read `docs/OPTIONS.md` — every option in detail, with feasibility
   notes.
3. Read `docs/THREAT_MODEL.md` — what we defend against and what we
   explicitly don't. This is the most important doc.
4. Read `docs/API.md` — MCP tool surface + HTTP proxy surface.
5. Read `docs/EVALUATION.md` — leak metrics, quality metrics, cost
   metrics.
6. Read `docs/PAPER.md` — the arXiv paper outline.
7. Read `.agent/memory/origin.md`, `decisions.md`, `next-steps.md`,
   `user-profile.md`, `gotchas.md`.

## Hard rules

- **Never claim more privacy than the technique actually provides.**
  Every option has a residual leak; the paper quantifies it. The
  code's error messages and docs must match the paper's numbers.
- **The threat model is the contract.** If a request would defeat
  the threat model (e.g., contains a known-unseen PII type we don't
  detect), the correct behaviour is to *refuse* or *escalate*, not
  to silently pass it through.
- **Every option is independently togglable** for evaluation and for
  real-world mix-and-match.
- **Leak-rate measurements must be automated and reproducible.**
  Manual spot checks don't count for the paper.
- **Restoration on the response path must be deterministic.** A
  placeholder inserted on the request must be restored exactly on
  the response. Any mismatch is a bug and must fail closed.
- **The paper is a deliverable.** Treat `paper/paper.tex` as a
  first-class artefact.

## What this project is NOT

- **Not a secret-scanner that blocks commits.** That's a different
  tool (gitleaks, detect-secrets). We operate on LLM request
  payloads, not on git trees.
- **Not an encryption product.** We're not claiming to encrypt
  anything the way a PKI product does. Options B, C, H use
  redaction, rephrasing, and noise — not cryptography in the
  mathematical sense. Options D, F, G use cryptography but the
  properties are specific (TEE attestation, FHE evaluation, MPC
  secret shares) and we don't promise more than each protocol
  delivers.
- **Not a replacement for a proper DLP program.** We sit inside the
  LLM request pipeline; organisation-wide DLP requires many other
  controls.
- **Not a sibling of `resilient-write`.** Different concern. They
  can coexist in a pipeline — `resilient-write` handles writes to
  disk, `llm-redactor` handles sends to LLM endpoints.
- **Not a sibling of `local-splitter`.** Also different concern.
  `local-splitter` is about cost; we're about privacy. See the
  README on why they're separate projects, not a unified tool.

## The paper

We're aiming for a cs.CR (Cryptography and Security) arXiv
submission with the form:

> **"Eight Techniques for Privacy-Preserving LLM Requests: An
> Empirical Measurement of Leak Rates, Utility, and Cost."**

See `docs/PAPER.md` for the outline and `paper/paper.tex` for the
LaTeX skeleton. The contribution is empirical: rigorous measurement
of residual leakage and utility loss for each technique, on a
common benchmark, with a decision rule for practitioners.

## How to talk to the user

Direct, terse, proof > promises, no preamble. See
`.agent/memory/user-profile.md`.
