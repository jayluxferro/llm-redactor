# llm-redactor

A privacy-preserving shim for outbound LLM requests. `llm-redactor`
sits between an agent and an LLM endpoint and removes, masks, or
transforms sensitive content **before** it leaves the device, then
restores placeholders in the response so the user gets a normal
answer.

This repo is a **research + implementation project**. The plan:

1. Freeze the design for the eight options listed below.
2. Build a reference implementation covering the options that are
   practical today.
3. Run a rigorous evaluation measuring leak rates, quality loss,
   latency, and failure modes per option and per combination.
4. Publish the results as a LaTeX paper on arXiv
   (`paper/paper.tex`).

**Novelty angle**: the eight options span a spectrum from
"redact-and-restore pipelines" (practical today) to "homomorphic
inference" (research-stage). Nobody has measured them head-to-head
on a common benchmark, nobody has quantified the residual leak rate
of each technique, and nobody has published a decision rule for
which option to pick given a threat model.

## The eight options

| Option | Short name | What it does |
|---|---|---|
| **A** | `local-only` | Never call the cloud. Run inference entirely on a local model. |
| **B** | `redact` | Local NER + regex pipeline detects sensitive spans, replaces with typed placeholders, restores on response. |
| **C** | `rephrase` | Local model semantically rewrites the prompt to remove identifying details while preserving intent. |
| **D** | `tee` | Send to a Trusted Execution Environment (Nitro Enclave, SGX, Apple PCC, H100 CC). Plaintext only exists inside attested hardware. |
| **E** | `split-inference` | Run the first layers of an open-weight model locally, send activations to a remote host for the remaining layers. |
| **F** | `fhe` | Fully homomorphic encryption — cloud operates on ciphertext. Practical only for very small models today. |
| **G** | `mpc` | Secret-share the input across multiple non-colluding servers. |
| **H** | `dp-noise` | Inject calibrated noise into the input; good for statistical workloads, lossy for qualitative ones. |

See `docs/OPTIONS.md` for the deep dive on each.

## How to pick it up

If you're a fresh agent landing here, read in this order:

1. `AGENT.md`
2. `docs/ARCHITECTURE.md`
3. `docs/OPTIONS.md`
4. `docs/THREAT_MODEL.md`
5. `docs/API.md`
6. `docs/EVALUATION.md`
7. `docs/PAPER.md`
8. `.agent/memory/origin.md`, `decisions.md`, `next-steps.md`, `user-profile.md`, `gotchas.md`

Then propose your first action and wait for confirmation before coding.

## Status

- [x] Research brief + option list
- [x] Agent handoff docs
- [x] Paper skeleton (`paper/paper.tex`)
- [ ] Reference implementation (A, B, C today; D experimental; E–H research)
- [ ] Evaluation harness
- [ ] Paper first draft
- [ ] arXiv submission
