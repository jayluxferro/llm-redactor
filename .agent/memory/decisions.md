---
name: design decisions
description: What was considered, chosen, and rejected
type: project
---

# Decisions

## Overall shape

### Decision: eight options, each independently togglable

**Why**: the research question is *which technique wins against
which threat model at which utility cost*. Collapsing options
makes measurement impossible.

**Rejected alternatives**:
- *A single "smart" pipeline*. Rejected — no attribution.
- *Fewer options (just redact + TEE)*. Rejected because the
  research contribution is the breadth of comparison.
- *More options (adding e.g. watermarking or adversarial
  perturbation)*. Rejected — scope creep; those are not
  privacy-preserving in the input-protection sense.

### Decision: separate project from `local-splitter`

**Why**: **different research questions, different threat models,
different audiences**. `local-splitter`'s goal is cost reduction;
`llm-redactor`'s goal is privacy. A single tool would blur the
research contribution of each. Two separate papers also target
different venues (cs.CL / cs.DC for splitter; cs.CR for redactor).

**Rejected alternatives**:
- *Unified "LLM shim" project*. Rejected. See the dedicated note
  in `docs/ARCHITECTURE.md` on why they're separate.

### Decision: the threat model is the contract

**Why**: every privacy claim in the code, docs, and paper must be
relative to the documented threat model in
`docs/THREAT_MODEL.md`. Any claim that exceeds the threat model
is a bug.

## Pipeline shape

### Decision: reverse map lives in memory only, never on disk

**Why**: persisting the reverse map would be a worse leakage
channel than the one we're preventing. If a process crash loses
the map mid-request, the response can't be de-redacted — that is
an acceptable failure mode. It fails safe.

### Decision: strict mode refuses on low-confidence detection

**Why**: passing through a request with low-confidence detections
silently is the worst outcome — the user thinks they're protected
but the vendor sees sensitive content. Refusing forces the user to
notice and make an explicit choice.

**Rejected alternatives**:
- *Always pass through with a warning*. Rejected — warnings get
  ignored.
- *Ask the user interactively*. Rejected — the shim runs as a
  non-interactive process; it doesn't have a UI channel back.

### Decision: placeholders are typed (`{EMAIL_1}`) by default,
with an opt-in opaque mode

**Why**: typed placeholders preserve enough structure for the
cloud model to reason coherently about the prompt. Opaque
placeholders (random tokens) hide even the *category* of the
redacted content, which is a stronger guarantee at a utility cost.
Users pick via config.

### Decision: detection uses presidio + regex + local LM classifier,
not a custom-trained model

**Why**: training a detector is out of scope for the paper. Using
off-the-shelf tools makes the results reproducible and the
detector replaceable. The paper's "detector recall floor"
analysis turns the detector's quality into a *variable*, which is
actually a stronger contribution than a custom model would be.

**Rejected alternatives**:
- *Train a custom NER model*. Rejected — scope creep and less
  reproducible.
- *Rules only (no LM classifier)*. Rejected — can't catch
  implicit identity.
- *LM only*. Rejected — too slow and non-deterministic for the
  hot path.

## Options-specific decisions

### Option A (local-only)

Decision: integrate via the sibling `local-splitter`'s T1
classifier, don't reimplement routing.

### Option B (redact + restore)

Decision: the default enabled option. Most deployable. Paper's
main empirical result.

### Option C (rephrase)

Decision: requires a validator that checks the rewrite still
preserves the technical answerability of the question. Without
the validator, rephrasing can silently strip load-bearing context.

### Option D (TEE)

Decision: for the paper, demonstrate end-to-end on **AWS Nitro
Enclaves** because they're general-purpose, documented, and
reproducible. Apple PCC requires an iOS/macOS app which is out of
scope. Document but do not implement other TEE platforms in the
first release.

### Option E (split inference)

Decision: research demo only. Pick **Petals** as the reference
implementation because it's the closest thing to a production
split-inference system. Demonstrate on a 7B open-weight model.
Measure activation-inversion risk.

### Option F (FHE)

Decision: research demo only. Build a **small classifier** (a
sensitive-vs-non-sensitive binary classifier) running under FHE
via Zama's Concrete ML. Show that the protocol works end-to-end
at an acceptable latency for that specific task. Make it clear
in the paper that this is **not** inference of a chat model.

### Option G (MPC)

Decision: research demo only. Implement the **first-layer MPC
embedding lookup** hybrid as described in `OPTIONS.md`. Use
CrypTen. Measure the latency cost.

### Option H (DP noise)

Decision: implement for completeness but don't recommend as a
default. Useful for statistical workloads; lossy for qualitative
ones. The paper's DP section will be short.

## Paper and evaluation

### Decision: ground-truth-labelled leak benchmark is the primary
contribution

**Why**: every prior paper in this space uses a different
evaluation approach. Committing to a public, reproducible
benchmark raises the floor for future work in the area.

### Decision: judge-model quality evaluation, not full human
evaluation

**Why**: cost. Human evaluation at scale is prohibitive for a
solo project. Judge-model with family-bias mitigation is the
field standard.

### Decision: no live-capture workloads in the repo

**Why**: every workload is synthetic or hand-scrubbed. No real
user prompts. This is a security paper — leaking anyone's
prompts in the evaluation dataset would be an obvious bad look.

### Decision: responsible disclosure if a vendor-specific bypass
is found

**Why**: we're building this in the open. If we discover that a
specific vendor's bundled SDK evades our proxy, we notify them
30 days before publication, document the timeline in the paper,
and publish anyway.
