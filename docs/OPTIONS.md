# Options — deep dive

Eight options, ranked roughly by practicality today (most to least).

## Option A — Local inference only

### What it does
Never call a cloud LLM. Run every request on a local model (Ollama,
llama.cpp, MLX, LM Studio).

### Privacy property
**Complete**, by construction. Nothing leaves the device.

### Utility property
**Bounded by the local model.** A 70B local model on an M3 Max with
unified memory is now comparable to GPT-3.5; a 1--7B model on a
normal laptop is meaningfully weaker than frontier cloud models.

### When to use it
- When the content is so sensitive nothing can leave the device.
- When the task is well-matched to local-model capability
  (autocompletion, short code generation, simple Q&A, classification).

### Implementation notes
- This option is primarily a *routing decision*, not a pipeline
  stage. If `opt_a_local_only` is enabled and the request is
  tractable locally, skip the rest of the pipeline entirely.
- Integrate with the sibling `local-splitter` project's T1 classifier
  to decide "is this local-answerable?" without re-implementing it.

### Failure modes
- User expects frontier-level answers and gets mediocrity.
- Local model hallucinates on tasks outside its capability.

---

## Option B — Redact + restore pipeline

### What it does
1. Local NER + regex detector finds sensitive spans in the outgoing
   request.
2. Each span is replaced with a typed placeholder
   (`{PERSON_1}`, `{EMAIL_2}`, `{API_KEY_3}`, `{ORG_1}`).
3. The redacted request goes to the cloud.
4. On the response, placeholders are replaced back with the originals
   from an in-memory map.

### Privacy property
**Imperfect but concrete.** Only what the detector finds is protected.
The paper measures residual leakage on known ground-truth sets.

### Utility property
**High**, as long as the cloud model's reasoning doesn't require the
actual identifier. "Explain this Python script" works; "look up user
`bob@example.org` in this database" does not.

### When to use it
- Default for any request that must leave the device.
- Strong fit for structured data (API responses, logs, database rows)
  with well-defined sensitive columns.
- Weaker fit for free-form prose where identity bleeds across
  sentences.

### Implementation notes
- Use `presidio-analyzer` for general PII + a custom pattern file
  for credentials and organisation-specific identifiers.
- Placeholders must be **typed and stable** within one request —
  two occurrences of the same original value must map to the same
  placeholder, or the cloud model will treat them as unrelated.
- The reverse map lives **only in process memory** for the lifetime
  of the request.
- The detector emits `confidence` scores; in `strict` mode, anything
  below a threshold is refused rather than passed through.

### Failure modes
- Detector misses a non-standard identifier (e.g. "the CFO's wife",
  which is identifying but not a PII pattern).
- Cloud model's response references a placeholder the restorer
  doesn't recognise (e.g. the model paraphrases `{PERSON_1}` as
  "the person"). The restorer must leave those untouched.
- Placeholder collision: `{PERSON_1}` happens to appear in the
  original text. Use a random suffix or a rare Unicode marker.

### Threat model caveat
Option B defeats *adversaries with access to the cloud logs*. It
does **not** defeat an adversary who can correlate the redacted
request with out-of-band context. If the cloud vendor knows your
organisation, a request containing `"{ORG_1}'s 2026 quarterly
report"` still leaks that you're working on a quarterly report, even
without the org name.

---

## Option C — Local semantic rephrase

### What it does
A local model rewrites the outgoing prompt to remove identifying
details while preserving the technical question. Instead of "help me
debug this Python script for our NBA player valuation model at
Warriors Analytics", the cloud sees "help me debug this Python
script for a sports analytics pricing model".

### Privacy property
**Imperfect and quality-dependent.** The local model decides what to
strip; mistakes can under-redact or over-redact.

### Utility property
**Variable.** A careful rephrase preserves enough context for a good
cloud answer; an over-zealous rephrase strips context the cloud
needed. A validator step checks that key technical terms survive.

### When to use it
- Free-form prose where PII-span detection misses the implicit
  identity (names of teams, products, internal projects).
- As a second pass after Option B for requests that contain
  identifying phrases without token-level markers.

### Implementation notes
- Use a strong local model (7--13B) for rephrasing — smaller models
  rewrite clumsily.
- Run a validator: given the rewritten prompt, can the original
  question still be answered? If not, roll back the rewrite.
- Record every rewrite in `runs.jsonl` for audit.

### Failure modes
- Rephrase model hallucinates new details that weren't in the
  original.
- Over-redaction removes the load-bearing technical term.
- Under-redaction leaves identifying phrases in place.

### Open research question
How much can a local 7B model compress identifying information
without hurting task performance? This is one of the research
contributions of the paper.

---

## Option D — TEE-hosted inference

### What it does
Send the plaintext request to an endpoint running inside a Trusted
Execution Environment (TEE). The client attests the enclave before
sending, verifies the hardware-measured identity, and trusts that
plaintext only exists inside the enclave's memory boundary.

### Privacy property
**Strong, conditional on the hardware.** TEEs protect against
co-tenants and non-privileged cloud operators, but not against a
compromised hardware manufacturer, side-channel attacks, or bugs in
the enclave's code.

### Utility property
**Identical to the cloud model**, because the same model runs inside
the TEE. No utility loss.

### Available options (as of 2026)
- **Apple Private Cloud Compute (PCC)** — Apple silicon, attested,
  no persistence. Available to Apple apps only.
- **AWS Nitro Enclaves** — x86 + confidential VMs. General purpose.
- **Azure Confidential Computing** — SGX and SEV-SNP based.
- **GCP Confidential Space** — AMD SEV.
- **NVIDIA H100 Confidential Compute** — GPU-side confidential mode.
- **Phala Network** — decentralised TEE provider running SGX/TDX
  with inference offerings.

### When to use it
- When the organisation already trusts a TEE vendor (AWS, Azure,
  GCP, Apple).
- When deploying your own inference (e.g. vLLM on H100 in Nitro).
- When the other options are insufficient but local inference is
  too weak.

### Implementation notes
- Client verifies enclave attestation before sending plaintext.
- For self-hosted inference, maintain a known-good measurement
  registry (the enclave's expected PCR values) and refuse to send
  if the measurement changes unexpectedly.
- For third-party PCC: use their SDK.

### Failure modes
- Side-channel attacks on the enclave (historically a recurring
  concern; SGX has had several).
- Supply-chain compromise of the hardware manufacturer.
- Attestation bypass bugs.

### Honest note
TEEs are **not a panacea**. They raise the bar substantially but
they don't eliminate every threat. The paper will quantify residual
risk based on publicly documented vulnerabilities in each platform.

---

## Option E — Split inference

### What it does
Run the first N layers of an open-weight model locally, compute the
intermediate activations, and send only the activations (not the
tokens) to a remote host to complete the forward pass.

### Privacy property
**Partial.** Activations are not plaintext tokens, but the research
literature shows they can sometimes be inverted back to the input.
Combining with DP noise on the activations is a stronger variant.

### Utility property
**Identical to the non-split model**, because the model's final
output is unchanged.

### When to use it
- When you run your own open-weight model weights (e.g., Llama-3
  70B) and can split the model cleanly.
- When you trust your local client but want to offload compute to a
  remote GPU without sending raw tokens.

### Implementation notes
- You need access to the model weights on both sides.
- Splitting happens at a layer boundary; the most common split is
  after the first 2--4 layers.
- The protocol must be defined between the two ends; there is no
  standard.

### Research status
- Academic literature exists (SplitNN, federated inference).
- Production implementations: Petals runs inference across
  volunteer GPUs with a split similar to this; it's the closest to
  a real implementation.
- **Not production-ready** for mainstream deployments because it
  requires open-weight models and custom protocols.

### Failure modes
- Activation inversion attacks recover the original input.
- The remote host is compromised and exfiltrates activations for
  offline inversion.
- Model fingerprinting leaks which architecture is being used.

---

## Option F — Fully homomorphic encryption (FHE)

### What it does
Encrypt the input with a homomorphic scheme; the cloud model
performs inference *on the ciphertext* and returns ciphertext; the
client decrypts.

### Privacy property
**Mathematically strong** — the cloud provably cannot read the
plaintext.

### Utility property
**Identical** in principle. Output is the same as non-encrypted
inference.

### Practical today
**No**, not for mainstream LLMs. FHE inference has a 10,000--100,000×
slowdown compared to plaintext. FHE LLM inference works for models
well under 1B parameters in academic demos (CryptoNets,
Intel HE-Transformer, Microsoft SEAL based projects) but not for a
7B+ chat model.

### Research status
- Active research area (Microsoft, Zama, Intel).
- Performance improving roughly 2× per year.
- Realistic timeline for practical LLM FHE: 5--10 years.

### When to use it (today)
- For small classifiers or embedding lookups — those are feasible.
- For concept demonstrations or research papers.
- **Not** for production LLM inference.

### Implementation notes
If we build an FHE stage, it should be for a *small local classifier*
(e.g. "is this sensitive?") running on FHE-encrypted input — that is
tractable today and makes an interesting paper experiment.

---

## Option G — Secret sharing / MPC

### What it does
Split the input across N non-colluding servers using a secret-sharing
scheme. No single server sees the full input. Inference runs using a
multi-party computation (MPC) protocol.

### Privacy property
**Mathematically strong**, conditional on the non-collusion
assumption.

### Utility property
**Identical** in principle. Output matches non-MPC inference.

### Practical today
- Academic frameworks: CrypTen, MP-SPDZ, SecureML.
- Slowdowns of 2--3 orders of magnitude over plaintext inference.
- Works for small models; LLM-scale MPC is research.

### Most feasible today
**Hybrid**: MPC only for the *first layer* of a standard model (token
embedding lookup). This keeps token IDs secret while the remaining
layers run normally on plaintext activations. Interesting but
limited privacy gain — it defeats token-level logging on the server
but not activation inspection.

### Implementation notes
If we build an MPC stage, it should be the "MPC-first-layer" hybrid
as a research experiment, not a general-purpose protocol.

---

## Option H — Differential privacy noise

### What it does
Perturb the input with calibrated noise (token substitutions,
paraphrase jitter, random deletion) so the model's output over the
population is faithful but individual inputs can't be reconstructed.

### Privacy property
**Formal DP guarantee at some ε**. Stronger ε (more noise) = stronger
privacy and worse utility.

### Utility property
**Lossy for qualitative queries.** Great for statistical workloads
("how many of these logs have error X?"); bad for qualitative ones
("what does this log say?").

### When to use it
- Statistical aggregation queries over sensitive data.
- Workloads where a fraction of tokens being wrong is acceptable.
- As a *last line of defence* on top of redaction, to blur the
  residual signal.

### Implementation notes
- Word-level substitution with a semantically close alternative
  from an embedding table.
- Calibrate ε to the task; measure utility degradation.
- Never combine with exact-answer tasks.

### Failure modes
- User thinks they're getting the real answer but the cloud saw
  noisy input; response may not fit the actual case.
- Adversary with many queries can de-noise via aggregation.

---

## Option comparison matrix

| Option | Privacy | Utility | Cost | Latency | Works today? |
|---|---|---|---|---|---|
| **A** local | perfect | bounded | $0 | low | yes |
| **B** redact | partial | high | low | low | yes |
| **C** rephrase | partial | medium | low | medium | yes |
| **D** TEE | strong | full | high | low | yes (limited) |
| **E** split | partial | full | medium | medium | research |
| **F** FHE | mathematical | full | prohibitive | very high | research (tiny) |
| **G** MPC | mathematical | full | high | high | research |
| **H** DP noise | formal | lossy | low | low | yes (niche) |

## Combining options

The interesting combinations:

- **A + B**: route to local if local-answerable, else redact + cloud.
  This is the sensible default.
- **B + C**: redact PII spans AND rephrase identifying prose.
  Defence in depth.
- **B + D**: redact AND send the redacted request to a TEE endpoint.
  Belt + suspenders.
- **B + H**: redact, then add DP noise to anything we couldn't
  redact. Reduces the signal that survives.

The paper measures all of these combinations.
