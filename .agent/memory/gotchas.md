---
name: gotchas and lessons learned
description: Non-obvious things that would otherwise burn time
type: feedback
---

# Gotchas

## Presidio

- `presidio-analyzer` uses spaCy as its NER backbone by default.
  You must install a spaCy model explicitly: `python -m spacy
  download en_core_web_sm`. CI and first-time-install scripts
  need this step or detection silently fails.
- Presidio's default recognisers have **low recall on
  non-US phone/address formats**. Add custom recognisers for any
  locale you care about or you will under-detect.
- Presidio can be slow to initialise (~1 second). Load it once at
  startup, never per-request.
- Presidio's `analyzer.analyze()` returns overlapping spans in
  some cases. Deduplicate before redacting or you'll end up with
  `{EMAIL_{EMAIL_1}1}`-style monstrosities.

## Detector recall

- Our Option B's privacy guarantee is exactly the detector's
  recall. If recall is 95% on emails, 5% of emails leak. Report
  this honestly in the paper.
- Adversarial inputs can defeat regex-based detectors with
  trivial obfuscations (spaces, zero-width characters, unicode
  homoglyphs). The paper should include an adversarial benchmark
  showing which detectors fall to which transforms.
- "Implicit identity" is the detector's hardest failure mode.
  Phrases like "the CFO whose wife works at the competitor" are
  identifying but have no PII-span-level markers. Option C
  (rephrase) is the intended defence; the paper should measure
  whether it actually works.

## Placeholder design

- **Collisions are a real bug class.** If the user's prompt
  contains the literal string `{EMAIL_1}` — maybe because they're
  asking a question about placeholder syntax — the restorer will
  incorrectly substitute it. Use a rare-character prefix like
  `⟨EMAIL_1⟩` or a random suffix.
- **Stability within a request is critical.** Two references to
  `alice@example.org` must both become `{EMAIL_1}`, not two
  different placeholders, or the cloud model will lose the
  coreference.
- **Placeholders leak structure.** The cloud model seeing
  `{PERSON_1}` and `{PERSON_2}` knows you're talking about two
  people. Typed placeholders trade privacy for utility; opaque
  random tokens trade utility for privacy. Offer both.

## Reverse-map lifetime

- The reverse map must **never** persist to disk. Ever. A crashed
  process loses the map and the response can't be de-redacted —
  that's the correct failure mode.
- The reverse map is per-request, not per-session. Don't reuse
  across requests or you leak across conversations.

## Response-path restoration

- The cloud model sometimes **paraphrases** placeholders, e.g.
  "I'll write an email to PERSON_1" without the braces, or
  "I'll write an email to the person". The restorer must
  tolerate this — only substitute on exact matches. Never try to
  pattern-match placeholder-like strings.
- The cloud model sometimes **inserts new placeholders** that
  weren't in the request (because the model saw `{EMAIL_1}` and
  decided to echo it). These are safe to leave alone.

## TEE attestation (Option D)

- AWS Nitro Enclave attestation documents are 4-6 KB CBOR blobs
  signed by AWS. Verifying them requires pulling AWS's root cert
  chain and checking the PCR values against an expected
  measurement. This is non-trivial — allocate serious time.
- Enclaves are **very small by default**. Allocate enough memory
  for the model (vLLM on Llama-3 7B needs ~20GB). This means a
  large instance type.
- Enclaves have no network access except through a vsock proxy.
  Your vLLM config needs a non-standard networking setup.
- Apple PCC cannot be used from non-Apple platforms. Skip it
  for the paper's demo.

## FHE (Option F)

- Zama's Concrete ML is the most usable FHE-ML framework today,
  but it's limited to the model architectures it supports.
  Trying to run an unsupported architecture produces cryptic
  errors. Start with their example classifier and adapt.
- FHE benchmarks are hardware-sensitive — report CPU and memory,
  not just "it took X seconds".

## Judge models

- Family bias is real. If you judge GPT output with GPT, scores
  are inflated. Use a different family. If testing GPT output,
  use Claude as judge; if testing Claude output, use GPT.
- Judge models sometimes ignore instructions and score
  free-form. Enforce a structured JSON output with a schema.
- Tie rates are informative. Report them.

## Leak measurement

- The leak meter for WL1/WL2 is deterministic (string-match
  against annotations). The leak meter for WL3 (implicit
  identity) is not — it requires a judge model comparing
  "does the redacted text still identify the same individual".
  Report both leak rates separately.
- **Partial leaks matter.** If the real name is "Alice
  Hernandez" and the redactor strips "Alice" but leaves
  "Hernandez", that's still a leak. Report partial leaks
  alongside exact leaks.

## Config precedence

- Environment > config file > defaults. Document the precedence
  in the README. Users will hit edge cases if it's ambiguous.

## Ethics

- **No real user prompts in any workload.** Generate synthetic
  data. If you absolutely need a real-capture, hand-scrub and
  get Jay's sign-off on the sanitised version.
- **Responsible disclosure** if you find a vendor-specific
  bypass (e.g., a bundled SDK that circumvents the proxy). 30
  days notice.
- **Don't publish attack techniques that aren't already public
  knowledge.** If your leak-rate test discovers a new way to
  circumvent the detector, disclose to presidio maintainers
  before publishing the paper.
