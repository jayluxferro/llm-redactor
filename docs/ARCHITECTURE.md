# Architecture

`llm-redactor` is a single process with two transport interfaces and
a pipeline of eight options that can be individually enabled.

```
┌────────────────────────┐
│ agent outbound request │
└────────────┬───────────┘
             │
             ▼
┌────────────────────────┐
│ stage 0: classify      │  "is this safe to route locally?"
└────────────┬───────────┘
             │
   ┌─────────┴──────────┐
   │ LOCAL-OK           │  CLOUD-REQUIRED
   ▼                    ▼
┌─────────┐   ┌──────────────────────────┐
│ Opt A   │   │ stage 1: detect          │  detect sensitive spans
│ local   │   └────────────┬─────────────┘
└─────────┘                │
                           ▼
              ┌──────────────────────────┐
              │ stage 2: redact          │  Opt B
              └────────────┬─────────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │ stage 3: rephrase        │  Opt C
              └────────────┬─────────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │ stage 4: noise           │  Opt H
              └────────────┬─────────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │ stage 5: route to target │
              └────────────┬─────────────┘
                           │
              ┌────────────┴─────────────┐
              ▼                          ▼
       ┌──────────────┐         ┌──────────────┐
       │ standard     │         │ TEE-hosted   │ Opt D
       │ cloud API    │         │ endpoint     │
       └──────┬───────┘         └──────┬───────┘
              │                        │
              └────────────┬───────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │ stage 6: restore         │  inverse of stage 2
              └────────────┬─────────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │ return to agent          │
              └──────────────────────────┘
```

Options **E, F, G** live as alternative *routers* in stage 5: if
enabled, they replace the standard cloud API target with a
split-inference endpoint, an FHE endpoint, or an MPC coordinator.
These are research-stage and gated off by default.

## Transport layer

Two parallel interfaces:

1. **MCP server (stdio)** — `llm.chat`, `redact.scrub`, `redact.restore`,
   `redact.detect`, `redact.stats`.
2. **HTTP proxy** (`POST /v1/chat/completions`) — OpenAI-compatible.
   Points `OPENAI_API_BASE` at `http://localhost:<port>` and the
   agent's cloud calls transparently go through the redactor.

## Core components

### 1. Detector (`src/llm_redactor/detect/`)

- `regex.py` — pattern families from `docs/POLICY.md` (inherited
  from `resilient-write`).
- `ner.py` — `presidio` or a small local NER model for
  PII detection.
- `llm_validator.py` — optional local LLM (Ollama) batch validation of
  NER spans to drop false positives; enabled via `pipeline.llm_validation`.

Detectors emit `Span(start, end, kind, confidence, source, text)`
records.

### 2. Redactor (`src/llm_redactor/redact/`)

- `placeholder.py` — generates typed, stable placeholders using Unicode
  angle brackets (for example `⟨EMAIL_1⟩`). Optional per-request tag
  (`pipeline.placeholder_request_tag`) embeds random bytes so accidental
  collisions with user text are rarer (`⟨EMAIL_1·a1b2c3d⟩`).
- `restore.py` — the reverse map; stores original → placeholder and
  replaces placeholder → original in the response.
- The reverse map lives **only in the process memory** for the
  lifetime of the request. It is never persisted.

### 3. Rephraser (`src/llm_redactor/rephrase/`)

- `local_model.py` — calls a local Ollama model with a rewriting
  prompt.
- `validator.py` — checks that rewritten text still contains the
  key technical terms required to answer (defended against
  over-rewriting).

### 4. Noise injector (`src/llm_redactor/noise/`)

- `dp.py` — differential-privacy token substitution or paraphrase
  noise.

### 5. Transport / routers (`src/llm_redactor/transport/`)

- `cloud.py` — standard OpenAI-compatible POST.
- `tee.py` — posts to a TEE endpoint and verifies the attestation.
- `split_inference.py` — stub for Option E (research).
- `fhe.py` — stub for Option F (research).
- `mpc.py` — stub for Option G (research).

### 6. Evaluation harness (`evals/`)

- `workloads/` — synthetic and real-capture inputs with ground-truth
  sensitive-span labels.
- `leak_meter.py` — runs the request through each option and
  measures residual leakage in the outgoing bytes.
- `utility_meter.py` — measures how much the response quality
  degrades vs. baseline.
- `report.py` — produces the paper figures.

## Config model

```yaml
version: 1
transport:
  mcp: true
  http: true
  http_port: 7789
  tools_policy: bypass   # bypass | refuse — tool/function payloads skip redaction
  mcp_session_cap: 2000  # MCP scrub sessions; LRU eviction when full

local_model:
  backend: ollama
  endpoint: http://127.0.0.1:11434
  chat_model: llama3.2:3b
  ner_model: null      # null = Presidio default; e.g. xx_ent_wiki_sm for multilingual

cloud_target:
  backend: openai_compat
  endpoint: https://api.openai.com/v1
  api_key_env: OPENAI_API_KEY

pipeline:
  llm_validation:      { enabled: false, model: "" }  # Ollama validation of NER spans
  placeholder_request_tag: false  # random tag inside each placeholder per HTTP/MCP call
  opt_a_local_only:    { enabled: false }  # opt-in for privacy-max mode
  opt_b_redact:        { enabled: true, strict: true }
  opt_c_rephrase:      { enabled: false, require_validator_pass: true }
  opt_d_tee:           { enabled: false, endpoint: "" }
  opt_e_split:         { enabled: false }  # research
  opt_f_fhe:           { enabled: false }  # research
  opt_g_mpc:           { enabled: false }  # research
  opt_h_dp_noise:      { enabled: false, epsilon: 4.0 }

policy:
  strict_refuse_on_unknown_sensitive: true
  categories: [pii, secret, org_identifier, customer_name]  # aliases; see README for full taxonomy
  extend_patterns_file: .llm_redactor/patterns.yaml
```

Category aliases expand at runtime: `pii` → identity, contact, government_id,
financial, medical, temporal; `secret` → credential, cloud_credential,
vendor_api_key, private_key; `org_identifier` → infrastructure;
`customer_name` → identity.  Fine-grained names can be used directly
(e.g. `[credential, contact]`).

## State directory

`.llm_redactor/` per workspace:

```
.llm_redactor/
├── runs.jsonl           # one row per request, for audit + eval
├── patterns.yaml        # workspace-local pattern overrides
└── leak_metrics.jsonl   # test results
```

The **reverse map is never persisted to disk.** It lives in memory
for the duration of a single request. If the process crashes mid-
request, the map is lost and the response can't be de-redacted. That
is intentional: on-disk reverse maps would be a leakage channel
worse than the one we're trying to prevent.
