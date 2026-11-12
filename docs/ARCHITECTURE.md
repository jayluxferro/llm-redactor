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
2. **HTTP proxy**: `POST /v1/chat/completions` (OpenAI-compatible; point
   the client's base URL at `http://localhost:<port>/v1`, and note the
   `/v1`) and `POST /v1/messages` + `/v1/messages/count_tokens` (Anthropic;
   `ANTHROPIC_BASE_URL=http://localhost:<port>`). Any other path is
   forwarded raw, unredacted (`X-LLM-Redactor-Mode: raw-passthrough`).

## Core components

### 1. Detector (`src/llm_redactor/detect/`)

- `regex.py`: pattern families (secrets, structured PII), plus checksum
  filters from `checksums.py`; custom patterns via
  `policy.extend_patterns_file`.
- `wallets.py`: blockchain addresses, public/private keys and BIP-39
  seed phrases, classified by decoding each candidate.
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
  mcp_session_cap: 10000  # MCP scrub sessions; LRU eviction when full

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
  llm_validation:      { enabled: false, model: "", backend: "model" }  # or "rules": checksum validators, no Ollama
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
└── patterns.yaml        # workspace-local pattern overrides (policy.extend_patterns_file)
```

(Nothing writes per-request audit rows: the proxy logs counts-only JSON
events on the `llm_redactor` logger instead. Eval results go to
`evals/results*/`.)

The **reverse map is never persisted to disk.** It lives in memory
for the duration of a single request (MCP `redact.scrub` sessions are the
exception: they live until `redact.restore` consumes them or the
`transport.mcp_session_cap` LRU evicts them). If the process crashes mid-
request, the map is lost and the response can't be de-redacted. That
is intentional: on-disk reverse maps would be a leakage channel
worse than the one we're trying to prevent.

## Burp Suite extension (`burp-plugin/`)

A Kotlin Option B implementation runs inside Burp's HTTP and WebSocket layers.
It uses the local Python detector service as the authoritative detector:

1. The extension decodes the outbound request (content encoding, then format) and
   extracts the strings to check: query and form values, JSON string values (each
   with its member name as context), multipart text parts, protobuf strings.
2. It sends them in ordered batches to `POST /v1/redactor/detect-batch` on the
   local service, which runs regex, NER, and any enabled local-LLM validation.
3. It replaces the returned spans with typed placeholders, one namespace per
   request, and rebuilds the body in its original format: JSON keeps its numbers
   and structure, protobuf and gRPC framing get recomputed lengths. On service
   failure it uses its built-in detector, a port of `detect/regex.py` and
   `detect/wallets.py` held to the Python output by `tests/test_burp_parity.py`
   and `ParityTest`.
4. Only a request in which something was detected is re-encoded and rewritten.

Responses and SSE events are not restored or modified, except that Burp's canonical
local block response (exactly `400 {"detail":"Bad Request"}`) becomes a local `204`
acknowledgement, which keeps fire-and-forget clients working while the block stays in
force. Client-to-server WebSocket text frames are redacted with the built-in detector
only, since a detector round trip can stall a streaming connection; binary and
server-to-client frames pass through.

OpenAI Responses API requests (`POST /v1/responses`, `POST /backend-api/codex/responses`)
are protocol JSON: only user and tool text (`content`, `input`, `instructions`, `message`,
`prompt`, `text`, `output`, `arguments`, `command`) is redacted; IDs, metadata, and
encrypted reasoning items are left byte for byte. Invalid JSON passes through.

Ciphertext (JSON members named like `encrypted_content` or `ciphertext`, Fernet
tokens) is never modified, because one changed byte breaks its authentication. Outside
the Responses API path, a request carrying such an envelope passes through whole, since
authentication can cover the surrounding fields. Signed requests (SigV4, presigned
URLs), Brotli, and unreadable payloads pass through too. The live Activity UI is
bounded and shows only time, host, protocol, result, detection counts, and pass-through
reason; it never stores request bytes, detected values, query strings, or reverse maps.

When `pipeline.image_redaction.enabled` and `license_acknowledged` are true, raw
JPEG/PNG bodies and base64 `data:image/...` attachments take a separate loopback-only
path: the extension sends decoded bytes to `POST /v1/redactor/redact-image`, which
runs a user-supplied local RF-DETR-compatible ONNX model and paints opaque black
rectangles over all detections.
ONNX Runtime chooses CoreML, CUDA, DirectML, or CPU locally. Model weights are not
bundled; the Screenpipe reference model is CC BY-NC 4.0, so this adapter is intended
for permitted non-commercial use. Missing models/runtimes return 503 and cause a
safe pass-through with `image-redactor-unavailable` activity metadata.

Build: `cd burp-plugin && ./gradlew test shadowJar` → `build/libs/burp-llm-redactor.jar`.
Details: [`burp-plugin/README.md`](../burp-plugin/README.md).
