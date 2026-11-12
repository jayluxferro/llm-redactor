# API

Two parallel interfaces into the same pipeline.

## 1. MCP interface (stdio)

The server exposes these tools (see `src/llm_redactor/transport/mcp_server.py`).

### `llm.chat`

One-shot: detect/redact each message (respecting `pipeline.llm_validation` and
`pipeline.placeholder_request_tag` in config), `POST` to the configured OpenAI-compatible
`cloud_target`, restore placeholders in the assistant message, return JSON with
`response`, `detections`, `usage`, etc.

Requires `cloud_target` and API key env in the MCP process environment.

### `redact.scrub`

Detect and redact a single string. Optional arguments: `use_ner` (default true),
`use_llm_validation` (when set, overrides server default for this call only).

Returns `redacted_text`, `session_id`, `detected_kinds`, and metadata. The server
stores the reverse map in memory with LRU eviction when `transport.mcp_session_cap`
is exceeded (oldest sessions dropped; `redact.restore` then fails safely).

### `redact.restore`

Substitute placeholders back using a `session_id` from `redact.scrub`. Consumes
the session (one-shot).

### `redact.detect`

Dry-run detection. Optional: `use_ner`, `use_llm_validation` (per-call override).
Returns `{"spans": [...]}`: span objects with offsets, kind, confidence, text, source.

### `redact.stats`

Process-wide counters (`requests`, `detections`, `restores`, `llm_calls`).

---

## 2. HTTP proxy interface

### `POST /v1/chat/completions`

OpenAI-compatible. Point the client's base URL (`OPENAI_BASE_URL` for openai-python ≥ 1)
at `http://localhost:<port>/v1`. It must end in `/v1`: without it, requests land on the
raw-passthrough catch-all and are forwarded **unredacted**.

**Response headers**

| Header | When |
|--------|------|
| `X-LLM-Redactor-Mode: redacted` | Normal path (redaction applied) |
| `X-LLM-Redactor-Mode: bypass-tools` | Request included `tools` or `functions` and `transport.tools_policy` is `bypass` |
| `X-LLM-Redactor-Bypass-Reason: tools-or-functions` | Same as bypass-tools |
| `X-LLM-Redactor-Mode: raw-passthrough` | Any path without its own route (catch-all): forwarded unredacted |

**Tool / function calls**

If the JSON body contains `tools` or `functions`, the proxy either **refuses** (HTTP 422,
`reason: tools_or_functions_present`) when `transport.tools_policy: refuse`, or **forwards
unchanged** to the cloud when `tools_policy: bypass` (no redaction; see headers above).

**Per-request override**

| Field | Purpose |
|-------|---------|
| `extra_body.redactor.strict` | Boolean; override Option B strict mode for this request |

**Response JSON (non-streaming)**

Standard OpenAI chat completion plus:

```json
{
  "choices": [...],
  "usage": {...},
  "redactor": {
    "options_applied": ["B"],
    "detections": [{"kind": "email", "count": 2}],
    "leak_audit": {
      "outgoing_bytes": 1840,
      "sensitive_tokens_detected": 3,
      "original_span_text_survived": 0
    }
  }
}
```

Streaming (`stream: true`) uses the same redaction path; placeholders are restored in
SSE `delta.content` chunks before they reach the client, including placeholders the model
streams across several deltas. Message `content` may be a string or a list of content
parts; `text` parts are redacted, other parts (images) pass through.

### `POST /v1/messages`

Anthropic Messages API shape. Redacts `system` (string or text blocks) and, in every
message, string content, `text` blocks, `tool_result` content, every string inside
`tool_use` inputs, and text `document` sources. Forwards to `cloud_target` and restores
placeholders in the response's text and `tool_use` inputs, both for `stream: false` and
for SSE (`text_delta` and `input_json_delta`, JSON-escaped). Response JSON carries a
`redactor` object (options applied, detection counts) but no `leak_audit`.

Requests containing signed `thinking` / `redacted_thinking` blocks are redacted surgically
on the raw bytes, so the signatures stay valid; the header is then
`X-LLM-Redactor-Mode: signed-surgical`. If nothing needs redacting, or the surgery fails,
the original bytes are forwarded with `X-LLM-Redactor-Mode: signed-passthrough`.
Content inside the signed blocks themselves is never modified.

### `POST /v1/messages/count_tokens`

Redacted exactly like `/v1/messages` (the body is the same conversation), then forwarded.
Bodies with nothing to redact are forwarded byte-identical.

### `POST /v1/redactor/detect`

Detection-only endpoint for external consumers (e.g. the Burp Suite plugin).
Runs the full pipeline (regex + optional NER) on a single text string and returns
the detected spans without redacting or forwarding anything.

**Request**

```json
{"text": "Call Alice Johnson at alice@example.com about the Q3 audit"}
```

**Response**: an array of span objects (real output with NER on; kinds are lower-case,
see the README taxonomy):

```json
[
  {"start": 5,  "end": 18, "kind": "person", "confidence": 0.85, "text": "Alice Johnson",     "source": "ner"},
  {"start": 22, "end": 39, "kind": "email",  "confidence": 1.0,  "text": "alice@example.com", "source": "regex"}
]
```

Empty text → `[]` (HTTP 200).

### `POST /v1/redactor/detect-batch`

`{"texts": ["first", "second"]}` → `{"items": [[span, ...], [span, ...]]}`, at most 1,000
fragments. This is what the Burp plugin calls (it has no configurable endpoint field; the
URL is fixed to `http://127.0.0.1:7789/v1/redactor/detect-batch`).

### `POST /v1/redactor/redact-image`

JPEG or PNG body in, the same media type out with opaque boxes over detected regions
(`X-LLM-Redactor-Detections` gives the count). Returns 503 when image redaction is not
configured (see `pipeline.image_redaction`).

### `GET /v1/redactor/stats`

Pipeline counters (requests, detections, refusals).

### `GET /v1/redactor/config`

Non-secret subset of config: Option B flags, `llm_validation.enabled`,
`placeholder_request_tag`, `tools_policy`, `mcp_session_cap`, cloud endpoint metadata.

---

## 3. Explicit refusal semantics

**Strict Option B** — low-confidence spans → HTTP 422, `type: redactor_refused`,
`reason: low_confidence_detection`.

**Tools policy `refuse`** — HTTP 422, `reason: tools_or_functions_present`.

Structured logging (JSON lines on the `llm_redactor` logger at INFO) records events such
as `proxy_tools_bypass`, `proxy_stream_prepared`, and `mcp_scrub` with counts and flags
only — never raw user text or secrets.
