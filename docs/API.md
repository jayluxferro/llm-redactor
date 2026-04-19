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
Returns a JSON list of span objects (offsets, kind, confidence, source).

### `redact.stats`

Process-wide counters (`requests`, `detections`, `restores`, `llm_calls`).

---

## 2. HTTP proxy interface

### `POST /v1/chat/completions`

OpenAI-compatible. Point `OPENAI_API_BASE` at `http://localhost:<port>/v1`.

**Response headers**

| Header | When |
|--------|------|
| `X-LLM-Redactor-Mode: redacted` | Normal path (redaction applied) |
| `X-LLM-Redactor-Mode: bypass-tools` | Request included `tools` or `functions` and `transport.tools_policy` is `bypass` |
| `X-LLM-Redactor-Bypass-Reason: tools-or-functions` | Same as bypass-tools |

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
      "sensitive_tokens_sent": 0
    }
  }
}
```

Streaming (`stream: true`) uses the same redaction path; placeholders are restored in
SSE `delta.content` chunks before they reach the client.

### `POST /v1/messages`

Anthropic Messages API shape: redacts string or text-block content, forwards to
`cloud_target`, restores in the response. `stream` is forced off in this handler.

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
