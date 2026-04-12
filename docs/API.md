# API

Two parallel interfaces into the same pipeline.

## 1. MCP interface (stdio)

### `redact.transform`

Main entry. Runs the full pipeline: detect, redact, (optionally
rephrase), route to the configured target, restore the response.

**Input**
```json
{
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."}
  ],
  "options_override": ["B", "C"],
  "strict": true,
  "meta": {
    "tool_name": "coding_agent",
    "session_id": "..."
  }
}
```

**Output (success)**
```json
{
  "response": "...",
  "detections": [
    {"kind": "email", "count": 2, "example_placeholder": "{EMAIL_1}"},
    {"kind": "org_name", "count": 1}
  ],
  "options_applied": ["B"],
  "latency_ms": 240,
  "leak_audit": {
    "outgoing_bytes": 1840,
    "sensitive_tokens_detected": 3,
    "sensitive_tokens_sent": 0
  }
}
```

**Output (refuse in strict mode)**
```json
{
  "error": "refused",
  "reason": "low_confidence_detection",
  "detected_spans": [...],
  "suggestion": "review the input and mark the sensitive spans manually, or disable strict mode"
}
```

### `redact.detect`

Dry-run. Runs only the detector and returns the spans it would
redact. Does not send anything anywhere.

### `redact.stats`

Aggregate counters since process start. Detection counts by kind,
refusal counts, average detection confidence, average pipeline
latency.

### `redact.config`

Read-only view of the current config.

---

## 2. HTTP proxy interface (`POST /v1/chat/completions`)

OpenAI-compatible. Point `OPENAI_API_BASE` at
`http://localhost:7789/v1` and every call transparently goes through
the redactor.

### Extra fields recognised by the proxy

| Field | Purpose |
|---|---|
| `extra_body.redactor.strict` | Override strict mode for this call |
| `extra_body.redactor.options` | List of option letters to enable for this call (overrides config) |
| `extra_body.redactor.refuse_on_unknown` | Boolean; refuse if detector is uncertain |
| `extra_body.redactor.tag` | Opaque string for metrics segmentation |

### Response shape

Standard OpenAI chat completion plus:

```json
{
  "choices": [...],
  "usage": {...},
  "redactor": {
    "options_applied": ["B"],
    "detections": [{"kind": "email", "count": 2}],
    "leak_audit": {...}
  }
}
```

---

## 3. Explicit refusal semantics

When strict mode is on and the detector has low confidence, the
proxy responds with HTTP 422 and a body explaining the refusal:

```http
HTTP/1.1 422 Unprocessable Entity
Content-Type: application/json

{
  "error": {
    "type": "redactor_refused",
    "reason": "low_confidence_detection",
    "detected_spans": [
      {"kind": "unknown_sensitive", "text_hint": "…abcd…", "confidence": 0.42}
    ],
    "guidance": "Review the request and mark the sensitive spans manually, or temporarily disable strict mode with extra_body.redactor.strict=false."
  }
}
```

Agents can catch this and prompt the user or escalate to a human.

---

## 4. Audit log endpoint

### `GET /v1/redactor/audit?since=<iso8601>`

Returns per-request audit entries since a timestamp. Each entry
includes the detection counts, options applied, and leak-audit
fields, but **never** the raw content or the reverse map.
