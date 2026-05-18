# burp-llm-redactor

A Burp Suite extension that transparently redacts PII and secrets from outbound
LLM API traffic — the same privacy pipeline as the
[llm-redactor](../README.md) MCP/HTTP proxy, ported to Kotlin and wired into
Burp's proxy layer.

When a request to an LLM API host (OpenAI, Anthropic, Cursor Connect-RPC, etc.)
passes through Burp, the extension detects sensitive content in outbound bodies,
replaces it with typed Unicode placeholders (e.g. `⟨EMAIL_1⟩`,
`⟨AWS_ACCESS_KEY_1⟩`), and forwards the scrubbed request upstream.

**Responses are not redacted.** By default the upstream response body is passed
through unchanged so agent tool output, file writes, and protobuf RPC replies stay
verbatim. An optional setting can swap placeholders back in responses for simple
chat UIs only.

All state stays in the JVM heap for the duration of a request/response pair —
nothing is written to disk.

---

## Contents

- [How it works](#how-it-works)
- [Supported wire formats](#supported-wire-formats)
- [Outbound-only policy](#outbound-only-policy)
- [Requirements](#requirements)
- [Build](#build)
- [Install in Burp Suite](#install-in-burp-suite)
- [UI walkthrough](#ui-walkthrough)
- [Configuration reference](#configuration-reference)
- [Detection — patterns and categories](#detection--patterns-and-categories)
- [Placeholder format](#placeholder-format)
- [Session management](#session-management)
- [Streaming responses (SSE)](#streaming-responses-sse)
- [Using with the llm-redactor HTTP proxy](#using-with-the-llm-redactor-http-proxy)
- [NER endpoint integration](#ner-endpoint-integration)
- [Strict mode](#strict-mode)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Development](#development)

---

## How it works

```
Browser / Cursor / agent
        │
        ▼  (CONNECT or plain HTTP)
┌───────────────────────────────────────┐
│  Burp Suite Proxy (e.g. :8080)        │
│                                       │
│  RequestInterceptor                   │
│    1. Match target host + path        │
│    2. Detect format (JSON / Connect)  │
│    3. (strict) Drop if low-confidence │
│    4. Regex + optional NER detect     │
│    5. Replace spans → placeholders    │
│    6. Save reverse map + fingerprints │
│    7. Fix Content-Length / encoding   │
│    8. Forward scrubbed request ──────►│──► upstream LLM API
│                                       │
│  ResponseInterceptor (default)        │◄── upstream response
│    1. Match initiating request body   │
│    2. Drop session map from memory    │
│    3. Pass response through unchanged │──► client (verbatim)
│                                       │
│  ResponseInterceptor (optional)       │
│    … restore ⟨placeholders⟩ in body   │──► client (chat UX only)
└───────────────────────────────────────┘
```

The reverse map is keyed by a SHA-256 fingerprint of `host + path + request
body` (both the original and redacted bodies are indexed so restore still works
across Burp versions). It is never written to disk.

---

## Supported wire formats

| Format | `Content-Type` (typical) | Notes |
|---|---|---|
| OpenAI / Anthropic JSON | `application/json` | `messages[]` text and content blocks |
| OpenAI SSE (restore opt-in) | `text/event-stream` | Buffered by Burp; LCP delta restore |
| Cursor / Connect-RPC | `application/proto`, `application/connect+proto` | Unary and framed protobuf; path prefix `/aiserver.v1.` |
| OTLP traces | `application/json`, `application/x-protobuf` | `POST /v1/traces` — JSON tree walk or schema-blind protobuf |

HTTP body compression: **gzip**, **deflate**, **brotli**, **zstd**, and Unix
**compress** are decoded, redacted, and re-encoded (brotli needs native libs).
Unknown `Content-Encoding` tokens are left untouched (pass-through).

Protobuf redaction is **schema-blind** (no `.proto` files): the walker parses wire
format, **recurses into nested sub-messages** (depth cap 64), scans UTF-8 text in
string/bytes fields of any size (bounded only by the HTTP body Burp already buffered),
handles **packed length-delimited repeats**, and uses heuristics for embedded JSON
(skips hex/base64 blobs and malformed UTF-8). Opaque binary is unchanged.
Redact/restore round-trips preserve wire structure.

Decision order for each length-delimited field:

1. Valid nested protobuf → recurse and redact inner fields.
2. Else if UTF-8 text passes heuristics → scan and redact.
3. Else if packed `[len][bytes]…` repeats with scannable elements → redact each.
4. Else → copy bytes unchanged.

---

## Outbound-only policy

| Direction | Default | Purpose |
|---|---|---|
| Request → upstream | **Redact** | Cloud never sees raw secrets |
| Response ← upstream | **Pass through** | Tool calls, patches, and RPC payloads stay exact |

Enable **Restore placeholders in responses** in Settings only when you want
the assistant text in a plain chat UI to show original values instead of
`⟨EMAIL_1⟩`. Leave it **off** for Cursor agent sessions (recommended).

The plugin does **not** scan response bodies for new PII from the model — only
optional placeholder substitution using the map from the paired request.

---

## Requirements

| Requirement | Minimum version |
|---|---|
| Burp Suite Professional or Community | 2022.2.1 (Montoya API) |
| Java (to build) | 21+ |
| Gradle (to build) | 8.x / 9.x (wrapper included) |

The JAR targets **Java 21** bytecode. Burp ships its own JRE; any modern Burp
version includes a compatible one.

---

## Build

```bash
cd burp-plugin
./gradlew shadowJar
# → build/libs/burp-llm-redactor.jar  (~1.9 MB, fat jar)
```

The shadow jar bundles Kotlin stdlib and `org.json`. The Montoya API is
`compileOnly` — Burp provides it at runtime and must **not** be bundled.

To rebuild after changes:

```bash
./gradlew clean shadowJar
```

---

## Install in Burp Suite

1. Open Burp Suite.
2. Go to **Extensions → Installed → Add**.
3. Set **Extension type** to `Java`.
4. Click **Select file** and choose `build/libs/burp-llm-redactor.jar`.
5. Click **Next**. The **Output** tab should show:

   ```
   LLM Redactor loaded — hosts: api.openai.com, api.anthropic.com, api2.cursor.sh, ...
   ```

6. A new **LLM Redactor** tab appears in the Burp Suite top-level tab bar.

> **Note:** Settings survive restarts — they are persisted via Burp's built-in
> extension data store (no external config file required).

---

## UI walkthrough

```
┌─ LLM Redactor ───────────────────────────────────────────────────────────┐
│  LLM Redactor — Outbound redaction for LLM API traffic      [● Live]    │
├─[ Settings ]──[ Activity ]──────────────────────────────────────────────┤
│                                                                          │
│  SETTINGS (collapsible sections — click ▾/▸ to fold)                     │
│  ▾ Scope          hosts / paths (multi-line)                             │
│  ▾ Detection      categories · NER · Ollama validation                   │
│  ▾ Policies       tools policy · strict · restore responses              │
│  ▸ Advanced       placeholders · debug · session cap · log cap         │
│                                              [ Save settings ]           │
│                                                                          │
│  ACTIVITY (full width)                                                   │
│  [ Requests ] [ Spans ] [ Restores ] [ Refusals ] [ Evictions ]         │
│  Recent redactions · newest first · configurable row cap   [Clear][CSV] │
│  ▾ Activity log   Time | Host | Path | Spans | Kinds                    │
└──────────────────────────────────────────────────────────────────────────┘
```

Burp-orange accents match the suite chrome. Settings use a fixed-width left
column; Activity stretches to the full tab width.

### Live / Paused toggle

The header pill (**● Live** / **○ Paused**) toggles interception immediately.
When paused, traffic passes through unmodified — no detection, redaction, or
logging. The state is persisted.

### Settings tab

Grouped into **collapsible sections** (Scope, Detection, Policies, Advanced).
Click the section header or chevron to expand/collapse. Advanced starts
collapsed.

Settings apply when you click **Save settings**. See
[Configuration reference](#configuration-reference) for field details.

### Activity tab

- **Metric cards** — running totals since the extension loaded (`Requests`,
  `Spans redacted`, `Restores`, `Refusals`, `Evictions`). **Evictions** updates
  live when the session LRU drops old placeholder maps (see [Session
  management](#session-management)).
- **Activity log** — one row per redacted or refused request, **newest first**.
  Strict-mode drops show `REFUSED low_confidence: …` in the Kinds column.
  With **Log matched requests** enabled (default), requests that matched scope
  but had **0 spans** show `no_spans` in Kinds; tool bypass shows `tools_bypass`.
  These rows do **not** increment the **Requests** metric (only actual redactions do).
- **Retention** — a ring buffer keeps the last **N** rows (default **500**, tunable
  under Settings → Advanced). Older rows drop automatically; nothing is written
  to disk. Use **Export CSV** before **Clear** if you need a longer history.
- **Clear** — empties the log table and resets all counters (including
  evictions). Does **not** clear in-flight session maps used for restore.
- **Export CSV** — saves the rows currently visible in the table.

---

## Configuration reference

All settings are persisted via the Montoya extension data store. They survive
Burp restarts.

### Target hosts

Comma-separated list of hostnames the plugin should intercept.
Subdomains match automatically: adding `openai.com` also covers
`api.openai.com` and `api.eu.openai.com`.

**Default** (also merged automatically on load for existing installs):

```
api.openai.com, api.anthropic.com, openai.azure.com, api.deepseek.com,
cursor.sh, api2.cursor.sh, repo42.cursor.sh, api5.cursor.sh,
agent.api5.cursor.sh, agentn.api5.cursor.sh, agentn.global.api5.cursor.sh
```

Add any OpenAI-compatible, Anthropic-compatible, or Cursor endpoint here.

### Target paths

Path prefixes that identify LLM chat / RPC traffic. Requests outside these
prefixes are passed through unchanged.

**Default** (merged into persisted config like Cursor hosts):

```
/v1/chat/completions, /v1/messages, /v1/completions, /anthropic/v1/messages,
/aiserver.v1.
```

Paths are configured in `PluginConfig` defaults (not yet a separate UI field).
Any path starting with `/aiserver.v1.` matches Cursor Connect-RPC methods.

### Categories

Which families of sensitive data to detect and redact. Multiple categories
can be active simultaneously.

| Checkbox | Alias | Expands to |
|---|---|---|
| **PII** | `pii` | `identity`, `contact`, `government_id`, `financial`, `medical`, `temporal` |
| **Secrets** | `secret` | `credential`, `cloud_credential`, `vendor_api_key`, `private_key` |
| **Org IDs** | `org_identifier` | `infrastructure` (internal hostnames, connection strings) |
| **All** | `all` | Every category in the taxonomy |

Fine-grained category names can be typed directly into the field if you need
to narrow further (e.g. `cloud_credential, vendor_api_key`).

**Default:** `pii, secret`

### NER endpoint

Optional URL of an HTTP endpoint that provides named-entity recognition for
person names, organisation names, and locations that regex cannot reliably
detect.

- Leave blank to use regex-only mode (the default).
- Click **Test** to verify connectivity before applying.
- Falls back silently to regex-only if the endpoint is unavailable.

See [NER endpoint integration](#ner-endpoint-integration) for the wire format
and how to use the llm-redactor server as the NER backend.

### Strict mode

When enabled, any span detected with `confidence < 0.5` causes the **entire
request to be dropped** (Burp drops it; the LLM never sees it). Off by default.

This mirrors `pipeline.opt_b_redact.strict` in the Python config.

When a request is refused:
- Burp **drops** the request (`ProxyRequestReceivedAction.drop()`).
- The log shows **0 spans** and `REFUSED low_confidence: …` in Kinds.
- The **Requests** counter is **not** incremented; **Refusals** is.

Regex detections use confidence `1.0`; strict mode mainly affects **NER** spans.

### Restore placeholders in responses

**Off by default.** When enabled, the response handler replaces `⟨…⟩` placeholders
in JSON, SSE, or Connect/protobuf bodies using the reverse map from the paired
request. When disabled (recommended for agents), responses are **not modified** —
only the in-memory session entry is removed.

### Placeholder tag

When enabled, each redaction session gets a random 8-hex-character suffix
embedded in every placeholder:

```
⟨EMAIL_1·a1b2c3d4⟩   instead of   ⟨EMAIL_1⟩
```

This prevents accidental collisions if a model's training data or the user's
text happens to contain a string that looks like a placeholder. Off by default.

### Session cap

Maximum number of in-flight request/response sessions to hold in memory at
once (LRU eviction when exceeded). Default: **10,000** (used when no value has
been saved yet).

Increase if you are sending many parallel streaming requests; decrease if
memory is constrained.

### Debug dump

When enabled, writes request/response byte dumps and a trace log under
`/tmp/burp-redactor-debug/` (useful for protobuf / encoding issues). Off by default.

### Activity log row cap

Maximum rows in the Activity log table (ring buffer). Default: **500** (range
50–10,000). Older rows are dropped when the cap is exceeded.

### Log matched requests

When enabled (default), the Activity log records target requests even when no
spans were redacted (`no_spans`) or when JSON tool/function payloads bypass
redaction (`tools_bypass`). Disable to log only successful redactions and refusals.

---

## Detection — patterns and categories

The plugin ships **39 regex patterns** ported directly from
`src/llm_redactor/detect/regex.py`. They are grouped by category below.

### PII (`pii`)

#### identity
| Kind | Example match |
|---|---|
| `employee_id` | `EMP-001234` |

#### contact
| Kind | Example match |
|---|---|
| `email` | `alice@example.com` |
| `phone_us` | `+1 (415) 555-0100` |
| `phone_intl` | `+44 20 7946 0958` |
| `ip_v4` | `192.168.1.1` |
| `ip_v6` | `2001:db8::1` |

#### government_id
| Kind | Example match |
|---|---|
| `ssn` | `123-45-6789` |

#### financial
| Kind | Example match |
|---|---|
| `credit_card` | `4111 1111 1111 1111` |

### Secrets (`secret`)

#### credential
| Kind | Example match |
|---|---|
| `password` | `password = s3cr3t!` |
| `secret_assignment` | `token = abc123xyz` |
| `bearer_token` | `Bearer eyJhbGci...` |
| `basic_auth` | `Basic dXNlcjpwYXNz` |
| `jwt` | `eyJhbGciOiJSUzI1NiJ9.eyJzdWIi...` |
| `generic_api_key` | `api_key=abcdef1234567890` |

#### cloud_credential
| Kind | Example match |
|---|---|
| `aws_access_key` | `AKIAIOSFODNN7EXAMPLE` |
| `aws_secret_key` | `aws_secret_key = wJalrXUtnFEMI/...` |
| `aws_session_token` | `aws_session_token = FwoGZXIvYXdz...` |
| `gcp_service_account` | `svc@project.iam.gserviceaccount.com` |
| `gcp_api_key` | `AIzaSyD-9tSrke72...` |
| `azure_storage_key` | `account_key = abc123==` |
| `azure_connection_string` | `DefaultEndpointsProtocol=https;AccountName=...` |

#### vendor_api_key
| Kind | Example match |
|---|---|
| `openai_api_key` | `sk-proj-abc123...` |
| `anthropic_api_key` | `sk-ant-api03-abc123...` |
| `github_token` | `ghp_abc123...` |
| `gitlab_token` | `glpat-abc123...` |
| `slack_token` | `xoxb-1234-5678-abcd` |
| `slack_webhook` | `https://hooks.slack.com/services/T.../B.../...` |
| `stripe_key` | `sk_live_abc123...` |
| `twilio_key` | `SK0123456789abcdef...` |
| `sendgrid_key` | `SG.abc123.xyz456` |
| `mailgun_key` | `key-abc123...` |
| `npm_token` | `npm_abc123...` |
| `pypi_token` | `pypi-AgEI...` |
| `heroku_api_key` | `heroku_api_key=11111111-2222-3333-4444-555555555555` |

#### private_key
| Kind | Example match |
|---|---|
| `private_key_pem` | `-----BEGIN PRIVATE KEY-----` |
| `ssh_private_key` | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| `pgp_private_key` | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |

### Org IDs (`org_identifier`)

#### infrastructure
| Kind | Example match |
|---|---|
| `connection_string` | `postgres://user:pass@db.internal:5432/prod` |
| `hostname_internal` | `db-primary.internal`, `cache.corp` |

### False-positive suppression

The following NER-sourced detections are suppressed automatically (mirrors
Python `_FP_SUPPRESS`):

- Generic acronyms: `api`, `pii`, `llm`, `sql`, `url`, `gpt`, …
- Relative time words: `today`, `yesterday`, `now`, …
- Fiscal quarter refs: `q1` – `q4`
- Common drug names misclassified as `PERSON` by spaCy/Presidio
- Spans of length ≤ 2 (except `ssn`, `ip_address`)
- NER spans with `confidence < 0.4` and `length < 6`

---

## Placeholder format

Placeholders use rare Unicode angle brackets to minimise accidental collisions
with user text:

```
⟨KIND_N⟩           e.g. ⟨EMAIL_1⟩, ⟨AWS_ACCESS_KEY_1⟩
⟨KIND_N·TAG⟩       e.g. ⟨EMAIL_1·a1b2c3d4⟩  (placeholder tag enabled)
```

- `KIND` — uppercase detection kind (e.g. `EMAIL`, `JWT`, `OPENAI_API_KEY`)
- `N` — per-kind counter, starting at 1; increments each time a new distinct
  value is seen within a request
- `·` — U+00B7 MIDDLE DOT (separator)
- `TAG` — 8 random hex characters, unique per request (when placeholder tag
  is enabled)

**Coreference stability:** two occurrences of the same original string within
the same request get the **same** placeholder. If the same email appears in
the system prompt and the user message it becomes `⟨EMAIL_1⟩` in both places.

---

## Session management

Each outbound request that redacts at least one span stores a **reverse map**
(placeholder → original) in an in-memory LRU `SessionStore`, keyed internally by
a random UUID and indexed by **request fingerprints**:

```
SHA-256(host + NUL + path + NUL + request_body_bytes)
```

Both the **client-original** body and the **redacted** body sent upstream are
indexed. Burp versions disagree on which body `initiatingRequest` returns on the
response path; dual indexing avoids restore misses.

No custom HTTP headers are added to upstream traffic.

On response, the handler fingerprints the initiating request, **removes** the
map (one-shot), and either passes the body through (default) or restores
placeholders (optional).

If the LRU cap evicts a session before the response arrives, any optional restore
cannot run; with the default pass-through policy the client still receives the
upstream body unchanged.

Each LRU eviction increments the **Evictions** counter on the Activity tab (live,
not only on Clear). Tune **Session cap** under Settings → Advanced if you see
evictions during normal chat traffic.

The Activity **log table** is separate from session maps: it keeps the last
**Activity log row cap** UI rows (default 500) for auditing and exports.
Session maps are bounded by **Session cap** (default 10,000) and are not persisted.

---

## Streaming responses (SSE)

Only applies when **Restore placeholders in responses** is enabled.

Burp buffers the complete SSE body before passing it to extensions, so the
plugin receives all `data:` lines at once. The restoration algorithm is a
faithful port of the Python streaming path:

1. Parse each `data: {...}` line.
2. Accumulate `choices[].delta.content` fragments into a growing string.
3. Run `restore(accumulated, reverseMap)` to get the fully-restored text so far.
4. Compute the **longest common prefix (LCP)** between the previous restore
   result and the new one.
5. Emit only `newRestored.substring(lcp)` as the corrected delta, so that
   clients concatenating deltas still reconstruct the correct plaintext —
   including placeholders that were split across chunk boundaries.

This handles the edge case where a placeholder like `⟨EMAIL_1⟩` is split
across two or more SSE chunks.

---

## Using with the llm-redactor HTTP proxy

The Burp plugin and the Python HTTP proxy (`src/llm_redactor/transport/http_proxy.py`)
solve the same problem at different layers. You can use either independently,
or combine them.

### Option A — Burp plugin only (recommended for interactive testing)

Point your browser or tool at Burp's proxy (default `:8080`). The plugin
intercepts traffic automatically. No llm-redactor process required.

```
curl --proxy http://127.0.0.1:8080 \
     https://api.openai.com/v1/chat/completions \
     -H "Authorization: Bearer $OPENAI_API_KEY" \
     -d '{"model":"gpt-4o","messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}'
```

### Option B — llm-redactor HTTP proxy only (recommended for agents/scripts)

Run the llm-redactor server and point `OPENAI_BASE_URL` at it:

```bash
cd ..   # repo root
uv run python -m llm_redactor.cli serve --config config.yaml
# HTTP proxy listens on http://localhost:7789

export OPENAI_BASE_URL=http://localhost:7789/v1
```

### Option C — Both layers in sequence

Run the llm-redactor HTTP proxy **and** route it through Burp for inspection.
This lets you observe what the redactor sends to the cloud while also having
Burp's history, repeater, and scanner available.

```
Agent → llm-redactor proxy (:7789) → Burp proxy (:8080) → cloud LLM
```

Configure the llm-redactor process to use Burp as an upstream proxy:

```bash
# export proxy env vars so httpx picks them up
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080

# If Burp's CA cert isn't in the system store, point httpx at it:
export SSL_CERT_FILE=/path/to/burp-ca.pem

uv run python -m llm_redactor.cli serve --config config.yaml
```

In this setup, the Burp plugin **also** intercepts the already-redacted
requests from the Python proxy. To avoid double-redaction you have two options:

- **Disable the Burp plugin** (toggle off) — use Burp for visibility only.
- **Restrict Burp plugin scope** — remove `api.openai.com` from the Burp
  plugin's target hosts and add `127.0.0.1` / `localhost` pointing at the
  llm-redactor proxy port instead. The plugin then only redacts traffic that
  hasn't gone through the Python layer.

### Option D — Burp plugin as the NER backend caller

The Burp plugin can call the llm-redactor server's NER endpoint to get
Presidio-powered person/org/location detection:

1. Start the llm-redactor HTTP proxy (it exposes a `/v1/redactor/detect` endpoint):

   ```bash
   uv run python -m llm_redactor.cli serve --config config.yaml
   ```

2. In the Burp plugin's **Settings** tab, set **NER endpoint** to:
   ```
   http://localhost:7789/v1/redactor/detect
   ```

3. Click **Test** — you should see "NER endpoint reachable ✓".
4. Click **Apply**.

The plugin will now send each text field to the llm-redactor NER endpoint
before regex detection, combining both result sets.

---

## NER endpoint integration

The NER client (`NerClient.kt`) speaks a simple JSON protocol:

### Request

```
POST <nerEndpoint>
Content-Type: application/json

{"text": "Call me at +44 20 7946 0958 or email alice@example.com"}
```

### Response

```json
[
  {"start": 10, "end": 25, "kind": "phone_intl", "confidence": 0.95, "text": "+44 20 7946 0958", "source": "ner"},
  {"start": 35, "end": 52, "kind": "email",      "confidence": 0.99, "text": "alice@example.com", "source": "ner"}
]
```

Any HTTP server that accepts this contract works. The llm-redactor HTTP proxy
exposes a compatible endpoint at `http://localhost:7789/v1/redactor/detect`
when running — see [docs/API.md](../docs/API.md) for the full spec.

Connectivity and response timeouts are both 5 seconds. Any connection error,
non-200 status, or JSON parse failure is silently swallowed — the plugin falls
back to regex-only for that request.

---

## Limitations

1. **Outbound redaction only (by default).** Responses are not scanned for new
   PII from the model. Optional restore only swaps known placeholders from the
   paired request.

2. **JSON `messages[]` focus for OpenAI-style APIs.** Tool and function payloads
   follow **Tools policy** (`bypass` forwards unchanged; `refuse` drops the request).
   Tool *schemas* in JSON are not deeply redacted — keep secrets out of definitions.

3. **Protobuf is schema-blind.** Nested sub-messages and packed string/bytes repeats
   are walked; UTF-8 text uses heuristics. **Packed numeric** (varint) repeats and
   custom non-protobuf encodings are not interpreted — secrets there may slip through.

4. **Compression.** Brotli requires native libraries; if unavailable, `br` bodies
   may decode as identity and skip redaction until the library loads. Unix `compress`
   is decoded for redaction; re-encode may fall back to plaintext (header stripped)
   because commons-compress does not ship a Z compressor writer.

5. **NER requires an HTTP endpoint.** No bundled model; point at llm-redactor's
   `/v1/redactor/detect` or any compatible server.

6. **The reverse map is not persisted.** Restarting Burp mid-flight drops in-memory
   state. Intentional — an on-disk map would be a leakage channel.

7. **Implicit sensitive data is not detected.** Use the Python rephrase pipeline
   for phrases without literal tokens (e.g. "the CEO's email").

8. **Burp buffers full responses** before extensions run (memory use on huge streams).

---

## Troubleshooting

### `ZlibError: Error -3 while decompressing data`

The most common cause is traffic routing through mitmproxy or another MITM proxy
whose certificate is not trusted by Burp's JRE.

```bash
# Import the mitmproxy cert into the JVM keystore Burp uses:
keytool -import -trustcacerts -alias mitmproxy \
  -file ~/.mitmproxy/mitmproxy-ca-cert.pem \
  -keystore "$JAVA_HOME/lib/security/cacerts" \
  -storepass changeit
```

Alternatively, set `NO_PROXY=api.openai.com,api.anthropic.com` so those
connections bypass mitmproxy entirely.

### Plugin loads but no requests are intercepted

1. Check that Burp's proxy listener is on and your browser/tool is using it.
2. Check the **Target hosts** field — the hostname must match exactly or as a
   suffix (e.g. `openai.com` matches `api.openai.com`).
3. Confirm the path matches a default prefix (e.g. `/v1/chat/completions` or
   `/aiserver.v1.…` for Cursor).
4. Verify `Content-Type` is supported: `application/json` or `application/proto`
   (and Connect variants).
5. Make sure the header pill shows **● Live** (not **○ Paused**).

### `API Error: empty or malformed response` (Cursor / protobuf)

Usually fixed by correct `Content-Length`, gzip handling, and fingerprint-based
sessions. Enable **Debug dump**, reproduce once, and inspect
`/tmp/burp-redactor-debug/trace.log`.

### Placeholders visible in the UI or in model output

**Expected** when **Restore placeholders in responses** is off (default): upstream
sees and may echo `⟨EMAIL_1⟩`. Enable restore only for plain chat, not agent/file
workflows.

If restore **is** on and placeholders remain, the session may have been evicted:
- Increase **Session cap** under high concurrency.
- Avoid reloading the extension mid-request.

### NER endpoint test fails

- Check that the llm-redactor server is running: `curl http://localhost:7789/ner -d '{"text":"test"}' -H "Content-Type: application/json"`
- Check the port matches (default llm-redactor HTTP proxy port is `7789`).
- If the server is behind a proxy, ensure `NO_PROXY` includes `localhost`.

### Extension output shows `LLM Redactor loaded` but the tab does not appear

This is a Burp UI race condition on some versions. Go to
**Extensions → Installed**, unload and reload the extension.

### Double-redaction when used with the llm-redactor HTTP proxy

See [Option C](#option-c--both-layers-in-sequence) above for the correct
configuration. Either disable the Burp plugin or restrict its target hosts
so it doesn't intercept already-scrubbed traffic.

### Build fails: `Could not find net.portswigger.burp.extensions:montoya-api`

Maven Central is unavailable. The artifact is at:
```
https://repo.maven.apache.org/maven2/net/portswigger/burp/extensions/montoya-api/
```
Check your network / proxy settings and retry.

---

## Project layout

```
burp-plugin/
├── build.gradle.kts            # Kotlin JVM + shadow jar
├── settings.gradle.kts
├── gradlew / gradlew.bat       # Gradle wrapper
├── README.md                   # This file
└── src/main/kotlin/com/llmredactor/burp/
    ├── BurpExtension.kt        # Montoya entry-point; wires everything
    │
    ├── config/
    │   └── PluginConfig.kt     # All settings; persisted via Montoya store
    │
    ├── detect/
    │   ├── Span.kt             # Detected-span data class
    │   ├── CategoryMap.kt      # kind→category taxonomy + alias expansion
    │   ├── RegexDetector.kt    # 39 compiled regex patterns
    │   └── DetectionOrchestrator.kt  # Merge overlaps, filter false-positives
    │
    ├── redact/
    │   ├── PlaceholderGenerator.kt   # ⟨KIND_N⟩ stable placeholder generator
    │   └── Restorer.kt               # Reverse-map substitution
    │
    ├── pipeline/
    │   └── RedactionPipeline.kt      # detect → filter → redact per text field
    │
    ├── transport/
    │   ├── BodyFormat.kt             # JSON / Connect / SKIP detection
    │   ├── BodyProcessor.kt          # Unified redact + optional restore
    │   ├── ConnectProtoCodec.kt      # Connect framing + HTTP gzip/deflate
    │   ├── ProtobufRedactor.kt       # Schema-blind string-field walk
    │   ├── TransportLogic.kt         # JSON/SSE helpers, encoding
    │   ├── SessionStore.kt           # LRU + fingerprint index
    │   ├── NerClient.kt              # Optional HTTP NER
    │   ├── RequestInterceptor.kt     # Outbound redact + strict drop
    │   ├── ResponseInterceptor.kt    # Pass-through or restore
    │   └── Stats.kt                  # Atomic counters
    │
    └── ui/
        ├── RedactorTab.kt            # Root Burp tab panel (enable toggle + tabs)
        ├── ConfigPanel.kt            # Settings form + Apply button
        └── LogPanel.kt               # Redaction log table + stats + CSV export
```

### Key dependencies

| Dependency | Version | Scope | Purpose |
|---|---|---|---|
| `net.portswigger.burp.extensions:montoya-api` | 2026.4 | compileOnly | Burp Suite Montoya API |
| `org.jetbrains.kotlin:kotlin-stdlib` | 2.1.20 | bundled | Kotlin runtime |
| `org.json:json` | 20240303 | bundled | JSON parsing (67 KB, no transitive deps) |

---

## Development

### Rebuilding

```bash
cd burp-plugin
./gradlew shadowJar          # incremental
./gradlew clean shadowJar    # full rebuild
```

### Adding new regex patterns

Edit `RegexDetector.kt`. Each entry is:

```kotlin
add("kind_name", """regex_pattern_here""")               // full match
add("kind_name", """prefix_([captured_value])""", hasGroup = true)  // group(1) only
```

Also add a `"kind_name" to "category"` mapping in `CategoryMap.kt` so the new
kind participates in category filtering.

### Upgrading the Montoya API

Change the version in `build.gradle.kts`:

```kotlin
compileOnly("net.portswigger.burp.extensions:montoya-api:YYYY.N")
```

Check available versions:
```bash
curl -s https://repo.maven.apache.org/maven2/net/portswigger/burp/extensions/montoya-api/maven-metadata.xml \
  | grep '<version>'
```

### Running tests

```bash
cd burp-plugin
./gradlew test
```

JUnit covers transport encoding, Connect/protobuf round-trips, and strict mode.
The Python repo's eval harness (`evals/`) remains the broader detection baseline:

```bash
cd ..   # repo root
uv run python -m evals.run_eval --workload wl1_pii
```

Manual Burp stress: `scripts/stress_mock_llm.py` + `scripts/stress-test.sh`.

---

## Relationship to the Python llm-redactor

This plugin is a structural port of the Python codebase. The table below maps
each Kotlin class to its Python counterpart:

| Kotlin | Python |
|---|---|
| `RegexDetector` | `src/llm_redactor/detect/regex.py` |
| `CategoryMap` | `src/llm_redactor/detect/types.py` (CATEGORY_MAP + ALIASES) |
| `DetectionOrchestrator` | `src/llm_redactor/detect/orchestrator.py` |
| `PlaceholderGenerator` + `redact()` | `src/llm_redactor/redact/placeholder.py` |
| `Restorer` | `src/llm_redactor/redact/restore.py` |
| `SessionStore` | `_sessions` OrderedDict in `transport/mcp_server.py` |
| `NerClient` | The NER detection path in `detect/ner.py` + `detect/orchestrator.py` |
| `RequestInterceptor` | `POST /v1/chat/completions` handler in `transport/http_proxy.py` |
| `ResponseInterceptor` | Response restoration path in `transport/http_proxy.py` |
| `PluginConfig` | `src/llm_redactor/config.py` |

Features present in the Python implementation but **not** in the Burp plugin
(research-stage or out of scope for a proxy extension):

| Python option | Status in Burp plugin |
|---|---|
| Option A (local-only routing) | Not applicable — Burp routes traffic, not the plugin |
| Option C (rephrase via local LLM) | Not implemented |
| Option D (TEE endpoint) | Not implemented |
| Options E/F/G (split inference / FHE / MPC) | Not implemented (research stubs) |
| Option H (DP noise) | Not implemented |
| Differential privacy token substitution | Not implemented |
| Audit journal (`runs.jsonl`) | Not implemented (use Burp's own history) |
