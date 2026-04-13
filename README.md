# llm-redactor

A privacy-preserving shim for outbound LLM requests. `llm-redactor`
sits between an agent and an LLM endpoint and removes, masks, or
transforms sensitive content **before** it leaves the device, then
restores placeholders in the response so the user gets a normal
answer.

## Paper

> **LLM-Redactor: An Empirical Evaluation of Eight Techniques for
> Privacy-Preserving LLM Requests**
>
> Justice Owusu Agyemang, Jerry John Kponyo, Elliot Amponsah,
> Godfred Manu Addo Boakye, Kwame Opuni-Boachie Obour Agyekum

We evaluate eight techniques on a common benchmark of 1,300 synthetic
prompts with 4,014 ground-truth annotations across four workload
classes.

## The eight options

| Option | Short name | What it does | Practical today? |
|---|---|---|---|
| **A** | `local-only` | Run inference entirely on a local model | Yes (bounded quality) |
| **B** | `redact` | NER + regex detection, typed placeholders, restore on response | Yes |
| **C** | `rephrase` | Local model semantically rewrites the prompt | Yes (quality-dependent) |
| **D** | `tee` | Forward to a Trusted Execution Environment (Nitro, SGX, PCC) | Partial |
| **E** | `split-inference` | Run first layers locally, send activations to remote | Research |
| **F** | `fhe` | Fully homomorphic encryption on ciphertext | Research (tiny models) |
| **G** | `mpc` | Secret-share input across non-colluding servers | Research |
| **H** | `dp-noise` | Calibrated word-level noise for statistical workloads | Yes (lossy) |

See [`docs/OPTIONS.md`](docs/OPTIONS.md) for the deep dive.

## Key results

| Option | WL1 (PII) | WL2 (Secrets) | WL3 (Implicit) | WL4 (Code) |
|--------|-----------|---------------|----------------|------------|
| Baseline | 100% | 100% | 100% | 100% |
| B (NER) | 15.3% | 31.8% | 95.0% | 58.5% |
| B+C | 13.9% | 31.6% | 94.1% | 55.8% |
| A | 6.3% | 24.2% | 46.8% | 59.9% |
| A+B+C | 0.6% | 6.4% | 43.6% | 31.3% |
| E/F/G | 0% | 0% | 0% | 0% |

*Combined leak rate (exact + partial). Lower is better. E/F/G are
protocol stubs — 0% reflects that tokens never leave the device.*

---

## Installation

```bash
uv sync
```

## Usage

There are four ways to use llm-redactor depending on your setup.

### 1. CLI (try it out)

```bash
# Detect sensitive spans
uv run llm-redactor detect "Contact alice@example.com, key AKIA1234567890ABCDEF"

# Detect with NER (slower, catches person/org names)
uv run llm-redactor detect "Email from John Smith at Acme Corp" --ner

# Detect and show redacted output
uv run llm-redactor detect "Contact alice@example.com about project Falcon" --redact
```

### 2. HTTP proxy (transparent, works with any agent)

The agent doesn't know redaction is happening — you just swap the API URL.

**Start the proxy:**

```bash
uv run llm-redactor serve --port 7789
```

**Point your agent at it:**

```bash
# Claude Code
export OPENAI_API_BASE=http://localhost:7789/v1
claude

# Aider
aider --openai-api-base http://localhost:7789/v1

# Cursor / Continue / any OpenAI-compatible agent
# Set api_base: http://localhost:7789/v1 in the agent's config

# Direct curl
curl http://localhost:7789/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Email alice@example.com about project Falcon"}]}'
```

The proxy intercepts every request, redacts PII/secrets, forwards to
the real cloud endpoint, restores placeholders in the response, and
returns a normal answer. Supports streaming (`stream: true`) and the
Anthropic Messages API (`/v1/messages`).

**Configure the cloud target** in `llm_redactor.yaml`:

```yaml
cloud_target:
  endpoint: https://api.openai.com/v1   # where to forward after redaction
  api_key_env: OPENAI_API_KEY            # env var holding the API key
pipeline:
  opt_b_redact: { enabled: true, strict: false }
```

Or use environment variables:

```bash
export LLM_REDACTOR_CLOUD_ENDPOINT=https://api.openai.com/v1
```

### 3. MCP server (for Claude Code, Claude Desktop, etc.)

Add to your MCP config (`~/.claude/settings.json` for Claude Code):

```json
{
  "mcpServers": {
    "llm-redactor": {
      "command": "uv",
      "args": ["--directory", "/path/to/llm-redactor", "run", "llm-redactor", "mcp"]
    }
  }
}
```

This gives the agent five tools:

| Tool | What it does | Cloud config needed? |
|------|-------------|---------------------|
| `llm.chat` | One-shot: scrub → call LLM → restore. Drop-in replacement for LLM calls. | Yes |
| `redact.scrub` | Redact text, return redacted version + `session_id` | No |
| `redact.restore` | Restore placeholders using `session_id` from scrub | No |
| `redact.detect` | Dry-run: show what would be detected | No |
| `redact.stats` | Request/detection/restore counters | No |

#### Option A: Use `llm.chat` (easiest)

The agent calls one tool that handles everything:

```json
{
  "messages": [
    {"role": "user", "content": "Help debug this for alice@example.com, API key sk-abc123"}
  ],
  "model": "gpt-4o"
}
```

Returns the LLM response with all sensitive content redacted in
transit and restored in the result. The agent never sees placeholders.
Requires `cloud_target` config (see above).

#### Option B: Use `scrub` / `restore` (no cloud config)

The agent handles its own LLM calls. The redactor just scrubs content.

```
Agent                          llm-redactor                Cloud LLM
  │                                │                           │
  │── redact.scrub(text) ─────────>│                           │
  │<── redacted_text + session_id ─│                           │
  │                                                            │
  │── send redacted_text ─────────────────────────────────────>│
  │<── response with placeholders ─────────────────────────────│
  │                                                            │
  │── redact.restore(response, session_id) ──>│                │
  │<── restored response ─────────────────────│                │
```

**Step 1: Scrub before sending**

```json
// Call redact.scrub
{ "text": "Contact alice@example.com about project Falcon. API key: sk-abc123def456" }
```

```json
// Returns
{
  "redacted_text": "Contact ⟨EMAIL_1⟩ about project Falcon. API key: ⟨API_KEY_1⟩",
  "session_id": "a1b2c3d4-...",
  "detections": 2,
  "detected_kinds": ["email", "generic_api_key"]
}
```

**Step 2: Send `redacted_text` to your LLM (however you normally do it)**

**Step 3: Restore the response**

```json
// Call redact.restore
{
  "text": "I've drafted an email to ⟨EMAIL_1⟩ regarding project Falcon.",
  "session_id": "a1b2c3d4-..."
}
```

```json
// Returns
{
  "restored_text": "I've drafted an email to alice@example.com regarding project Falcon.",
  "placeholders_restored": 2
}
```

### 4. Claude Code hook (automatic warnings)

Install a pre-tool hook that warns when sensitive content is about
to leave through any tool. Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/llm-redactor/hooks/detect-sensitive.sh"
          }
        ]
      }
    ]
  }
}
```

The hook scans every tool input for emails, API keys, bearer tokens,
PEM keys, and SSN patterns. If found, it blocks the tool call with a
warning. This works as a safety net alongside any of the other modes.

### Combining modes (belt and suspenders)

For maximum coverage, run the proxy AND load the MCP tools:

```bash
# Terminal 1: proxy catches all OpenAI-compatible traffic
uv run llm-redactor serve --port 7789

# Terminal 2: agent with both proxy and MCP
export OPENAI_API_BASE=http://localhost:7789/v1
claude  # with llm-redactor MCP server also configured
```

- **Proxy**: silently redacts everything going to the cloud
- **MCP tools**: available for the agent to inspect detections or manually scrub
- **Hook**: warns if sensitive data slips through other tool calls

### Mode comparison

| | HTTP Proxy | `llm.chat` | `scrub`/`restore` | Hook |
|---|---|---|---|---|
| Agent awareness | None | Calls one tool | Calls two tools | Warning only |
| Coverage | All requests | When agent uses it | When agent uses it | All tool calls |
| Cloud config needed | Yes | Yes | No | No |
| Works with | Any client | MCP agents | MCP agents | Claude Code |

---

## Configuration

```yaml
# llm_redactor.yaml
pipeline:
  opt_b_redact: { enabled: true, strict: true }
  opt_c_rephrase: { enabled: false }
  opt_h_dp_noise: { enabled: false, epsilon: 4.0 }
cloud_target:
  endpoint: https://api.openai.com/v1
  api_key_env: OPENAI_API_KEY
local_model:
  endpoint: http://127.0.0.1:11434
  chat_model: llama3.2:3b
```

Precedence: environment variables > YAML file > defaults.

## Project structure

```
src/llm_redactor/
  detect/          # NER + regex detection
  redact/          # Placeholder generation and restoration
  rephrase/        # Local model semantic rephrasing (Option C)
  noise/           # Differential privacy noise (Option H)
  pipeline/        # Option A-H pipeline implementations
  transport/       # HTTP proxy, MCP server, cloud/TEE/FHE/MPC clients
  config.py        # YAML config with env overrides
  cli.py           # Typer CLI

evals/
  workloads/       # 4 synthetic workloads (1,300 samples, 4,014 annotations)
  runner.py        # Evaluation runner for all options
  leak_meter.py    # Exact, partial, and semantic leak metrics
  utility_meter.py # Judge-model A/B utility comparison
  run_eval.py      # CLI entry point

hooks/
  detect-sensitive.sh  # Claude Code PreToolUse hook

docs/              # Architecture, options, threat model, API, evaluation design
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) -- System design
- [`docs/OPTIONS.md`](docs/OPTIONS.md) -- All eight options in detail
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) -- Actors, assets, attack scenarios
- [`docs/API.md`](docs/API.md) -- MCP + HTTP interfaces
- [`docs/EVALUATION.md`](docs/EVALUATION.md) -- Metrics and workload design

## Running the evaluation

```bash
# Option B with NER on all workloads
uv run python -m evals.run_eval --option B --use-ner

# Specific option and workload
uv run python -m evals.run_eval --option A+B+C --use-ner -w wl1_pii
```

## Tests

```bash
uv run pytest -v   # 46 tests
```

## License

MIT

## Citation

```bibtex
@article{agyemang2026llmredactor,
  title={LLM-Redactor: An Empirical Evaluation of Eight Techniques
         for Privacy-Preserving LLM Requests},
  author={Agyemang, Justice Owusu and Kponyo, Jerry John and
          Amponsah, Elliot and Boakye, Godfred Manu Addo and
          Agyekum, Kwame Opuni-Boachie Obour},
  year={2026},
  url={https://github.com/jayluxferro/llm-redactor}
}
```
