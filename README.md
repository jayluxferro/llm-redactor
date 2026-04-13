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
classes. See [`paper/paper.tex`](paper/paper.tex) for the full paper.

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
| E/F/G | 0% | 0% | 0% | 0% |

*Combined leak rate (exact + partial). Lower is better. E/F/G are
protocol stubs — 0% reflects that tokens never leave the device.*

## Quick start

```bash
# Install
uv sync

# Run the HTTP proxy (OpenAI-compatible)
uv run llm-redactor serve --port 7789

# Dry-run detection
uv run llm-redactor detect "Contact alice@example.com for API key sk-abc123" --redact

# Run the MCP stdio server
uv run llm-redactor mcp

# Run the evaluation harness
uv run python -m evals.run_eval --option B --use-ner
```

## Using with a coding agent

### Transparent HTTP proxy (recommended)

The agent doesn't know redaction is happening — you just swap the API URL.

```bash
# Terminal 1: start the redactor proxy
uv run llm-redactor serve --port 7789
```

Then point your agent at it:

```bash
# Claude Code
export OPENAI_API_BASE=http://localhost:7789/v1
claude

# Aider
aider --openai-api-base http://localhost:7789/v1

# Cursor / Continue / any OpenAI-compatible agent
# Set api_base: http://localhost:7789/v1 in the agent's config
```

The proxy intercepts every request, redacts PII/secrets, forwards to
the real cloud endpoint, restores placeholders in the response, and
returns a normal answer. The agent never sees placeholders.

### MCP server (explicit tools)

For MCP-capable agents (Claude Code, Claude Desktop), add to your
MCP config:

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

This exposes four tools:

- **`redact.scrub`** — detect and redact sensitive content; returns redacted text + `session_id`
- **`redact.restore`** — given a response + `session_id`, restore placeholders to originals
- **`redact.detect`** — dry-run: show what would be redacted without changing anything
- **`redact.stats`** — request/detection/restore counters

The redactor never contacts the cloud — it just scrubs content.
The agent handles its own LLM calls.

#### MCP workflow

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

#### Example: scrub before sending

Call `redact.scrub` with sensitive text:

```json
{
  "text": "Contact alice@example.com about project Falcon. API key: sk-abc123def456"
}
```

Returns:

```json
{
  "redacted_text": "Contact ⟨EMAIL_1⟩ about project Falcon. API key: ⟨API_KEY_1⟩",
  "session_id": "a1b2c3d4-...",
  "detections": 2,
  "detected_kinds": ["email", "generic_api_key"]
}
```

Send `redacted_text` to your LLM. When you get the response back,
call `redact.restore`:

```json
{
  "text": "I've drafted an email to ⟨EMAIL_1⟩ regarding project Falcon.",
  "session_id": "a1b2c3d4-..."
}
```

Returns:

```json
{
  "restored_text": "I've drafted an email to alice@example.com regarding project Falcon.",
  "placeholders_restored": 2
}
```

#### One-shot: `llm.chat` (easiest for MCP)

If you want the agent to use a single tool that handles everything
(scrub → LLM call → restore), use `llm.chat`:

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
Requires `cloud_target` in `llm_redactor.yaml` or env vars.

### Claude Code hook (automatic warnings)

Install a pre-tool hook that warns when sensitive content is about
to leave through any tool:

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

The hook scans tool inputs for emails, API keys, bearer tokens, PEM
keys, and SSN patterns. If found, it blocks the tool call with a
warning suggesting `redact.scrub` or `llm.chat` instead.

### Dual mode: proxy + MCP (belt and suspenders)

Run both for maximum coverage:

```bash
# Terminal 1: proxy catches all OpenAI-compatible traffic
uv run llm-redactor serve --port 7789

# Agent config: point at proxy AND load MCP tools
export OPENAI_API_BASE=http://localhost:7789/v1
```

With MCP config also loaded, the agent has:
- **Proxy**: silently redacts everything going to the cloud
- **`redact.detect`**: inspect what the proxy would catch
- **`redact.scrub`/`restore`**: manual control when needed
- **Hook**: warns if sensitive data slips through other tools

### Comparison

| | HTTP Proxy | `llm.chat` | `scrub`/`restore` | Hook |
|---|---|---|---|---|
| Agent awareness | None | Calls one tool | Calls two tools | Warning only |
| Coverage | All requests | When agent uses it | When agent uses it | All tool calls |
| Cloud config needed | Yes | Yes | No | No |
| Works with | Any client | MCP agents | MCP agents | Claude Code |

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

paper/
  paper.tex        # LaTeX source
  bibliography.bib # References
  figures/         # Generated figures

docs/              # Architecture, options, threat model, API, evaluation design
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System design
- [`docs/OPTIONS.md`](docs/OPTIONS.md) — All eight options in detail
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — Actors, assets, attack scenarios
- [`docs/API.md`](docs/API.md) — MCP + HTTP interfaces
- [`docs/EVALUATION.md`](docs/EVALUATION.md) — Metrics and workload design

## Configuration

```yaml
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

## Tests

```bash
uv run pytest -v   # 38 tests
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
