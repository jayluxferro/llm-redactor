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

The workflow: the agent calls `redact.scrub` before sending to the LLM,
sends the redacted text itself, then calls `redact.restore` on the
response. The redactor never contacts the cloud — it just scrubs content.

### Proxy vs MCP

| | HTTP Proxy | MCP |
|---|---|---|
| Agent awareness | None (transparent) | Agent calls tools explicitly |
| Coverage | All requests automatically | Only when agent chooses |
| Works with | Any OpenAI-compatible client | MCP-capable agents only |
| Streaming | Supported | Not yet |

For most use cases, the HTTP proxy is better — it catches everything
without relying on the agent to remember to use the tools.

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
