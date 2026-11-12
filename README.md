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
classes. [arXiv:2604.12064](https://arxiv.org/abs/2604.12064)

## Benchmark dataset

The **LLM-Redactor Leak Benchmark** is available on Hugging Face:
[`jayluxferro/llm-redactor-leak-benchmark`](https://huggingface.co/datasets/jayluxferro/llm-redactor-leak-benchmark)

```python
from datasets import load_dataset

# All 1,300 samples
ds = load_dataset("jayluxferro/llm-redactor-leak-benchmark")

# Single workload (wl1_pii | wl2_secrets | wl3_implicit | wl4_code)
pii = load_dataset("jayluxferro/llm-redactor-leak-benchmark", "wl1_pii")
```

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

There are five ways to use llm-redactor depending on your setup.

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
# Claude Code (Anthropic Messages API). No /v1 here: Claude Code appends
# /v1/messages itself. The proxy's cloud_target must then be Anthropic,
# e.g. examples/anthropic.yaml.
export ANTHROPIC_BASE_URL=http://localhost:7789
claude

# Aider
aider --openai-api-base http://localhost:7789/v1

# Cursor / Continue / openai-python (OPENAI_BASE_URL) / any OpenAI-compatible
# agent: base URL http://localhost:7789/v1. It must end in /v1, see below.

# Direct curl
curl http://localhost:7789/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Email alice@example.com about project Falcon"}]}'
```

The proxy redacts PII/secrets in requests to `/v1/chat/completions`,
`/v1/messages` and `/v1/messages/count_tokens`, forwards them to the real
cloud endpoint, restores placeholders in the response (streamed or not, text
and tool-call arguments alike), and returns a normal answer. On
`/v1/messages` that covers the system prompt, text, tool results, tool-call
inputs and text documents.

What it does **not** redact, so check it against your setup:

- **Any other path is forwarded raw**, e.g. OpenAI `/v1/responses` or
  `/v1/embeddings`, or a base URL configured without its `/v1`. Such responses
  carry `X-LLM-Redactor-Mode: raw-passthrough`.
- **OpenAI-format requests that carry `tools` / `functions`** bypass redaction
  unless `transport.tools_policy: refuse`. Most agents send tools on every
  call.
- **Content inside signed `thinking` blocks** is never modified, by design
  (see `redact/raw_surgery.py`).

**Configure the cloud target** in `llm_redactor.yaml`:

```yaml
cloud_target:
  endpoint: https://api.openai.com/v1   # where to forward after redaction
  api_key_env: OPENAI_API_KEY            # env var NAME (a pasted secret fails loudly at load)
pipeline:
  opt_b_redact: { enabled: true, strict: false }
```

Or use environment variables:

```bash
export LLM_REDACTOR_CLOUD_ENDPOINT=https://api.openai.com/v1
```

### 3. MCP server (for Claude Code, Claude Desktop, etc.)

Add to your MCP config: `.mcp.json` in the project, or `claude mcp add` for
Claude Code (MCP servers are not read from `~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "llm-redactor": {
      "command": "uv",
      "args": [
        "--directory", "/path/to/llm-redactor",
        "run", "llm-redactor", "mcp",
        "--config", "/path/to/llm-redactor/examples/local-only.yaml"
      ]
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
    {"role": "user", "content": "Help debug this for alice@example.com, API key sk-proj-4fJk9QmZ2LwX8rTb7Vn3"}
  ],
  "model": "gpt-4o"
}
```

Returns the LLM response with all sensitive content redacted in
transit and restored in the result. The agent never sees placeholders.
Requires a config with `cloud_target` — use
[`examples/mcp-with-cloud.yaml`](examples/mcp-with-cloud.yaml)
and pass via `--config` in the MCP args.

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
{ "text": "Contact alice@example.com about project Falcon. API key: sk-proj-4fJk9QmZ2LwX8rTb7Vn3" }
```

```json
// Returns (real output; NER is on by default and tags "Falcon" as an org).
// A short made-up key such as "sk-abc123" is NOT detected: vendor and generic
// key patterns require realistic lengths (sk- + 20 chars, or 16+ after "key:").
{
  "redacted_text": "Contact ⟨EMAIL_1⟩ about project ⟨ORG_NAME_1⟩. API key: ⟨OPENAI_API_KEY_1⟩",
  "session_id": "e7736626-...",
  "detections": 3,
  "detected_kinds": ["email", "openai_api_key", "org_name"]
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

### 4. Burp Suite extension (proxy-layer redaction)

For generic HTTP(S) traffic that already flows through Burp, load the Kotlin
extension instead of (or in addition to) the Python HTTP proxy. It redacts all
configured categories (default: `all`) from outbound request query values and
bodies, and from client-to-server WebSocket text frames:

```bash
cd burp-plugin
gradle shadowJar
# Install build/libs/burp-llm-redactor.jar in Burp → Extensions → Add
```

Point your browser or client at Burp’s proxy listener. The extension calls the
local `POST /v1/redactor/detect-batch` service first, which uses this project's
regex, NER, and optional local-LLM validation. If that service is unavailable,
the extension uses its local regex fallback. HTTP responses, SSE event streams,
and server-to-client WebSocket frames pass through unchanged.

| Topic | Detail |
|--------|--------|
| Full docs | [`burp-plugin/README.md`](burp-plugin/README.md) |
| Build | `gradle test shadowJar` |
| Detector backend | Start `uv run llm-redactor serve --port 7789`; the plugin uses `http://127.0.0.1:7789/v1/redactor/detect-batch` |

Supported body formats include UTF-8 text, JSON, XML, URL-encoded forms, multipart
text payloads, and schema-blind protobuf length-delimited UTF-8 fields. gzip,
deflate, and zstd bodies are decoded and re-encoded. Brotli, unreadable payloads,
signed requests, binary WebSocket frames, and JSON encrypted/ciphertext values pass through unchanged
and are shown in the plugin's live metadata-only activity table; no payload text
or detected values are persisted.

**Do not** stack Burp redaction on top of an already-scrubbed `OPENAI_API_BASE` pointed
at the llm-redactor proxy unless you intend to — restrict Burp target hosts or disable
one layer.

#### Optional local image redaction

The Burp extension can also redact raw JPEG/PNG request bodies and base64
`data:image/...` attachments in textual request bodies before they leave Burp. It
uses an optional local ONNX Runtime adapter and a user-supplied
Screenpipe-compatible detector; no image is sent to Ollama, `llama-server`, or a
cloud service. The model weights are CC BY-NC 4.0 and are not bundled, so enable it
only for permitted non-commercial use:

```bash
uv sync --extra image
git lfs install
git clone --depth 1 https://huggingface.co/screenpipe/pii-image-redactor models/screenpipe
```

```yaml
pipeline:
  image_redaction:
    enabled: true
    license_acknowledged: true
    model_path: /absolute/path/to/llm-redactor/models/screenpipe/rfdetr_v13.onnx
    input_size: 384
    score_threshold: 0.8
```

The adapter uses CoreML, CUDA, or DirectML when the installed ONNX Runtime exposes
one; otherwise it runs on CPU. It paints opaque rectangles over every detected region.
If the model/runtime is unavailable, the image passes through unchanged and the Burp
Activity tab records `image-redactor-unavailable`.

### 5. Claude Code hook (blocks risky tool calls)

Install a pre-tool hook that blocks a tool call whose input contains
sensitive content. Add to `~/.claude/settings.json`:

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

The hook scans every string in a tool input, nested ones included, for
emails, API keys in assignments, AWS access keys, bearer tokens, PEM keys
and SSN patterns. On a match it exits 2, which blocks the call, and the
findings go to stderr, which Claude Code shows to Claude. To warn without
blocking, change its `exit 2` to `exit 0`. It is a small pattern set (any
email blocks, including `git@github.com`), meant as a safety net alongside
the other modes, not a replacement for the detector.

### Combining modes (belt and suspenders)

For maximum coverage, run the proxy AND load the MCP tools:

```bash
# Terminal 1: proxy (cloud_target: Anthropic, see examples/anthropic.yaml)
uv run llm-redactor serve --port 7789

# Terminal 2: agent with both proxy and MCP
export ANTHROPIC_BASE_URL=http://localhost:7789
claude  # with llm-redactor MCP server also configured
```

- **Proxy**: redacts the agent's model traffic (see the limits listed above)
- **MCP tools**: available for the agent to inspect detections or manually scrub
- **Hook**: blocks tool calls whose input still contains sensitive data

### Mode comparison

| | HTTP Proxy | `llm.chat` | `scrub`/`restore` | Hook |
|---|---|---|---|---|
| Agent awareness | None | Calls one tool | Calls two tools | Blocked call + reason |
| Coverage | All requests | When agent uses it | When agent uses it | All tool calls |
| Cloud config needed | Yes | Yes | No | No |
| Works with | Any client | MCP agents | MCP agents | Claude Code |

---

## Configuration

Copy one of the example configs as your starting point:

| Config | Mode | What it does | Eval leak rate (PII) |
|--------|------|-------------|---------------------|
| [`local-only.yaml`](examples/local-only.yaml) | MCP | Local model only, nothing leaves device | 0% |
| [`cloud-redact.yaml`](examples/cloud-redact.yaml) | Proxy | Redact PII/secrets, forward to OpenAI | 15.3% |
| [`cloud-redact-rephrase.yaml`](examples/cloud-redact-rephrase.yaml) | Proxy | Redact + rephrase implicit identity | 13.9% |
| [`max-privacy.yaml`](examples/max-privacy.yaml) | Proxy | A+B+C: local routing + redact + rephrase | **0.6%** |
| [`anthropic.yaml`](examples/anthropic.yaml) | Proxy | Redact for Anthropic Claude API | 15.3% |
| [`mcp-with-cloud.yaml`](examples/mcp-with-cloud.yaml) | MCP | `llm.chat` tool with cloud backend | 15.3% |
| [`strict.yaml`](examples/strict.yaml) | Proxy | Refuse on low-confidence detections | varies |

> **Read this before relying on the table.** `serve` and `mcp` only ever run
> Option B (redaction), optionally with validation. Options A (local routing),
> C (rephrase) and H (DP noise) are implemented for the evaluation harness only
> (`evals/runner.py`), so `local-only.yaml`, `cloud-redact-rephrase.yaml` and
> `max-privacy.yaml` behave like plain Option B under `serve`. The A / A+B /
> A+B+C rows were also produced by a harness that, until the fix in this
> revision, never routed anything locally (it compared `classify()`'s tuple to
> `"TRIVIAL"`), so those numbers need re-running. `strict.yaml` refuses only
> spans scored below 0.5, and with the default `ner_confidence_floor: 0.5`
> nothing below 0.5 survives detection. It refuses only if you lower the floor.

```bash
# Pick a config
cp examples/max-privacy.yaml llm_redactor.yaml

# Set your API key
export OPENAI_API_KEY=sk-...

# Start (proxy mode)
uv run llm-redactor serve --port 7789

# Or start (MCP mode)
uv run llm-redactor mcp
```

Precedence: environment variables > YAML file > defaults.

## Detection categories and tags

Every detected span has a **kind** (the specific detector tag) and a
**category** (the policy-level grouping). Use `policy.categories` in your
YAML config to enable or disable entire families.

### Category aliases (default)

The default policy is `categories: [all]`. These aliases expand as follows:

| Alias | Expands to |
|---|---|
| `all` | Every category below, plus `unknown` (custom patterns) |
| `pii` | identity, contact, government_id, financial, medical, temporal |
| `secret` | credential, cloud_credential, vendor_api_key, private_key |
| `org_identifier` | infrastructure |
| `customer_name` | identity |

```yaml
# Default: everything, including custom patterns:
policy:
  categories: [all]

# Every built-in category, but NOT custom patterns (add `unknown` for those):
policy:
  categories: [pii, secret, org_identifier, customer_name]
```

You can mix aliases and fine-grained categories freely:

```yaml
# Only secrets and contact info:
policy:
  categories: [secret, contact]

# Everything except temporal (`pii` includes temporal, so list its parts):
policy:
  categories: [identity, contact, government_id, financial, medical, secret, org_identifier]
```

### Full taxonomy

| Category | Kind (tag) | Source | Description |
|---|---|---|---|
| **identity** | `person` | NER | Person name |
| | `nationality` | NER | National, religious, or political group |
| | `employee_id` | regex | Employee identifier (e.g. `EMP-1234`) |
| | `dob` | regex | Date of birth (context-anchored) |
| | `org_name` | NER | Organisation / company name |
| **contact** | `email` | regex, NER | Email address |
| | `phone` | NER | Phone number (NER-detected) |
| | `phone_us` | regex | US phone number |
| | `phone_intl` | regex | International phone number |
| | `location` | NER | Physical location / address |
| | `address` | regex | Street address (number-first anchored) |
| | `url` | NER | URL |
| | `ip_address` | NER | IP address (NER-detected) |
| | `ip_v4` | regex | IPv4 address |
| | `ip_v6` | regex | IPv6 address |
| **government_id** | `ssn` | regex, NER | US Social Security Number |
| | `passport_number` | regex | Passport number (context-anchored) |
| | `ein` | regex | US Employer Identification Number (context-anchored) |
| | `us_itin` | NER | US Individual Taxpayer Identification Number |
| | `driver_license` | NER | US driver's licence number |
| **financial** | `credit_card` | regex, NER | Credit card number (Luhn-checked by the `rules` validation backend) |
| | `us_routing_number` | regex | US ABA routing number (checksum-validated) |
| | `us_bank_account` | regex | Bank account number (context-anchored) |
| | `crypto_btc` | regex | Bitcoin address: legacy, P2SH, bech32, taproot, testnet (checksum-validated) |
| | `crypto_eth` | regex | EVM address `0x` + 40 hex (Ethereum, Polygon, BSC, Arbitrum, Base, …) |
| | `crypto_ltc` / `crypto_doge` / `crypto_bch` | regex | Litecoin, Dogecoin, Bitcoin Cash (CashAddr) addresses (checksum-validated) |
| | `crypto_trx` / `crypto_xrp` / `crypto_xtz` | regex | Tron, XRP (classic + X-address), Tezos addresses (checksum-validated) |
| | `crypto_sol` | regex | Solana address (no checksum exists; shape + decoding heuristics) |
| | `crypto_xmr` / `crypto_ada` / `crypto_dot` | regex | Monero, Cardano (Shelley + Byron), Polkadot/Kusama/Substrate SS58 |
| | `crypto_cosmos` / `crypto_xlm` / `crypto_algo` | regex | Cosmos-SDK bech32 (cosmos, osmo, …), Stellar, Algorand (checksum-validated) |
| | `crypto_lightning` | regex | Lightning BOLT11 invoice / LNURL |
| | `crypto_address` | regex | Checksum-valid address of a chain not listed above |
| | `crypto_xpub` | regex | BIP32 extended public key (xpub/ypub/zpub/tpub/…): reveals every wallet address |
| | `crypto_public_key` | regex | secp256k1 hex public key (on-curve check), Tezos/Cardano/Cosmos/Nostr public keys, Ethereum validator (BLS) key |
| | `crypto_wallet` | NER | Crypto wallet address (Presidio, Bitcoin only) |
| | `iban` | regex, NER | IBAN bank account number (mod-97 validated) |
| **medical** | `medical_license` | NER | Medical license number |
| | `npi` | regex | US National Provider Identifier (checksum-validated) |
| | `dea_number` | regex | DEA registration number (checksum-validated) |
| | `uk_nhs` | NER | UK NHS number |
| **temporal** | `date_time` | NER | Date or time expression |
| **credential** | `password` | regex | Password in assignment |
| | `secret_assignment` | regex | Secret/token/credential in assignment |
| | `bearer_token` | regex | HTTP Bearer token |
| | `basic_auth` | regex | HTTP Basic auth header |
| | `jwt` | regex | JSON Web Token |
| | `generic_api_key` | regex | Generic `api_key=...` pattern |
| **cloud_credential** | `aws_access_key` | regex | AWS access key ID (`AKIA...`) |
| | `aws_secret_key` | regex | AWS secret access key |
| | `aws_session_token` | regex | AWS session token |
| | `gcp_service_account` | regex | GCP service account email |
| | `gcp_api_key` | regex | GCP API key (`AIza...`) |
| | `azure_storage_key` | regex | Azure storage account key |
| | `azure_connection_string` | regex | Azure connection string |
| **vendor_api_key** | `openai_api_key` | regex | OpenAI API key (`sk-...`) |
| | `anthropic_api_key` | regex | Anthropic API key (`sk-ant-...`) |
| | `github_token` | regex | GitHub token (`ghp_...`) |
| | `gitlab_token` | regex | GitLab token (`glpat-...`) |
| | `slack_token` | regex | Slack token (`xox...`) |
| | `slack_webhook` | regex | Slack incoming webhook URL |
| | `stripe_key` | regex | Stripe API key (`sk_live_...`) |
| | `twilio_key` | regex | Twilio API key (`SK...`) |
| | `sendgrid_key` | regex | SendGrid API key (`SG....`) |
| | `mailgun_key` | regex | Mailgun API key (`key-...`) |
| | `npm_token` | regex | npm access token |
| | `pypi_token` | regex | PyPI API token |
| | `heroku_api_key` | regex | Heroku API key (UUID format) |
| | `telegram_bot_token` | regex | Telegram bot token (`<bot_id>:<secret>`) |
| | `discord_token` | regex | Discord bot token (`MTA…`) |
| | `huggingface_token` | regex | Hugging Face token (`hf_…`) |
| | `digitalocean_token` | regex | DigitalOcean token (`dop_v1_…`) |
| | `shopify_token` | regex | Shopify access token (`shpat_…`) |
| | `postman_api_key` | regex | Postman API key (`PMAK-…`) |
| | `notion_token` | regex | Notion integration token (`secret_…`) |
| | `hashicorp_vault_token` | regex | HashiCorp Vault token (`hvs.…`) |
| | `grafana_token` | regex | Grafana service-account token (`glsa_…`) |
| | `netlify_token` | regex | Netlify personal access token (`nfp_…`) |
| | `planetscale_token` | regex | PlanetScale service token (`pscale_tkn_…`) |
| | `sourcegraph_token` | regex | Sourcegraph access token (`sgp_…`) |
| | `pulumi_token` | regex | Pulumi access token (`pul-…`) |
| | `new_relic_key` | regex | New Relic user API key (`NRAK-…`) |
| | `dynatrace_token` | regex | Dynatrace API token (`dt0c01.…`) |
| | `doppler_token` | regex | Doppler token (`dp.pt.…`) |
| | `sentry_token` | regex | Sentry org token (`sntrys_…`) |
| | `replicate_token` | regex | Replicate API token (`r8_…`) |
| **private_key** | `private_key_pem` | regex | PEM-armored private key (any label, incl. Cosmos `TENDERMINT`) |
| | `ssh_private_key` | regex | OpenSSH private key |
| | `pgp_private_key` | regex | PGP private key block |
| | `crypto_private_key` | regex | Wallet private key: WIF, BIP38, hex near a "private key"-style keyword, Solana/NEAR keypair (JSON array or base58, verified), XRP/Stellar seeds, Tezos/Cardano/Sui/Nostr secret keys |
| | `crypto_xprv` | regex | BIP32 extended private key (xprv/yprv/zprv/tprv/…) |
| | `crypto_mnemonic` | regex | BIP-39 seed phrase (12–24 English words; also Algorand 25-word) |
| **infrastructure** | `connection_string` | regex | Database / message broker URI |
| | `hostname_internal` | regex | Internal hostname (`.internal`, `.corp`, etc.) |
| | `mac_address` | regex | MAC address |

### Blockchain keys, addresses and seed phrases

`detect/wallets.py` decodes each candidate token and lets the bytes pick the
kind, so the same base58 string is told apart as a Bitcoin address, an XRP
seed or a Solana key. Most formats carry their own checksum (Base58Check,
bech32/bech32m, CashAddr, SS58, Stellar CRC-16, Algorand), which keeps false
positives near zero. Limits worth knowing:

- **Mistyped addresses are not redacted.** A checksum failure means "not an
  address". A one-character typo is still one search away from the real value.
- **A bare `0x` + 64-hex value is not redacted** unless a keyword like
  `private key`, `PRIVATE_KEY`, `--private-key`, `secret`, `seed`,
  `accounts: [` or `new Wallet(` appears within 200 characters. Without
  context it is indistinguishable from a tx hash or a SHA-256 digest.
- **Seed phrases** must be at least 12 consecutive BIP-39 English words
  with at least 10 distinct words in some 12-word window. This keeps out
  repetitive code like `(False,), (True,)` tables. The public zero-entropy
  test vector (`abandon` ×11 + `about`) is deliberately not redacted. Other
  languages' wordlists are not supported.
- **Solana addresses** have no checksum: 32–44 char base58 that decodes to
  exactly 32 bytes. camelCase identifiers and fragments of base64 blobs are
  excluded. A short allowlist of public program IDs, mints and EVM
  infrastructure contracts (zero address, WETH, USDC, Multicall3, …) passes
  through unredacted.

Custom patterns added via `policy.extend_patterns_file` are loaded by
`serve`, `mcp` and `detect`. They get the category `unknown`, which `all`
includes. A narrower policy must list `unknown` explicitly, or you can add
the kind to `CATEGORY_MAP` in `detect/types.py`.

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

# Named presets (reproducible bundles; see evals/run_eval.py)
uv run python -m evals.run_eval --list-presets
uv run python -m evals.run_eval --preset readme-b-ner
uv run python -m evals.run_eval --preset quick-wl1
uv run python -m evals.run_eval --preset implicit-bc
```

### Measurable bundles (implicit / semantic PII)

Workload **wl3_implicit** is where redaction alone plateaus. Compare options on that
slice explicitly, for example `--preset implicit-bc` (B+C + NER) versus `--preset
readme-b-ner` (B + NER across all workloads). Latency and utility live in the eval
outputs under `evals/results_*`.

## Operator hardening (proxy + MCP)

- **Structured logs**: JSON lines on the `llm_redactor` logger (`pipeline_redact_prepared`,
  `proxy_tools_bypass`, `mcp_scrub`, …) contain counts and flags only — never raw prompts.
- **Tool calls**: `transport.tools_policy: refuse` returns HTTP 422 instead of silently
  forwarding unredacted tool payloads; `bypass` adds `X-LLM-Redactor-Mode: bypass-tools`.
  Environment override: `LLM_REDACTOR_TOOLS_POLICY`.
- **LLM validation**: set `pipeline.llm_validation.enabled: true` (or
  `LLM_REDACTOR_LLM_VALIDATION=true`) so the HTTP proxy and `llm.chat` / `redact.scrub` use
  Ollama to filter NER false positives.
- **Placeholder binding**: `pipeline.placeholder_request_tag: true` (or
  `LLM_REDACTOR_PLACEHOLDER_REQUEST_TAG=1`) embeds a per-request random suffix in each
  placeholder (`⟨EMAIL_1·…⟩`), shrinking accidental model echo collisions.
- **MCP session cap**: `transport.mcp_session_cap` / `LLM_REDACTOR_MCP_SESSION_CAP` bounds
  in-memory `redact.scrub` sessions; oldest entries are evicted under pressure.
- **Concurrency and scaling**: `serve` runs multiple uvicorn workers so a single slow
  request can never block the accept loop (the failure mode that surfaces as
  `502 Upstream unreachable` under load). `--workers N` sets the process count — `0`,
  the default, auto-scales to the CPU count capped at 8; `--limit-concurrency M`
  (default 64) is a per-worker load-shedding valve that returns HTTP 503 once M requests
  are in flight instead of letting the worker fall over. spaCy NER runs in a worker
  thread so detection never stalls the event loop, and the proxy shares one bounded HTTP
  connection pool per worker rather than opening a fresh client per request. Each worker
  loads its own detector (spaCy, plus the ONNX image model when `image_redaction` is
  enabled), so peak memory scales with worker count — size `--workers` against available
  RAM when running several instances on one host.

Example config: [`examples/operator-hardening.yaml`](examples/operator-hardening.yaml).

## Running without a local LLM

Set `pipeline.llm_validation.backend: "rules"` to replace the Ollama validator
with deterministic per-kind checks — Luhn for credit cards, the ISO 13616
mod-97 checksum for IBANs, Social Security Administration allocation rules for
SSNs, and shape/length floors for emails, phones, JWTs, and API-key-shaped
secrets. Rules mode needs no local model (no Ollama install, no VRAM, no
warm-up latency) and, unlike the model backend, it also validates
regex-sourced spans, so a regex credit-card match with a failing Luhn checksum
is now dropped instead of always kept. Fuzzy NER kinds (person, location,
nationality, date_time) intentionally have no rules and pass through, trading
a little of the model's name-level filtering for determinism and speed;
`tools/bench_rules_validator.py` benchmarks all three arms (none / rules /
model) over a labeled corpus if you want the numbers for your own machine.

## Multilingual / locale NER

Set `local_model.ner_model` in YAML (for example `xx_ent_wiki_sm`) and ensure the spaCy
weights are installed in the environment. Regex patterns remain English-centric unless
you extend them via `policy.extend_patterns_file`.

## Known limitations

- **Non-English names**: The NER model (`en_core_web_sm`) is English-only.
  Names with diacritics (e.g. Maria Garcia-Lopez) may not be detected.
  Use a multilingual spaCy model or add custom patterns for your locale.
- **NER false positives**: Presidio may flag drug names as persons,
  abbreviations as organizations, or common words as locations. The
  orchestrator suppresses known false positives but can't catch all of them.
- **Implicit identity**: Phrases like "the CFO's wife" identify individuals
  without containing PII tokens. Only Option C (rephrase) addresses this,
  and even then semantic leak rates remain high (95%+).

## Tests

```bash
uv run pytest -v
make format-check
make lint
```

Install the repository's versioned pre-push hook once per clone to run the Ruff
format and lint checks automatically before every push:

```bash
make install-hooks
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
  eprint={2604.12064},
  archivePrefix={arXiv},
  primaryClass={cs.CR},
  url={https://arxiv.org/abs/2604.12064}
}
```
