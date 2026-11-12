# Burp LLM Redactor

This Kotlin Burp extension redacts sensitive data in outbound HTTP(S) requests
(query string and body) and in client-to-server WebSocket text frames, replacing
each finding with a typed placeholder such as `⟨EMAIL_1⟩`. It uses the same
detection as the proxy's Option B: the local `llm-redactor serve` service
(regex, wallet checksums, NER, optional local-LLM validation), with every
category enabled. Unlike the proxy, it does not restore placeholders in
responses: responses pass through untouched.

When the service is not running, HTTP requests are redacted with the
extension's built-in detector instead, a Kotlin port of the service's regex and
wallet detectors (no NER). WebSocket frames always use the built-in detector,
because even a loopback round trip can stall a streaming connection.

## Build and install

Needs JDK 17 or newer; the Gradle wrapper fetches everything else.

```bash
./gradlew test shadowJar
```

Load `build/libs/burp-llm-redactor.jar` in **Burp Suite → Extensions → Add**.
Start the local detector service before sending traffic:

```bash
uv run llm-redactor serve --port 7789 --config ../examples/burp-plugin.yaml
```

The extension calls `http://127.0.0.1:7789/v1/redactor/detect-batch` (loopback
only, bypassing any proxy Burp or the JVM is configured with), in batches of at
most 500 texts.

### Optional local image redaction

PNG and JPEG request bodies can be irreversibly redacted with Screenpipe's local
ONNX image detector. The model is not bundled and is licensed **CC BY-NC 4.0**;
enable this only for permitted non-commercial use. Install the optional runtime,
download the model yourself, and set an absolute model path plus explicit license
acknowledgement in the configuration:

```bash
uv sync --extra image
git lfs install
git clone --depth 1 https://huggingface.co/screenpipe/pii-image-redactor ../models/screenpipe
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

When configured, the extension posts the image only to its loopback
`/v1/redactor/redact-image` endpoint. The Python service runs ONNX Runtime
(CoreML/CUDA/DirectML when available, otherwise CPU) and paints opaque black
rectangles over every detection. If the local runtime/model is unavailable, the
original image passes through unchanged.

## Traffic behavior

A request is rewritten only when something was detected; otherwise it goes out
byte for byte, compression included. One placeholder namespace covers a whole
request (query and every body field) or a whole WebSocket connection, so the
same value always gets the same placeholder and different values never share one.

- **JSON** is redacted value by value: each string is detected with its member
  name as context (so `"password": "..."` is caught), and numbers, keys and
  structure are never altered. A string holding JSON (tool-call `arguments`) is
  redacted inside and re-serialized. JSON Lines bodies are handled line by line.
- **Forms and query strings**: each value is percent-decoded, detected with its
  key as context, and re-encoded only if it changed. Malformed escapes are kept
  as they are.
- **Multipart**: each part on its own. Text fields are redacted, PNG/JPEG parts
  go to the image redactor, other file parts are left alone.
- **Protobuf** (`application/x-protobuf`, `application/proto`, ...) is walked
  schema-blind: nested messages are recursed into, strings redacted, and every
  enclosing length recomputed. **gRPC, gRPC-Web and Connect** framing is parsed
  and rewritten with correct lengths; compressed messages pass through.
- Other UTF-8 text (XML, plain text, ...) is redacted as text. Base64 `data:`
  PNG/JPEG attachments go to the image redactor; all base64 data URLs are kept
  away from text detection.
- Gzip, deflate and zstd bodies are decoded, redacted and re-encoded. Brotli
  and stacked encodings pass through.
- **OpenAI Responses API requests** (`POST /v1/responses`, Codex's
  `POST /backend-api/codex/responses`, Azure's `/openai/...responses`, over
  HTTP or WebSocket) are protocol JSON: only user and tool text is redacted
  (`content`, `input`, `instructions`, `message`, `prompt`, `text`, plus tool
  `output`, `arguments` and `command`). IDs, metadata and encrypted reasoning
  items are never touched, which is why these requests are redacted even when
  they replay `encrypted_content`.
- **Ciphertext**: values of JSON members named like `encrypted_content`,
  `ciphertext` or `sealed_payload`, and Fernet tokens, are never modified,
  since one changed byte breaks their authentication. Any other request that
  carries such an envelope passes through whole, because its authentication can
  cover the surrounding fields.
- **Signed requests** (AWS SigV4 `Authorization` or `X-Amz-Content-Sha256`,
  presigned `X-Amz-Signature` / `X-Goog-Signature` URLs) pass through: their
  signature covers the bytes that would change.
- Responses, SSE events, server-to-client WebSocket frames, binary WebSocket
  frames, headers, and traffic to loopback hosts pass through unchanged.
- Burp's canonical local block response, exactly `400 {"detail":"Bad Request"}`,
  becomes a local `204` acknowledgement, so clients keep working while Burp's
  blocking policy stays in force. Nothing else is rewritten: an upstream `403`
  or any other error body reaches the client as is, and Responses API requests
  are never acknowledged because they need their real event stream.
- A live, bounded activity table shows time, host, protocol, outcome, detection
  count, and pass-through reason for every redaction and pass-through. Records
  are in memory only and contain no body text, matches, placeholders,
  credentials, or query strings.

## The built-in detector

`RegexDetector.kt` and `WalletDetector.kt` port `src/llm_redactor/detect/regex.py`
and `wallets.py`: the same patterns in the same order, the same checksums
(IBAN, NPI, DEA, ABA routing; Base58Check, bech32/bech32m, CashAddr, SS58,
Stellar, Algorand, secp256k1 and Ed25519 key checks), the same seed-phrase
rules over the same 13 wordlists (copied into the jar from the Python package at
build time), and the same overlap merge. Not ported: NER and custom patterns
from the service's config.

To keep the two from drifting, `tests/test_burp_parity.py` pins the Python
output for a corpus of samples into `src/test/resources/.../parity.json`, and
`ParityTest` requires this port to reproduce it exactly. After changing a Python
detector:

```bash
LLM_REDACTOR_UPDATE_BURP_PARITY=1 uv run pytest tests/test_burp_parity.py   # from the repo root
./gradlew test                                                                # then port until this passes
```
