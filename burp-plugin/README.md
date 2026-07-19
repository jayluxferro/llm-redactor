# Burp LLM Redactor

This Kotlin Burp extension applies Option B redaction to outbound HTTP(S)
request query/body content. It enables every sensitive-data category by default.
Client-to-server WebSocket text frames use the extension's local regex detector only;
they never wait for the loopback detector service. Binary and server-to-client frames
pass through unchanged.

When Burp locally blocks an endpoint with its canonical `400 {"detail":"Bad Request"}`
response, the extension returns a local `204 No Content` acknowledgement instead. This
works for any matching blocked endpoint, does **not** allow it to leave Burp, and does
not retain its payload. Stateful Codex response streams are excluded because they need
their real streaming response rather than a synthetic acknowledgement.

## Build and install

```bash
gradle test shadowJar
```

Load `build/libs/burp-llm-redactor.jar` in **Burp Suite → Extensions → Add**.
Start the local detector service before sending traffic:

```bash
uv run llm-redactor serve --port 7789 --config ../examples/burp-plugin.yaml
```

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
original image safely passes through unchanged.

The plugin calls `http://127.0.0.1:7789/v1/redactor/detect-batch`. The service
uses its configured regex, NER, and optional local-LLM validation. If unavailable,
the plugin continues with its local regex fallback.

## Traffic behavior

- Redacts query values and UTF-8 text in JSON, XML, form, multipart-text, and
  generic protobuf length-delimited fields.
- Redacts raw PNG/JPEG bodies and base64 `data:image/...` attachments in textual
  request bodies through the optional local ONNX endpoint; image responses and
  non-image multipart file parts are unchanged.
- Re-encodes gzip, deflate, and zstd bodies after redaction.
- Handles `POST /backend-api/codex/responses` as protocol JSON: only explicit user-text
  fields (`content`, `input`, `instructions`, `message`, `prompt`, and `text`) are
  redacted, while protocol IDs and metadata are preserved.
- Leaves responses, SSE events, all WebSocket frames, headers,
  signed requests, Brotli, unreadable/binary content, and JSON encrypted/
  ciphertext values unchanged. Opaque ciphertext must not be modified because
  doing so invalidates its authentication tag. A request that contains an encrypted
  protocol envelope passes through unchanged because its authentication can cover
  surrounding fields.
- Converts Burp's canonical local block response (`400 {"detail":"Bad Request"}`) into a
  local `204` acknowledgement. This keeps clients operational while Burp's blocking
  policy remains in force; it does not mask upstream errors with a different body or
  acknowledge `POST /backend-api/codex/responses`.
- Shows a live, bounded activity table with time, host, protocol, outcome,
  detection count, and pass-through reason. Records are in memory only and
  contain no body text, matches, placeholders, or credentials.
