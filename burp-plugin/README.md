# Burp LLM Redactor

This Kotlin Burp extension applies Option B redaction to outbound HTTP(S)
request query/body content and client-to-server WebSocket text frames. It
enables every sensitive-data category by default.

## Build and install

```bash
gradle test shadowJar
```

Load `build/libs/burp-llm-redactor.jar` in **Burp Suite → Extensions → Add**.
Start the local detector service before sending traffic:

```bash
uv run llm-redactor serve --port 7789 --config ../examples/burp-plugin.yaml
```

The plugin calls `http://127.0.0.1:7789/v1/redactor/detect-batch`. The service
uses its configured regex, NER, and optional local-LLM validation. If unavailable,
the plugin continues with its local regex fallback.

## Traffic behavior

- Redacts query values and UTF-8 text in JSON, XML, form, multipart-text, and
  generic protobuf length-delimited fields.
- Re-encodes gzip, deflate, and zstd bodies after redaction.
- Leaves responses, SSE events, server-to-client WebSocket frames, headers,
  signed requests, Brotli, unreadable/binary content, and JSON encrypted/
  ciphertext values unchanged. Opaque ciphertext must not be modified because
  doing so invalidates its authentication tag.
- Shows a live, bounded activity table with time, host, protocol, outcome,
  detection count, and pass-through reason. Records are in memory only and
  contain no body text, matches, placeholders, or credentials.
