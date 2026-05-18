#!/usr/bin/env python3
"""Mock LLM API for stress-testing the Burp LLM Redactor extension.

Run this server, point Burp at it (add 127.0.0.1:8765 to target hosts), then:

  export OPENAI_API_KEY=sk-test
  curl -x http://127.0.0.1:8080 --proxy-insecure -k \\
    http://127.0.0.1:8765/v1/chat/completions \\
    -H 'Content-Type: application/json' \\
    -d '{"model":"gpt-4o","stream":false,"messages":[{"role":"user","content":"Email jane@example.com SSN 123-45-6789"}]}'

  curl ... -d '{"model":"gpt-4o","stream":true,"messages":[...]}'  # SSE

Requires: no external network; exercises JSON + SSE + gzip when Accept-Encoding is sent.
"""

from __future__ import annotations

import gzip
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    n = int(handler.headers.get("Content-Length", "0") or 0)
    return handler.rfile.read(n) if n else b""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] not in (
            "/v1/chat/completions",
            "/v1/messages",
        ):
            self.send_error(404)
            return

        body = json.loads(_read_body(self) or b"{}")
        user = ""
        for m in body.get("messages", []):
            if isinstance(m.get("content"), str):
                user += m["content"]

        if body.get("stream"):
            self._sse_reply(user)
        else:
            self._json_reply(user)

    def _json_reply(self, user: str) -> None:
        payload = {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Echo: {user[:200]}",
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        raw = json.dumps(payload).encode()
        self._send_maybe_gzip(raw, "application/json")

    def _sse_reply(self, user: str) -> None:
        chunks = [f"Echo: ", user[:80], " [done]"]
        lines: list[bytes] = []
        for piece in chunks:
            ev = {
                "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}]
            }
            lines.append(f"data: {json.dumps(ev)}\n\n".encode())
        lines.append(b"data: [DONE]\n\n")
        raw = b"".join(lines)
        self._send_maybe_gzip(raw, "text/event-stream")

    def _send_maybe_gzip(self, raw: bytes, content_type: str) -> None:
        ae = (self.headers.get("Accept-Encoding") or "").lower()
        if "gzip" in ae:
            body = gzip.compress(raw)
            enc = "gzip"
        else:
            body = raw
            enc = None

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if enc:
            self.send_header("Content-Encoding", enc)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock LLM on http://127.0.0.1:{port} (chat/completions + messages)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
