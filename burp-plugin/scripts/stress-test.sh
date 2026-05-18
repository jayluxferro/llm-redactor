#!/usr/bin/env bash
# Stress-test LLM Redactor via Burp proxy (127.0.0.1:8080).
# Prereqs: Burp running with LLM Redactor loaded+enabled; mock server from stress_mock_llm.py
set -euo pipefail

PROXY="${BURP_PROXY:-http://127.0.0.1:8080}"
MOCK="${MOCK_URL:-http://127.0.0.1:8765}"
CURL=(curl -sS -x "$PROXY" --proxy-insecure -k)

payload='{"model":"gpt-4o","stream":false,"messages":[{"role":"user","content":"Email jane@example.com SSN 123-45-6789 token sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"}]}'
payload_stream='{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"Email jane@example.com SSN 123-45-6789"}]}'

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }

echo "=== JSON non-stream (HTTP/1.1) ==="
resp="$("${CURL[@]}" -H 'Content-Type: application/json' -d "$payload" "$MOCK/v1/chat/completions")"
echo "$resp" | python3 -c 'import json,sys; json.load(sys.stdin)' || fail "non-stream invalid JSON: $resp"
echo "$resp" | grep -q 'jane@example.com' || fail "PII not restored in response"
ok "non-stream JSON valid and restored email"

echo "=== JSON with gzip Accept-Encoding ==="
resp="$("${CURL[@]}" -H 'Content-Type: application/json' -H 'Accept-Encoding: gzip' -d "$payload" "$MOCK/v1/chat/completions")"
echo "$resp" | python3 -c 'import json,sys; json.load(sys.stdin)' || fail "gzip response invalid JSON"
ok "gzip response decodes"

echo "=== SSE stream ==="
resp="$("${CURL[@]}" -N -H 'Content-Type: application/json' -d "$payload_stream" "$MOCK/v1/chat/completions")"
echo "$resp" | grep -q 'data:' || fail "no SSE data lines"
echo "$resp" | grep -q 'jane@example.com' || fail "SSE did not restore email"
ok "SSE stream restored PII"

echo "=== HTTP/2 (if curl supports --http2) ==="
if curl --version | grep -q http2; then
  resp="$(curl -sS --http2 -x "$PROXY" --proxy-insecure -k \
    -H 'Content-Type: application/json' -d "$payload" "$MOCK/v1/chat/completions")"
  echo "$resp" | python3 -c 'import json,sys; json.load(sys.stdin)' || fail "http2 invalid JSON"
  ok "HTTP/2 JSON valid"
else
  echo "SKIP: curl without http2"
fi

echo "All stress checks passed."
