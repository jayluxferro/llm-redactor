#!/usr/bin/env bash
# Claude Code PreToolUse hook: BLOCK a tool call whose input contains
# sensitive content.
#
# Reads the hook payload from stdin (JSON with tool_name and tool_input),
# runs a quick regex scan for common PII/secret patterns, and exits 2 with
# the findings on stderr if anything matches.  Exit 2 blocks the call and
# shows stderr to Claude; to warn without blocking, change `exit 2` to
# `exit 0` (stderr is then only visible in the transcript).
#
# Install in ~/.claude/settings.json:
#   {
#     "hooks": {
#       "PreToolUse": [
#         {
#           "matcher": "*",
#           "hooks": [
#             {
#               "type": "command",
#               "command": "/path/to/llm-redactor/hooks/detect-sensitive.sh"
#             }
#           ]
#         }
#       ]
#     }
#   }
#
# This is a deliberately small pattern set (no Python package needed).  For
# the full detector, use `llm-redactor detect` or the MCP redact.* tools.

set -euo pipefail

# Read tool input from stdin.
INPUT=$(cat)

# Every string anywhere inside tool_input, one per line (nested dicts and
# lists included; the old flattening only saw top-level values).
TEXT=$(printf '%s' "$INPUT" | python3 -c "
import json, sys

def walk(value):
    if isinstance(value, str):
        print(value)
    elif isinstance(value, dict):
        for v in value.values():
            walk(v)
    elif isinstance(value, list):
        for v in value:
            walk(v)

try:
    walk(json.load(sys.stdin).get('tool_input', {}))
except Exception:
    pass
" 2>/dev/null)

if [ -z "$TEXT" ]; then
    exit 0
fi

# Quick regex scan.  Here-strings, not `echo | grep -q`: under pipefail a
# grep that exits on the first match SIGPIPEs the echo on large inputs, and
# the pipeline then reports failure, i.e. the match is silently dropped.
# `-e` before each pattern: a pattern starting with "-" is otherwise parsed
# as an option (the PEM check never fired because of exactly that).
FINDINGS=""

if grep -qiE -e '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' <<<"$TEXT"; then
    FINDINGS="${FINDINGS}  - Email address detected\n"
fi

if grep -qiE -e '(api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd)\s*[=:]\s*\S{8,}' <<<"$TEXT"; then
    FINDINGS="${FINDINGS}  - API key or secret in assignment\n"
fi

if grep -qE -e 'AKIA[0-9A-Z]{16}' <<<"$TEXT"; then
    FINDINGS="${FINDINGS}  - AWS access key detected\n"
fi

if grep -qiE -e 'bearer\s+[a-z0-9._-]{20,}' <<<"$TEXT"; then
    FINDINGS="${FINDINGS}  - Bearer token detected\n"
fi

if grep -qE -e '-----BEGIN.*PRIVATE KEY-----' <<<"$TEXT"; then
    FINDINGS="${FINDINGS}  - Private key detected\n"
fi

if grep -qE -e '\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b' <<<"$TEXT"; then
    FINDINGS="${FINDINGS}  - SSN pattern detected\n"
fi

if [ -n "$FINDINGS" ]; then
    # stderr: on exit 2 Claude Code feeds stderr (not stdout) back to Claude.
    {
        echo "⚠ llm-redactor: Sensitive content detected in tool input:"
        printf '%b' "$FINDINGS"
        echo "Consider using redact.scrub or the llm.chat tool instead."
    } >&2
    exit 2
fi

exit 0
