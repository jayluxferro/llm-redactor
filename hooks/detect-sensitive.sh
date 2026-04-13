#!/usr/bin/env bash
# Claude Code pre-tool hook: warn if tool input contains sensitive content.
#
# Reads the tool input from stdin (JSON with tool_name and tool_input),
# runs a quick regex scan for common PII/secret patterns, and exits
# non-zero with a warning if anything is found.
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

set -euo pipefail

# Read tool input from stdin.
INPUT=$(cat)

# Extract the text content to scan (tool_input as string).
TEXT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    # Flatten all string values from tool_input.
    ti = d.get('tool_input', {})
    if isinstance(ti, str):
        print(ti)
    elif isinstance(ti, dict):
        for v in ti.values():
            if isinstance(v, str):
                print(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        for sv in item.values():
                            if isinstance(sv, str):
                                print(sv)
except:
    pass
" 2>/dev/null)

if [ -z "$TEXT" ]; then
    exit 0
fi

# Quick regex scan for common sensitive patterns.
FINDINGS=""

# Email addresses
if echo "$TEXT" | grep -qiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'; then
    FINDINGS="${FINDINGS}  - Email address detected\n"
fi

# API keys / secrets in assignments
if echo "$TEXT" | grep -qiE '(api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd)\s*[=:]\s*\S{8,}'; then
    FINDINGS="${FINDINGS}  - API key or secret in assignment\n"
fi

# AWS access keys
if echo "$TEXT" | grep -qE 'AKIA[0-9A-Z]{16}'; then
    FINDINGS="${FINDINGS}  - AWS access key detected\n"
fi

# Bearer tokens
if echo "$TEXT" | grep -qiE 'bearer\s+[a-z0-9._-]{20,}'; then
    FINDINGS="${FINDINGS}  - Bearer token detected\n"
fi

# PEM private keys
if echo "$TEXT" | grep -qE '-----BEGIN.*PRIVATE KEY-----'; then
    FINDINGS="${FINDINGS}  - Private key detected\n"
fi

# SSN pattern
if echo "$TEXT" | grep -qE '\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'; then
    FINDINGS="${FINDINGS}  - SSN pattern detected\n"
fi

if [ -n "$FINDINGS" ]; then
    echo "⚠ llm-redactor: Sensitive content detected in tool input:"
    echo -e "$FINDINGS"
    echo "Consider using redact.scrub or the llm.chat tool instead."
    # Exit 2 = block with message (Claude Code hook protocol).
    exit 2
fi

exit 0
