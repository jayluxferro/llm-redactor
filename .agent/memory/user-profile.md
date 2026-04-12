---
name: user profile
description: How to work with Jay (shared voice guide across sibling projects)
type: user
---

# Working with Jay

## Who they are

- **Jay Lux Ferro** (`jay@sperixlabs.org`, `@sperixlabs`, github
  `jayluxferro`).
- Personal cybersecurity research blog at `sperixlabs.org`.
- Focus areas: mobile reverse engineering, telemetry analysis,
  LLM tooling, privacy-preserving systems, local-first AI.
- Sibling projects in `~/dev/ml/mcp/`: `resilient-write`,
  `local-splitter`, `llm-redactor` (this one).
- Runs macOS / Apple Silicon, bun, Python 3.12+, Hugo.

## How they work

- **Direct and terse.** No preamble, no filler, no "I'm happy to
  help" energy.
- **Wants proof, not promises.** Screenshots, greps, hashes, file
  listings are appreciated.
- **Names trade-offs explicitly.** One sentence why, then move on.
- **Tracks tasks.** Uses the agent's task list heavily.
- **Asks before risky actions.** Especially destructive git,
  deletes, force-pushes.
- **Silence = acceptance.**

## Established preferences

- **Code style**: no emojis unless asked, short functions, no
  speculative abstractions. Comments only where non-obvious.
- **Documentation style**: structured markdown, tables for
  comparisons, code fences, explicit "what this is NOT" sections.
- **Scripts**: POSIX `sh`, `set -eu`, colour-coded status markers.
- **Python**: 3.12+, type hints, `pyproject.toml`, stdlib when
  reasonable.
- **Deploy / publish**: one-command flows with `--dry-run` and
  `--no-push` flags.

## Things to avoid

- Repetition.
- End-of-response summaries.
- Over-explaining technical basics.
- Decorative language.
- Unsolicited features.

## What to do on a new session

1. Read `AGENT.md`.
2. Read the five `.agent/memory/*.md` files.
3. Check git status; figure out any dirtiness before touching it.
4. Open by saying what you read and what you plan to do, in
   under 10 lines. Wait for confirmation.

## One-liner mental model

Build the smallest useful thing first, ship it, verify on the
wire, ask what's next.
