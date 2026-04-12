---
name: origin story
description: Where llm-redactor came from and what the motivating question is
type: project
---

# Origin

## The conversation that produced this project

In April 2026, while finishing a technical report on LLM CLI
telemetry, Jay (user, `@sperixlabs`) asked a pair of research
questions:

1. *"Using local models to reduce token usage — what's possible?"*
2. *"Hiding LLM data reading format or tokenization so it doesn't
   exist in plain text when sending data to llms — what's possible?"*

The telemetry report had just documented, in painful detail, how
every major coding CLI sends user prompts, session IDs, email
addresses, organisation UUIDs, device IDs, tool names, permission
modes, and cost telemetry to the cloud vendor, often to a bundled
third-party observability vendor as well. The question was
immediate and practical: *what can a user do about it?*

I sketched eight options (A through H) spanning the full spectrum
from "never leave the device" to "homomorphic encryption". Jay said
*"let's work on all of them"* and asked me to spin it out into a
standalone project.

This repo is the result. The sibling
`/Users/jay/dev/ml/mcp/local-splitter` handles question~(1) —
token reduction. We kept them separate on purpose (see
`decisions.md`).

## What this project is for

An outbound LLM request from a coding agent often contains content
the user would prefer not to share with the cloud vendor: real
names, customer identifiers, internal project codenames, API keys,
proprietary code, database schemas. Once the request is logged by
the vendor, the user has no recourse.

`llm-redactor` is an **enforcement point in the request pipeline**.
Agents make their requests as normal; the redactor transforms them
before they leave the device and restores placeholders on the
response path. The user never sees the transformation, and the
vendor never sees the raw content.

There are eight techniques for doing this enforcement. Each has
different privacy properties, different utility costs, different
deployment requirements, and different practicality today. The
research question is: **given a threat model and a workload, which
technique (or combination) is best?**

## Why it's a research project and not just a utility

Each of the eight options has been studied in isolation, often in
different threat models, on different benchmarks. To our knowledge,
no prior work has:

- Measured all eight on a common ground-truth-labelled leak
  benchmark.
- Quantified the residual leak rate of practical techniques
  (redaction, rephrasing) against a specific threat model.
- Published a decision rule for which technique to pick given a
  workload and a privacy budget.
- Released an open-source reference implementation that speaks
  MCP and OpenAI-compatible APIs.

The paper's contribution is the measurement and the decision
rule, not the techniques themselves.

## Why it lives in `~/dev/ml/mcp/`

Jay has three MCP-adjacent research projects in this directory:

- `resilient-write` — durable write surface (filter-block recovery)
- `local-splitter` — token reduction via local triage
- `llm-redactor` — this project (privacy)

All three are outbound-LLM-request-pipeline projects. They compose
well — redactor runs before splitter's cloud call, splitter's cache
lookup runs before redactor's detection, resilient-write handles
any disk-backed state either project produces. They may eventually
share a common library. They are explicitly separate projects now
because each has a distinct research question, threat model, and
target audience.

## Constraints from the user

- Must work with **any OpenAI-compatible API** and with Ollama.
- Must not depend on vendor SDKs.
- The paper (LaTeX, arXiv-ready) is a deliverable.
- The novelty must be real — "original research, not a rehash".
- Test which options actually work before claiming anything.

## Stakes

Jay is a security / privacy researcher. This project's results
inform how he — and other practitioners — build LLM-integrated
tools when the stakes include user PII, proprietary code, or
sensitive infrastructure data. Concrete real-world examples:

- A developer using Claude Code on a codebase that contains a
  customer's database schema.
- A security researcher using Copilot CLI to triage logs that
  contain user session tokens.
- An engineer using Cursor on a file with hard-coded API keys in
  environment variable defaults.

All three scenarios are routine. Today the only defence is "don't
type that into the agent" — a rule users forget. `llm-redactor` is
the defence that enforces itself.
