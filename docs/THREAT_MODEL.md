# Threat model

The threat model is the most important doc in this repo. Every
privacy claim the code or paper makes is relative to this model. If
the claim outruns the model, it's wrong.

## Actors

1. **User**. The developer sitting in front of the coding agent.
   Trusted. Their local machine is inside the trust boundary.
2. **Local coding agent**. Trusted, same as the user. Runs on the
   user's laptop.
3. **`llm-redactor`** itself. Trusted. It is the enforcement point.
4. **Local model**. Trusted for the tasks it's used for (detection,
   classification, rephrasing).
5. **Cloud LLM vendor** (OpenAI, Anthropic, etc.). Untrusted for the
   purposes of the privacy analysis. We assume they are *curious*
   but not actively malicious — they log requests, may retain them
   for training or debugging, may be subject to subpoena, but do
   not selectively target our user.
6. **Cloud infrastructure provider** (AWS, GCP, Azure hosting the
   cloud LLM). Untrusted for the same reasons.
7. **Passive network observer**. Untrusted. Defeated by TLS, which
   is table stakes and out of scope for this project.
8. **Supply-chain adversary** who compromised a downstream
   dependency (Python package, the local model's weights). Out of
   scope; this is a broader problem.

## Assets we try to protect

1. **User-identifying information**: names, emails, phone numbers,
   addresses, employee IDs, device IDs, hostnames.
2. **Organisation-identifying information**: company names, team
   names, internal project codenames, customer names.
3. **Secrets**: API keys, bearer tokens, OAuth tokens, PEM keys,
   session IDs, passwords, SSH keys.
4. **Proprietary code / prose**: lines of code, design docs, or
   business prose that the user doesn't want logged at the vendor.
5. **Data about the user's behaviour**: what they're asking,
   when, about what projects.

## Assets we explicitly do NOT try to protect

1. **Request timing**. The vendor will know when the user asked
   something, and how often. This is not in scope.
2. **Request volume**. The vendor will know how many requests per
   day. Not in scope.
3. **Model selection**. The vendor knows which model you asked for.
4. **Existence of the request**. The vendor knows a request was
   made. We are not hiding that fact; we are only hiding the
   content.
5. **Metadata in the TLS handshake**. SNI, user agent, client IP.
   Out of scope.
6. **Out-of-band context**. If a vendor already knows the user is
   working at a specific company via billing information, redacting
   the company name in the prompt doesn't hide that fact from them.

## Attack scenarios

### Scenario 1 — vendor log exfil

A cloud LLM vendor logs prompts and completions for debugging,
training, or compliance. An insider or a subpoena gains access to
those logs.

**What we protect**: the redactor/rephraser removes PII / secrets /
organisation identifiers before the request leaves. Logs contain
only the redacted form.

**Residual risk**: anything the detector missed, anything phrased
implicitly (e.g. "the CFO's wife"), and any behavioural patterns.

**Measured by**: the paper's "residual leak rate per option"
experiment on a ground-truth-labelled dataset.

### Scenario 2 — model training contamination

The vendor uses prompts for model training. A future model then
emits verbatim fragments of prior prompts in response to unrelated
queries.

**What we protect**: anything that was redacted in the original
prompt is not in the training data and cannot be regurgitated.

**Residual risk**: unredacted phrasing could still appear in
training.

### Scenario 3 — third-party observability sink

The coding agent ships a bundled telemetry SDK (see the real case
from the LLM CLI telemetry report — Claude Code shipping a Datadog
SDK). The SDK sends tool-call metadata to an observability vendor
who is **not** the LLM vendor.

**What we protect**: if the agent's tool calls flow through our
proxy, we redact before the SDK sees them. If the SDK
**bypasses** our proxy and phones home directly, we do not protect
against it.

**This is a key limitation**. Document it clearly in every README.

### Scenario 4 — response-time side channel

The vendor measures response generation time to infer how long the
model took, and correlates with other signals to de-anonymise.

**Not in scope**. Timing side channels would require uniform delays
which we explicitly do not add.

### Scenario 5 — placeholder leakage

The redactor replaces `alice@example.org` with `{EMAIL_1}`, but the
cloud model's response references `{EMAIL_1}` in a way that leaks
its structure (e.g. "I'll send the email to {EMAIL_1}, confirming
with {EMAIL_1} that..."). The restorer puts the real email back,
but the response structure reveals that there were two references
to the same person, which the cloud model now knows.

**Mitigation**: use opaque random tokens, not typed ones, when
maximum privacy is needed. Document the trade-off.

### Scenario 6 — detector adversarial input

A user types something that looks innocuous but contains a pattern
the detector misses. The request leaves with sensitive content
intact.

**Mitigation**: strict mode refuses requests with low-confidence
detection. The "unknown unknowns" problem — a sensitive kind we
don't have a detector for — is the fundamental limitation of
Option B.

## What each option defends against

| Option | S1 logs | S2 training | S3 SDK | S4 timing | S5 leakage | S6 unknown |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| A local | ✓ | ✓ | ✓ | ✓ | n/a | ✓ |
| B redact | partial | partial | partial | ✗ | partial | ✗ |
| C rephrase | partial | partial | partial | ✗ | n/a | partial |
| D TEE | ✓ (TEE) | ✓ (TEE) | ✗ | ✗ | n/a | ✓ (TEE) |
| E split | partial | partial | ✗ | ✗ | n/a | partial |
| F FHE | ✓ | ✓ | ✗ | ✗ | n/a | ✓ |
| G MPC | ✓ | ✓ | ✗ | ✗ | n/a | ✓ |
| H DP noise | partial | partial | partial | ✗ | n/a | partial |

## Trust boundaries diagram

```
╔════════════════════════════════════════════════════════╗
║  TRUSTED (laptop)                                      ║
║                                                        ║
║  ┌──────────┐   ┌──────────┐   ┌──────────────────┐    ║
║  │  agent   │──▶│  redactor│──▶│  local model     │    ║
║  └──────────┘   └─────┬────┘   └──────────────────┘    ║
║                       │                                ║
╚═══════════════════════┼════════════════════════════════╝
                        │  [redacted request]
                        ▼
╔════════════════════════════════════════════════════════╗
║  UNTRUSTED (cloud)                                     ║
║                                                        ║
║  ┌──────────────┐     ┌───────────────┐                ║
║  │ LLM vendor   │────▶│ vendor logs   │                ║
║  └──────────────┘     └───────────────┘                ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
```

The crossing at the dashed line is the only place where plaintext
can leak. Every option in `OPTIONS.md` is a strategy for ensuring
that what crosses the line is as safe as possible.
