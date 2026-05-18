package com.llmredactor.burp.detect

import java.util.regex.Pattern

/**
 * Regex-based detector for secrets and structured PII.
 *
 * Direct port of src/llm_redactor/detect/regex.py
 *
 * Sources: gitleaks rules, trufflehog patterns, detect-secrets,
 * OWASP secret patterns, AWS/GCP/Azure documentation.
 */
object RegexDetector {

    /**
     * Each entry is [kind, hasGroup1].
     * hasGroup1=true  → use group(1) as the matched span (same as Python group(1) logic).
     * hasGroup1=false → use the full match.
     */
    private data class PatternEntry(
        val kind: String,
        val pattern: Pattern,
        val hasGroup: Boolean,
    )

    private val PATTERNS: List<PatternEntry> = buildList {
        fun add(kind: String, regex: String, hasGroup: Boolean = false) {
            add(PatternEntry(kind, Pattern.compile(regex), hasGroup))
        }

        // ── PII ──────────────────────────────────────────────────────────
        add("email",       """[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}""")
        add("phone_us",    """(?<!\d)(?:\+?1[.\- ]?)?\(?\d{3}\)?[.\- ]?\d{3}[.\- ]?\d{4}(?!\d)""")
        add("phone_intl",  """\+\d{1,3}[.\- ]?\d{1,4}[.\- ]?\d{2,4}[.\- ]?\d{2,4}(?:[.\- ]?\d{1,4})?""")
        add("ssn",         """\b\d{3}-\d{2}-\d{4}\b""")
        add("ip_v4",       """\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b""")
        add("ip_v6",
            """(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}""" +
            """|(?:[0-9a-fA-F]{1,4}:){1,7}:""" +
            """|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}""")
        add("credit_card",
            """\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))""" +
            """[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b""")
        add("employee_id", """\bEMP-\d{4,6}\b""")

        // ── Passwords & secrets in assignments ────────────────────────────
        add("password",
            """(?i)(?:password|passwd|pwd|pass)[\s]*[=:]\s*['"]?(\S{4,})['"]?""",
            hasGroup = true)
        add("secret_assignment",
            """(?i)(?:secret|token|credential|auth)[\s]*[=:]\s*['"]?([A-Za-z0-9\-_.+/=]{8,})['"]?""",
            hasGroup = true)
        add("connection_string",
            """(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\s'"]{10,}""")

        // ── Cloud provider keys ───────────────────────────────────────────
        // AWS
        add("aws_access_key",
            """\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b""")
        add("aws_secret_key",
            """(?i)(?:aws)?[_\-]?(?:secret)?[_\-]?(?:access)?[_\-]?key[\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
            hasGroup = true)
        add("aws_session_token",
            """(?i)aws[_\-]?session[_\-]?token[\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?""",
            hasGroup = true)
        // GCP
        add("gcp_service_account",
            """\b[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b""")
        add("gcp_api_key",
            """\bAIza[0-9A-Za-z\-_]{35}\b""")
        // Azure
        add("azure_storage_key",
            """(?i)(?:account[_\-]?key|storage[_\-]?key)[\s]*[=:]\s*['"]?([A-Za-z0-9+/=]{88})['"]?""",
            hasGroup = true)
        add("azure_connection_string",
            """(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}""")

        // ── API keys by vendor ────────────────────────────────────────────
        add("openai_api_key",     """\bsk-(?:proj-)?[a-zA-Z0-9\-_]{20,}\b""")
        add("anthropic_api_key",  """\bsk-ant-(?:api03-)?[a-zA-Z0-9\-_]{20,}\b""")
        add("github_token",       """\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b""")
        add("gitlab_token",       """\bgl(?:pat|ptt|dt|rt|at)-[A-Za-z0-9\-_]{20,}\b""")
        add("slack_token",        """\bxox[baprs]-[0-9A-Za-z\-]{10,}\b""")
        add("slack_webhook",      """https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+""")
        add("stripe_key",         """\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}\b""")
        add("twilio_key",         """\bSK[0-9a-fA-F]{32}\b""")
        add("sendgrid_key",       """\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{20,}\b""")
        add("mailgun_key",        """\bkey-[0-9a-zA-Z]{32}\b""")
        add("npm_token",          """\bnpm_[A-Za-z0-9]{36}\b""")
        add("pypi_token",         """\bpypi-[A-Za-z0-9\-_]{50,}\b""")
        // Require "heroku" context — bare UUID pattern matches too many false positives
        // (session IDs, request IDs, trace IDs, etc.)
        add("heroku_api_key",
            """(?i)heroku[_\-]?(?:api[_\-]?)?(?:key|token)[\s]*[=:\s]+['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?""",
            hasGroup = true)

        // ── Generic patterns ──────────────────────────────────────────────
        add("generic_api_key",
            """(?i)(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)""" +
            """[\s]*[=:]\s*['"]?([A-Za-z0-9\-_.+/=]{16,})['"]?""",
            hasGroup = true)
        add("bearer_token", """(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,}=*""")
        add("basic_auth",   """(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}""")
        add("jwt",
            """\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+\b""")
        add("private_key_pem",
            """-----BEGIN (?:RSA |EC |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----""")
        add("ssh_private_key", """-----BEGIN OPENSSH PRIVATE KEY-----""")
        add("pgp_private_key", """-----BEGIN PGP PRIVATE KEY BLOCK-----""")

        // ── Hostnames ─────────────────────────────────────────────────────
        add("hostname_internal",
            """\b[a-z][a-z0-9\-]+\.(?:internal|local|corp|lan|intranet|private|staging|dev)\b""")
    }

    /** Run all patterns against [text] and return all detected spans. */
    fun detect(text: String): List<Span> {
        val spans = mutableListOf<Span>()
        for (entry in PATTERNS) {
            val matcher = entry.pattern.matcher(text)
            while (matcher.find()) {
                val (start, end, matched) = if (entry.hasGroup && matcher.groupCount() >= 1
                    && matcher.group(1) != null) {
                    Triple(matcher.start(1), matcher.end(1), matcher.group(1)!!)
                } else {
                    Triple(matcher.start(), matcher.end(), matcher.group())
                }
                spans.add(Span(
                    start = start,
                    end = end,
                    kind = entry.kind,
                    confidence = 1.0,
                    text = matched,
                    source = "regex",
                ))
            }
        }
        return spans
    }
}
