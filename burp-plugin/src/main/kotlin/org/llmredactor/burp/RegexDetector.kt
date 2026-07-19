package org.llmredactor.burp

/** Local availability fallback. Keep these categories aligned with detect/regex.py. */
class RegexDetector {
    private val patterns = linkedMapOf(
        "email" to Regex("\\b[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}\\b"),
        "phone" to Regex("(?<!\\d)(?:\\+?\\d{1,3}[-.\\s]?)?(?:\\(?\\d{2,4}\\)?[-.\\s]?){2,4}\\d{2,4}(?!\\d)"),
        "ssn" to Regex("\\b\\d{3}-\\d{2}-\\d{4}\\b"),
        "ip_v4" to Regex("\\b(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)(?:\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)){3}\\b"),
        "credit_card" to Regex("\\b(?:4\\d{3}|5[1-5]\\d{2}|3[47]\\d{2}|6(?:011|5\\d{2}))[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{1,4}\\b"),
        "password" to Regex("(?i)(?:password|passwd|pwd|pass)\\s*[=:]\\s*['\\\"]?([^\\s'\\\"]{4,})"),
        "connection_string" to Regex("(?i)(?:mongodb(?:\\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\\s'\\\"]{10,}"),
        "aws_access_key" to Regex("\\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\\b"),
        "gcp_api_key" to Regex("\\bAIza[0-9A-Za-z\\-_]{35}\\b"),
        "openai_api_key" to Regex("\\bsk-(?:proj-)?[a-zA-Z0-9\\-_]{20,}\\b"),
        "anthropic_api_key" to Regex("\\bsk-ant-(?:api03-)?[a-zA-Z0-9\\-_]{20,}\\b"),
        "github_token" to Regex("\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\\b"),
        "gitlab_token" to Regex("\\bgl(?:pat|ptt|dt|rt|at)-[A-Za-z0-9\\-_]{20,}\\b"),
        "slack_token" to Regex("\\bxox[baprs]-[0-9A-Za-z\\-]{10,}\\b"),
        "stripe_key" to Regex("\\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}\\b"),
        "generic_api_key" to Regex("(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\\s*[=:]\\s*['\\\"]?([A-Za-z0-9\\-_.+/=]{16,})"),
        "bearer_token" to Regex("(?i)bearer\\s+[A-Za-z0-9\\-_.~+/]{20,}=*"),
        "jwt" to Regex("\\beyJ[A-Za-z0-9\\-_]+\\.eyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_.+/=]+\\b"),
        "private_key_pem" to Regex("-----BEGIN (?:RSA |EC |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----"),
        "hostname_internal" to Regex("\\b[a-z][a-z0-9\\-]+\\.(?:internal|local|corp|lan|intranet|private|staging|dev)\\b"),
    )

    fun detect(text: String): List<Span> = patterns.flatMap { (kind, regex) ->
        regex.findAll(text).map { match ->
            val group = if (match.groupValues.size > 1 && match.groups[1] != null) match.groups[1]!! else match.groups[0]!!
            // group.range uses UTF-16 code-unit indices on JVM, but TextRedactor.replace
            // treats span offsets as code-point indices (consistent with the Python detector).
            Span(text.codePointCount(0, group.range.first), text.codePointCount(0, group.range.last + 1), kind)
        }.toList()
    }.sortedBy { it.start }.fold(mutableListOf()) { accepted, span ->
        if (accepted.none { span.start < it.end && it.start < span.end }) accepted += span
        accepted
    }
}
