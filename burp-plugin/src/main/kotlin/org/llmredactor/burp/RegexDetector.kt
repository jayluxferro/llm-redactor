package org.llmredactor.burp

/**
 * The extension's own detector: used when the local detector service is
 * unreachable, and always for WebSocket frames (which must not wait on a
 * loopback round trip).
 *
 * It is a port of src/llm_redactor/detect/regex.py (patterns, in the same
 * order, with the same detection-time checksums) and of detect/wallets.py
 * (WalletDetector), merged the way the Python orchestrator merges. The
 * patterns are copied from the Python verbatim (generated from
 * `PATTERNS[kind].pattern`), so a diff against regex.py is meaningful; the
 * only edits are bounds on three group repetitions, marked below. Drift is
 * caught by tests/test_burp_parity.py + ParityTest, which replay the Python
 * output for a sample corpus against this class.
 *
 * Not ported: NER (Presidio/spaCy) and custom patterns from the service's
 * config file. Those need the service.
 */
class RegexDetector {
    fun detect(text: String): List<Span> {
        if (text.isEmpty()) return emptyList()
        val index = CodePointIndex(text)
        val hits = ArrayList<Span>()
        // Wallet spans first, as in detect_regex: on identical spans the merge
        // keeps the earlier one, and the specific crypto label is the useful one.
        WalletDetector.scan(text) { start, end, kind ->
            hits += Span(index.toCodePoint(start), index.toCodePoint(end), kind)
        }
        for ((kind, pattern) in PATTERNS) {
            val validator = VALIDATORS[kind]
            for (match in pattern.findAll(text)) {
                val group = (1 until match.groups.size).firstNotNullOfOrNull { match.groups[it] } ?: match.groups[0]!!
                if (validator != null) {
                    // A checksum that throws must never unredact (fail open to "keep").
                    val valid = try {
                        validator(group.value)
                    } catch (_: Exception) {
                        true
                    }
                    if (!valid) continue
                }
                hits += Span(index.toCodePoint(group.range.first), index.toCodePoint(group.range.last + 1), kind)
            }
        }
        return mergeOverlapping(hits)
    }

    companion object {
        // (?U): Python 3's \b, \d, \s and \w are Unicode-aware; Java's are ASCII
        // unless asked. Every pattern below is compiled with it.
        private fun compile(pattern: String) = Regex("(?U)$pattern")

        // Same order as regex.PATTERNS: on identical spans the earlier kind wins.
        private val PATTERNS: List<Pair<String, Regex>> = listOf(
            "email" to """\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b""",
            "phone_us" to """(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)""",
            "phone_intl" to """\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}(?:[-.\s]?\d{1,4})?""",
            "ssn" to """\b\d{3}-\d{2}-\d{4}\b""",
            "ip_v4" to """\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b""",
            "ip_v6" to """\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b""",
            "credit_card" to """\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}\b""",
            "employee_id" to """\bEMP-\d{4,6}\b""",
            // EDIT: the city part's `(?:\s+Word)*` is bounded {0,10}. java.util.regex
            // recurses per group repetition; unbounded, a long run of capitalised
            // words after an address overflowed the stack.
            "address" to """\b\d{1,6}\s+(?:[A-Z][A-Za-z0-9.'\-]*\s+){0,4}(?i:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Circle|Cir|Court|Ct|Way|Place|Pl|Terrace|Ter|Highway|Hwy|Parkway|Pkwy|Square|Sq|Trail|Trl|Loop|Alley|Crescent|Cres|Street|Avenue)\.?(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|Bldg|Floor|Fl|#)\.?\s*[A-Za-z0-9\-]+)?(?:\s*,\s*[A-Z][A-Za-z.'\-]+(?:\s+[A-Z][A-Za-z.'\-]+){0,10})?(?:\s*,?\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?""",
            "passport_number" to """(?i)passport\s*(?:number|no\.?|#|id)?\s*[:=]?\s*([A-Z]{0,2}\d{7,9})\b""",
            "ein" to """(?i)\b(?:ein|employer\s+id(?:entification)?|tax\s+id|tin)\b\s*[:=#]?\s*(\d{2}-?\d{7})\b""",
            "dob" to """(?i)(?:date\s+of\s+birth|d\.?o\.?b\.?|birth\s*date|born(?:\s+on)?)\s*[:=]?\s*(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})""",
            "iban" to """\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){3,8}\b""",
            "us_routing_number" to """(?i)(?:routing|aba|rtn)\s*(?:number|no\.?|#)?\s*[:=]?\s*(\d{9})""",
            "us_bank_account" to """(?i)(?:account|acct)\s*(?:number|no\.?|#)\s*[:=]?\s*(\d{6,17})""",
            "npi" to """(?i)\bnpi\b\s*(?:number|no\.?|#|id)?\s*[:=]?\s*[12]\d{9}\b""",
            "dea_number" to """\b[A-Za-z][A-Za-z]\d{7}\b""",
            "mac_address" to """\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b""",
            "password" to """(?i)(?:password|passwd|pwd|pass)['\"]?[\s]*[=:]\s*(?:\"([^\"\r\n]{4,})\"|'([^'\r\n]{4,})'|(\S{4,}))""",
            "secret_assignment" to """(?i)['\"]?(?:secret|token|credential|auth)['\"]?[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_.:+/=]{8,})['\"]?""",
            "connection_string" to """(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\s'\"]{10,}""",
            "aws_access_key" to """\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b""",
            "aws_secret_key" to """(?i)['\"]?(?:aws)?[_\-]?(?:secret)?[_\-]?(?:access)?[_\-]?key['\"]?(?:[^=]{0,40}[=:]|[^\S\n]*)\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])['\"]?""",
            "aws_session_token" to """(?i)aws[_\-]?session[_\-]?token[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?""",
            "gcp_service_account" to """\b[a-z0-9\-]{1,64}@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b""",
            "gcp_api_key" to """\bAIza[0-9A-Za-z\-_]{35}\b""",
            "azure_storage_key" to """(?i)(?:account[_\-]?key|storage[_\-]?key)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/=]{88})['\"]?""",
            "azure_connection_string" to """(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}""",
            "openai_api_key" to """\bsk-(?:proj-)?[a-zA-Z0-9\-_]{20,}\b""",
            "anthropic_api_key" to """\bsk-ant-(?:api03-)?[a-zA-Z0-9\-_]{20,}\b""",
            "github_token" to """\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59}\b""",
            "gitlab_token" to """\bgl(?:pat|ptt|dt|rt|at)-[A-Za-z0-9\-_]{20,}\b""",
            "slack_token" to """\bxox[baprs]-[0-9A-Za-z\-]{10,}\b""",
            "slack_webhook" to """https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+""",
            "stripe_key" to """\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}\b""",
            "twilio_key" to """\bSK[0-9a-fA-F]{32}\b""",
            "sendgrid_key" to """\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{20,}\b""",
            "mailgun_key" to """\bkey-[0-9a-zA-Z]{32}\b""",
            "npm_token" to """\bnpm_[A-Za-z0-9]{36}\b""",
            "pypi_token" to """\bpypi-[A-Za-z0-9\-_]{50,}\b""",
            "heroku_api_key" to """(?i)heroku[_\-]?(?:api[_\-]?)?(?:key|token)[\s]*[=:\s]+['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?""",
            "telegram_bot_token" to """\b\d{5,12}:[A-Za-z0-9_-]{30,}\b""",
            "discord_token" to """\bMTA[0-9A-Za-z_-]{20,}\b""",
            "huggingface_token" to """\bhf_[A-Za-z0-9]{34,}\b""",
            "digitalocean_token" to """\bdo[opr]_v1_[a-f0-9]{64}\b""",
            "shopify_token" to """\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b""",
            "postman_api_key" to """\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b""",
            "notion_token" to """\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b""",
            "hashicorp_vault_token" to """\bhv[bs]\.[A-Za-z0-9_-]{24,}\b""",
            "grafana_token" to """\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\b""",
            "netlify_token" to """\bnfp_[A-Za-z0-9]{40}\b""",
            "planetscale_token" to """\bpscale_tkn_[A-Za-z0-9_-]{40,}\b""",
            "sourcegraph_token" to """\bsgp_[a-f0-9]{40}\b""",
            "pulumi_token" to """\bpul-[a-f0-9]{40}\b""",
            "new_relic_key" to """\bNRAK-[A-Z0-9]{27}\b""",
            "dynatrace_token" to """\bdt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b""",
            "doppler_token" to """\bdp\.(?:pt|st|sa)\.[A-Za-z0-9]{40,}\b""",
            "sentry_token" to """\bsntrys_[A-Za-z0-9]{40,}\b""",
            "replicate_token" to """\br8_[A-Za-z0-9]{37,}\b""",
            "generic_api_key" to """(?i)['\"]?(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|key)['\"]?[\s]*[=:]\s*['\"]?([A-Za-z0-9\-_.:+/=]{16,})['\"]?""",
            "bearer_token" to """(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,}=*""",
            "basic_auth" to """(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}""",
            "jwt" to """\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+\b""",
            // EDIT: armor label words bounded {0,8} (Python: unbounded `*`).
            "private_key_pem" to """(?s)-----BEGIN (?!OPENSSH )(?:[A-Z0-9]+ ){0,8}PRIVATE KEY-----.*?-----END (?:[A-Z0-9]+ ){0,8}PRIVATE KEY-----""",
            "ssh_private_key" to """(?s)-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----""",
            "pgp_private_key" to """(?s)-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----""",
            // EDIT: trailing labels bounded {0,126} (a DNS name has at most 127).
            "hostname_internal" to """\b[a-z][a-z0-9\-]{0,62}\.(?:internal|local|corp|lan|intranet|private|staging|dev|infra|test|qa|k8s|cluster|svc)(?:\.[a-z0-9\-]+){0,126}\b""",
        ).map { (kind, pattern) -> kind to compile(pattern) }

        // checksums.py: kinds whose pattern alone over-matches.
        private val VALIDATORS: Map<String, (String) -> Boolean> = mapOf(
            "iban" to Checksums::iban,
            "npi" to Checksums::npi,
            "dea_number" to Checksums::deaNumber,
            "us_routing_number" to Checksums::usRoutingNumber,
        )
    }
}

/** Port of src/llm_redactor/detect/checksums.py (the detection-time subset). */
internal object Checksums {
    private fun digitsOnly(text: String): String = text.filter { it.isDigit() }

    fun luhn(digits: String): Boolean {
        var total = 0
        digits.reversed().forEachIndexed { i, ch ->
            var d = ch.digitToInt()
            if (i % 2 == 1) {
                d *= 2
                if (d > 9) d -= 9
            }
            total += d
        }
        return total % 10 == 0
    }

    fun iban(text: String): Boolean {
        val s = text.replace(" ", "").replace("-", "").uppercase()
        if (s.length < 15 || s.length > 34 || !s.substring(0, 2).all { it.isLetter() } ||
            !s.substring(2, 4).all { it.isDigit() }
        ) {
            return false
        }
        var value = 0L
        for (ch in s.substring(4) + s.substring(0, 4)) {
            value = when {
                ch.isDigit() -> value * 10 + ch.digitToInt()
                ch in 'A'..'Z' -> value * 100 + (ch - 'A' + 10)
                else -> return false
            }
            value %= 97
        }
        return value % 97 == 1L
    }

    fun npi(text: String): Boolean {
        val d = digitsOnly(text)
        return d.length == 10 && luhn("80840$d")
    }

    private const val DEA_FIRST_LETTERS = "ABCDEFGHJKLMNPRSTUX"

    fun deaNumber(text: String): Boolean {
        val s = text.trim().uppercase()
        if (s.length != 9 || !s.substring(0, 2).all { it.isLetter() } || !s.substring(2).all { it.isDigit() }) return false
        if (s[0] !in DEA_FIRST_LETTERS) return false
        val d = s.substring(2).map { it.digitToInt() }
        val odd = d[0] + d[2] + d[4]
        val even = d[1] + d[3] + d[5]
        return (odd + 2 * even) % 10 == d[6]
    }

    fun usRoutingNumber(text: String): Boolean {
        val d = digitsOnly(text).map { it.digitToInt() }
        if (d.size != 9) return false
        val prefix = d[0] * 10 + d[1]
        if (!(prefix <= 12 || prefix in 21..32 || prefix in 61..72 || prefix == 80)) return false
        val checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
        return checksum % 10 == 0
    }
}
