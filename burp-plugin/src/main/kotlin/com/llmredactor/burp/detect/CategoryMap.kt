package com.llmredactor.burp.detect

/**
 * Taxonomy: maps every detection kind to a policy-level category.
 *
 * Direct port of src/llm_redactor/detect/types.py :: CATEGORY_MAP + CATEGORY_ALIASES
 */
object CategoryMap {

    val KIND_TO_CATEGORY: Map<String, String> = mapOf(
        // ── identity ─────────────────────────────────────────────────────
        "person"             to "identity",
        "nationality"        to "identity",
        "employee_id"        to "identity",
        // ── contact ──────────────────────────────────────────────────────
        "email"              to "contact",
        "phone"              to "contact",
        "phone_us"           to "contact",
        "phone_intl"         to "contact",
        "location"           to "contact",
        "url"                to "contact",
        "ip_address"         to "contact",
        "ip_v4"              to "contact",
        "ip_v6"              to "contact",
        // ── government_id ─────────────────────────────────────────────────
        "ssn"                to "government_id",
        // ── financial ─────────────────────────────────────────────────────
        "credit_card"        to "financial",
        "iban"               to "financial",
        // ── medical ───────────────────────────────────────────────────────
        "medical_license"    to "medical",
        // ── temporal ──────────────────────────────────────────────────────
        "date_time"          to "temporal",
        // ── credential ────────────────────────────────────────────────────
        "password"           to "credential",
        "secret_assignment"  to "credential",
        "bearer_token"       to "credential",
        "basic_auth"         to "credential",
        "jwt"                to "credential",
        "generic_api_key"    to "credential",
        // ── cloud_credential ──────────────────────────────────────────────
        "aws_access_key"          to "cloud_credential",
        "aws_secret_key"          to "cloud_credential",
        "aws_session_token"       to "cloud_credential",
        "gcp_service_account"     to "cloud_credential",
        "gcp_api_key"             to "cloud_credential",
        "azure_storage_key"       to "cloud_credential",
        "azure_connection_string" to "cloud_credential",
        // ── vendor_api_key ────────────────────────────────────────────────
        "openai_api_key"     to "vendor_api_key",
        "anthropic_api_key"  to "vendor_api_key",
        "github_token"       to "vendor_api_key",
        "gitlab_token"       to "vendor_api_key",
        "slack_token"        to "vendor_api_key",
        "slack_webhook"      to "vendor_api_key",
        "stripe_key"         to "vendor_api_key",
        "twilio_key"         to "vendor_api_key",
        "sendgrid_key"       to "vendor_api_key",
        "mailgun_key"        to "vendor_api_key",
        "npm_token"          to "vendor_api_key",
        "pypi_token"         to "vendor_api_key",
        "heroku_api_key"     to "vendor_api_key",
        // ── private_key ───────────────────────────────────────────────────
        "private_key_pem"    to "private_key",
        "ssh_private_key"    to "private_key",
        "pgp_private_key"    to "private_key",
        // ── infrastructure ────────────────────────────────────────────────
        "connection_string"  to "infrastructure",
        "hostname_internal"  to "infrastructure",
    )

    /** Aliases expand to one or more fine-grained category names. */
    val ALIASES: Map<String, List<String>> = mapOf(
        "all"           to KIND_TO_CATEGORY.values.distinct(),
        "pii"           to listOf("identity", "contact", "government_id", "financial", "medical", "temporal"),
        "secret"        to listOf("credential", "cloud_credential", "vendor_api_key", "private_key"),
        "org_identifier" to listOf("infrastructure"),
        "customer_name" to listOf("identity"),
    )

    fun kindToCategory(kind: String): String =
        KIND_TO_CATEGORY[kind] ?: "unknown"

    /** Expand a list of category names / aliases into fine-grained category names. */
    fun resolveCategories(names: Set<String>): Set<String> {
        val result = mutableSetOf<String>()
        for (name in names) {
            val expanded = ALIASES[name]
            if (expanded != null) result.addAll(expanded) else result.add(name)
        }
        return result
    }
}
