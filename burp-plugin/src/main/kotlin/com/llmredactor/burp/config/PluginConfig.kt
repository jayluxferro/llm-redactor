package com.llmredactor.burp.config

import burp.api.montoya.persistence.PersistedObject

/**
 * Plugin settings, persisted via Montoya's extensionData store.
 */
class PluginConfig(private val store: PersistedObject) {

    companion object {
        private const val KEY_ENABLED          = "enabled"
        private const val KEY_TARGET_HOSTS     = "targetHosts"
        private const val KEY_TARGET_PATHS     = "targetPaths"
        private const val KEY_CATEGORIES       = "categories"
        private const val KEY_NER_ENDPOINT     = "nerEndpoint"
        private const val KEY_STRICT           = "strict"
        private const val KEY_SESSION_CAP      = "sessionCap"
        private const val KEY_PLACEHOLDER_TAG  = "placeholderTag"
        private const val KEY_DEBUG_DUMP       = "debugDump"
        private const val KEY_RESTORE_RESPONSES = "restoreResponses"
        private const val KEY_TOOLS_POLICY       = "toolsPolicy"
        private const val KEY_LLM_VALIDATION     = "llmValidationEnabled"
        private const val KEY_OLLAMA_ENDPOINT    = "ollamaEndpoint"
        private const val KEY_OLLAMA_MODEL       = "ollamaModel"
        private const val KEY_LOG_ROW_CAP        = "logRowCap"
        private const val KEY_LOG_MATCHED        = "logMatchedRequests"

        /** Always merged into saved host lists (existing Burp installs keep old persisted values). */
        val CURSOR_HOSTS = setOf(
            "cursor.sh",
            "api2.cursor.sh",
            "repo42.cursor.sh",
            "api5.cursor.sh",
            "agent.api5.cursor.sh",
            "agentn.api5.cursor.sh",
            "agentn.global.api5.cursor.sh",
        )

        private val DEFAULT_HOSTS = setOf(
            "api.openai.com",
            "api.anthropic.com",
            "openai.azure.com",
            "api.deepseek.com",
        ) + CURSOR_HOSTS
        private val DEFAULT_PATHS = setOf(
            "/v1/chat/completions",
            "/v1/messages",
            "/v1/completions",
            "/v1/traces",
            "/anthropic/v1/messages",
            "/aiserver.v1.",
        )
        private val DEFAULT_CATEGORIES = setOf("pii", "secret")
        const val DEFAULT_LOG_ROW_CAP = 500
    }

    var enabled: Boolean
        get() = store.getBoolean(KEY_ENABLED) ?: true
        set(v) = store.setBoolean(KEY_ENABLED, v)

    var targetHosts: Set<String>
        get() {
            val raw = store.getString(KEY_TARGET_HOSTS)
            if (raw == null) return DEFAULT_HOSTS
            val stored = raw.split(",").map { it.trim() }.filter { it.isNotBlank() }.toSet()
            val merged = stored + CURSOR_HOSTS
            if (merged != stored) {
                store.setString(KEY_TARGET_HOSTS, merged.joinToString(", "))
            }
            return merged
        }
        set(v) = store.setString(KEY_TARGET_HOSTS, v.joinToString(","))

    var targetPaths: Set<String>
        get() {
            val raw = store.getString(KEY_TARGET_PATHS)
            if (raw == null) return DEFAULT_PATHS
            val stored = raw.split(",").map { it.trim() }.filter { it.isNotBlank() }.toSet()
            val mergedDefaults = setOf("/aiserver.v1.", "/v1/traces")
            val merged = stored + mergedDefaults
            if (merged != stored) {
                store.setString(KEY_TARGET_PATHS, merged.joinToString(", "))
            }
            return merged
        }
        set(v) = store.setString(KEY_TARGET_PATHS, v.joinToString(","))

    var categories: Set<String>
        get() = store.getString(KEY_CATEGORIES)
            ?.split(",")?.map { it.trim() }?.filter { it.isNotBlank() }?.toSet()
            ?: DEFAULT_CATEGORIES
        set(v) = store.setString(KEY_CATEGORIES, v.joinToString(","))

    var nerEndpoint: String
        get() = store.getString(KEY_NER_ENDPOINT) ?: ""
        set(v) = store.setString(KEY_NER_ENDPOINT, v)

    var strict: Boolean
        get() = store.getBoolean(KEY_STRICT) ?: false
        set(v) = store.setBoolean(KEY_STRICT, v)

    var sessionCap: Int
        get() = store.getInteger(KEY_SESSION_CAP) ?: 10_000
        set(v) = store.setInteger(KEY_SESSION_CAP, v)

    var placeholderTag: Boolean
        get() = store.getBoolean(KEY_PLACEHOLDER_TAG) ?: false
        set(v) = store.setBoolean(KEY_PLACEHOLDER_TAG, v)

    var debugDump: Boolean
        get() = store.getBoolean(KEY_DEBUG_DUMP) ?: false
        set(v) = store.setBoolean(KEY_DEBUG_DUMP, v)

    /**
     * When false (default), upstream responses are passed through unchanged.
     * Outbound requests are still redacted. Use true only for simple chat UIs
     * where swapping ⟨placeholders⟩ back in the assistant text is desired.
     */
    var restoreResponses: Boolean
        get() = store.getBoolean(KEY_RESTORE_RESPONSES) ?: false
        set(v) = store.setBoolean(KEY_RESTORE_RESPONSES, v)

    /** `bypass` (default): forward tool/function requests unredacted. `refuse`: drop. */
    var toolsPolicy: String
        get() = store.getString(KEY_TOOLS_POLICY) ?: "bypass"
        set(v) = store.setString(KEY_TOOLS_POLICY, v.lowercase())

    var llmValidationEnabled: Boolean
        get() = store.getBoolean(KEY_LLM_VALIDATION) ?: false
        set(v) = store.setBoolean(KEY_LLM_VALIDATION, v)

    var ollamaEndpoint: String
        get() = store.getString(KEY_OLLAMA_ENDPOINT) ?: "http://127.0.0.1:11434"
        set(v) = store.setString(KEY_OLLAMA_ENDPOINT, v)

    var ollamaModel: String
        get() = store.getString(KEY_OLLAMA_MODEL) ?: "llama3.2"
        set(v) = store.setString(KEY_OLLAMA_MODEL, v)

    /** Max rows in the Activity log table (ring buffer). */
    var logRowCap: Int
        get() = store.getInteger(KEY_LOG_ROW_CAP) ?: DEFAULT_LOG_ROW_CAP
        set(v) = store.setInteger(KEY_LOG_ROW_CAP, v)

    /** Log target requests even when no spans were redacted. */
    var logMatchedRequests: Boolean
        get() = store.getBoolean(KEY_LOG_MATCHED) ?: true
        set(v) = store.setBoolean(KEY_LOG_MATCHED, v)
}
