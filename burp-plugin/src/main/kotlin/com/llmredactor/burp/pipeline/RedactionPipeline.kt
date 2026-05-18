package com.llmredactor.burp.pipeline

import com.llmredactor.burp.config.PluginConfig
import com.llmredactor.burp.detect.DetectionOrchestrator
import com.llmredactor.burp.detect.Span
import com.llmredactor.burp.redact.RedactionResult
import com.llmredactor.burp.redact.redact
import com.llmredactor.burp.detect.LlmValidator
import com.llmredactor.burp.transport.NerClient
import java.util.UUID

/**
 * Orchestrates: detect → filter → redact for a single text string.
 *
 * The pipeline is stateless per call; session management lives in SessionStore.
 */
class RedactionPipeline(private val config: PluginConfig) {

    companion object {
        /** Matches Python ``opt_b_redact.strict`` (refuse when any span is below this). */
        const val STRICT_CONFIDENCE_THRESHOLD = 0.5
    }

    /** Spans that would cause strict mode to drop the request (empty if strict is off). */
    fun strictRefusalSpans(spans: List<Span>): List<Span> {
        if (!config.strict) return emptyList()
        return spans.filter { it.confidence < STRICT_CONFIDENCE_THRESHOLD }
    }

    /** Detect all sensitive spans in [text], filtered to the configured categories. */
    fun detectSpans(text: String): List<Span> {
        val nerSpans: List<Span> = if (config.nerEndpoint.isNotBlank()) {
            NerClient.detect(text, config.nerEndpoint)
        } else emptyList()

        val all = DetectionOrchestrator.detect(text, nerSpans)
        val filtered = DetectionOrchestrator.filterByCategories(all, config.categories)
        if (!config.llmValidationEnabled) return filtered
        val model = config.ollamaModel.ifBlank { "llama3.2" }
        return LlmValidator.validate(text, filtered, config.ollamaEndpoint, model)
    }

    /** Redact [text], returning the result and a fresh session tag if configured. */
    fun redactText(text: String, sessionTag: String? = null): RedactionResult {
        val spans = detectSpans(text)
        return redact(text, spans, sessionTag)
    }

    /** Generate a per-request session tag (8 hex chars) if placeholder tagging is on. */
    fun newSessionTag(): String? =
        if (config.placeholderTag) UUID.randomUUID().toString().replace("-", "").take(8)
        else null
}
