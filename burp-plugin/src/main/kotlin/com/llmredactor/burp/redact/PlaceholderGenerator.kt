package com.llmredactor.burp.redact

import com.llmredactor.burp.detect.Span

/**
 * Generates stable, typed Unicode placeholders and builds the reverse map.
 *
 * Port of src/llm_redactor/redact/placeholder.py
 *
 * Format: ⟨EMAIL_1⟩  or  ⟨EMAIL_1·a1b2c3d⟩  (with request tag)
 *   PREFIX = U+27E8 ⟨   SUFFIX = U+27E9 ⟩   SEP = U+00B7 ·
 */
class PlaceholderGenerator(private val sessionTag: String? = null) {

    private val counters = mutableMapOf<String, Int>()
    private val seen = mutableMapOf<String, String>() // originalText -> placeholder

    private fun nextPlaceholder(kind: String): String {
        val count = (counters[kind] ?: 0) + 1
        counters[kind] = count
        val core = "${kind.uppercase()}_$count"
        val inner = if (sessionTag != null) "$core·$sessionTag" else core
        return "⟨$inner⟩"
    }

    /** Return a stable placeholder for span.text (coreference stability). */
    fun getPlaceholder(span: Span): String {
        return seen.getOrPut(span.text) { nextPlaceholder(span.kind) }
    }
}

data class RedactionResult(
    val redactedText: String,
    val reverseMap: Map<String, String>,  // placeholder -> original
    val placeholders: List<String>,
)

/**
 * Replace detected spans with placeholders.
 * Spans are applied in reverse start order so earlier offsets are not invalidated.
 */
fun redact(text: String, spans: List<Span>, sessionTag: String? = null): RedactionResult {
    if (spans.isEmpty()) return RedactionResult(text, emptyMap(), emptyList())
    return redact(text, spans, PlaceholderGenerator(sessionTag))
}

/**
 * Same as above but uses an existing [PlaceholderGenerator] so counters stay
 * consistent across multiple [redact] calls within the same request.
 */
fun redact(text: String, spans: List<Span>, gen: PlaceholderGenerator): RedactionResult {
    if (spans.isEmpty()) return RedactionResult(text, emptyMap(), emptyList())

    val sortedSpans = spans.sortedByDescending { it.start }

    var result = text
    val reverseMap = mutableMapOf<String, String>()
    val placeholders = mutableListOf<String>()

    for (span in sortedSpans) {
        val placeholder = gen.getPlaceholder(span)
        reverseMap[placeholder] = span.text
        placeholders.add(placeholder)
        result = result.substring(0, span.start) + placeholder + result.substring(span.end)
    }

    placeholders.reverse() // restore insertion order
    return RedactionResult(result, reverseMap, placeholders)
}
