package com.llmredactor.burp.detect

/**
 * A detected sensitive span in an input text.
 *
 * Direct port of src/llm_redactor/detect/types.py :: Span
 */
data class Span(
    val start: Int,
    val end: Int,
    val kind: String,        // e.g. "email", "aws_access_key", "person"
    val confidence: Double,  // 0.0 – 1.0
    val text: String,        // the matched substring
    val source: String,      // "regex" | "ner"
) {
    val category: String get() = CategoryMap.kindToCategory(kind)
}
