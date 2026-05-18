package com.llmredactor.burp.detect

/**
 * Merges spans from multiple detectors, deduplicates overlaps, and
 * filters out known false positives.
 *
 * Port of src/llm_redactor/detect/orchestrator.py
 */
object DetectionOrchestrator {

    private val FP_SUPPRESS: Set<String> = setOf(
        "pii", "api", "ssn", "dob", "ehr", "phi", "hipaa", "gdpr",
        "sql", "csv", "json", "xml", "html", "http", "https", "url",
        "llm", "nlp", "ner", "gpt", "ai", "ml", "dl",
        "today", "yesterday", "tomorrow", "now", "recently",
        "q1", "q2", "q3", "q4",
        "café", "cafe", "office", "home", "here", "there",
    )

    private val FP_DRUGS = Regex(
        """(?i)^(?:lisinopril|metformin|atorvastatin|omeprazole|amlodipine|""" +
        """metoprolol|losartan|albuterol|gabapentin|hydrochlorothiazide|""" +
        """levothyroxine|simvastatin|ibuprofen|acetaminophen|amoxicillin|""" +
        """azithromycin|ciprofloxacin|prednisone|sertraline|fluoxetine)$"""
    )

    private val FP_LABELS = Regex("""(?i)^(?:dob|ssn|ein|tin|mrn)\s""")

    private fun isFalsePositive(span: Span): Boolean {
        if (span.source != "ner") return false
        val lower = span.text.trim().lowercase()
        if (lower in FP_SUPPRESS) return true
        if (lower.length <= 2 && span.kind !in setOf("ssn", "ip_address")) return true
        if (FP_DRUGS.containsMatchIn(span.text.trim())) return true
        if (FP_LABELS.containsMatchIn(span.text.trim())) return true
        if (span.confidence < 0.4 && span.text.length < 6) return true
        return false
    }

    /** Merge overlapping spans; keep highest-confidence on overlap. */
    fun mergeOverlapping(spans: List<Span>): List<Span> {
        if (spans.isEmpty()) return emptyList()
        val sorted = spans.sortedWith(compareBy({ it.start }, { -(it.end - it.start) }))
        val merged = mutableListOf(sorted[0])
        for (span in sorted.drop(1)) {
            val prev = merged.last()
            if (span.start < prev.end) {
                if (span.confidence > prev.confidence) merged[merged.lastIndex] = span
            } else {
                merged.add(span)
            }
        }
        return merged
    }

    /** Combine regex + NER spans, filter false positives, merge overlaps. */
    fun detect(text: String, nerSpans: List<Span> = emptyList()): List<Span> {
        val regexSpans = RegexDetector.detect(text)
        val filteredNer = nerSpans.filter { !isFalsePositive(it) }
        return mergeOverlapping(regexSpans + filteredNer)
    }

    /** Keep only spans whose category is in [categories] (after alias expansion). */
    fun filterByCategories(spans: List<Span>, categories: Set<String>): List<Span> {
        val allowed = CategoryMap.resolveCategories(categories)
        return spans.filter { it.category in allowed }
    }
}
