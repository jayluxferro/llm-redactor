package org.llmredactor.burp

data class Span(
    val start: Int,
    val end: Int,
    val kind: String,
    val confidence: Double = 1.0,
    val source: String = "regex",
)

data class RedactionOutcome(
    val text: String,
    val spans: List<Span>,
    val usedFallback: Boolean,
)

data class Activity(
    val protocol: String,
    val host: String,
    val outcome: String,
    val detections: Int = 0,
    val detail: String = "",
)
