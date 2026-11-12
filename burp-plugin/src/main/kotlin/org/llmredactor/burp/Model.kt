package org.llmredactor.burp

/** A detection over code-point offsets [start, end), the Python detector's unit. */
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
    val timestamp: Long = System.currentTimeMillis(),
)

/**
 * One placeholder namespace, mirroring the Python PlaceholderGenerator: the
 * same original value always gets the same placeholder, and two different
 * values never share one. Use one instance per HTTP request (query string and
 * every body field) and one per WebSocket connection. A fresh namespace per
 * string, as this extension once used, gave two different e-mails in one
 * request the same `⟨EMAIL_1⟩`, telling the model they were one person.
 */
class PlaceholderNaming {
    private val counters = HashMap<String, Int>()
    private val seen = HashMap<String, String>()

    @Synchronized
    fun placeholderFor(original: String, kind: String): String = seen.getOrPut(original) {
        val count = (counters[kind] ?: 0) + 1
        counters[kind] = count
        "⟨${kind.uppercase()}_$count⟩"
    }
}
