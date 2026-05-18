package com.llmredactor.burp.detect

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * Optional Ollama batch validation for NER spans (regex spans are kept as-is).
 * Port of src/llm_redactor/detect/llm_validator.py
 */
object LlmValidator {

    private const val CONTEXT_CHARS = 30

    private const val SYSTEM_PROMPT = """You are a PII/secret detection validator. You will be given a text span that was flagged as potentially sensitive, along with its surrounding context and the detection type.

Your job: determine if this span is ACTUALLY sensitive information that should be redacted before sending to a cloud LLM.

Rules:
- KEEP means "yes, redact this — it is real PII or a real secret"
- DROP means "no, this is a false positive — do not redact"
- Drug names, medical terms, technical jargon → DROP
- Common abbreviations (PII, API, SQL, Q3) when not actual identifiers → DROP
- Actual person names, emails, phone numbers, SSNs, API keys → KEEP
- Organization names that are real companies → KEEP
- Generic words (café, office, today) → DROP

Respond with ONLY a JSON object: {"verdict": "KEEP"} or {"verdict": "DROP"} for a single span, or a JSON array [{"span": 1, "verdict": "KEEP"}, ...] for multiple."""

    private val client: HttpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_1_1)
        .connectTimeout(Duration.ofSeconds(3))
        .build()

    fun validate(
        text: String,
        spans: List<Span>,
        endpoint: String,
        model: String,
        timeoutSeconds: Long = 30,
    ): List<Span> {
        if (spans.isEmpty()) return emptyList()

        val regexSpans = spans.filter { it.source == "regex" }
        val nerSpans = spans.filter { it.source != "regex" }
        if (nerSpans.isEmpty()) return regexSpans

        val deduped = mutableListOf<Span>()
        val keyToIndex = mutableMapOf<Pair<String, String>, Int>()
        for (s in nerSpans) {
            val key = s.text.trim().lowercase() to s.kind
            if (key !in keyToIndex) {
                keyToIndex[key] = deduped.size
                deduped.add(s)
            }
        }

        val keptUnique = batchValidate(text, deduped, endpoint, model, timeoutSeconds)
        val keptIndices = keptUnique.map { deduped.indexOf(it) }.toSet()

        val validated = regexSpans.toMutableList()
        for (s in nerSpans) {
            val idx = keyToIndex[s.text.trim().lowercase() to s.kind]
            if (idx != null && idx in keptIndices) validated.add(s)
        }
        return validated
    }

    private fun batchValidate(
        text: String,
        spans: List<Span>,
        endpoint: String,
        model: String,
        timeoutSeconds: Long,
    ): List<Span> {
        if (endpoint.isBlank() || model.isBlank()) return spans

        val entries = spans.mapIndexed { i, span ->
            val ctxStart = maxOf(0, span.start - CONTEXT_CHARS)
            val ctxEnd = minOf(text.length, span.end + CONTEXT_CHARS)
            val context = text.substring(ctxStart, ctxEnd)
            "Span ${i + 1}: \"${span.text}\" (detected as: ${span.kind}, confidence: ${"%.2f".format(span.confidence)})\n" +
                "Context: ...$context..."
        }

        val prompt = buildString {
            append("Validate these detected spans. For each, respond KEEP or DROP.\n\n")
            append(entries.joinToString("\n\n"))
            append("\n\nRespond with ONLY a JSON array of verdicts, e.g.:\n")
            append("[{\"span\": 1, \"verdict\": \"KEEP\"}, {\"span\": 2, \"verdict\": \"DROP\"}]")
        }

        val url = "${endpoint.trimEnd('/')}/api/chat"
        val body = JSONObject()
            .put("model", model)
            .put(
                "messages",
                JSONArray()
                    .put(JSONObject().put("role", "system").put("content", SYSTEM_PROMPT))
                    .put(JSONObject().put("role", "user").put("content", prompt)),
            )
            .put("stream", false)
            .put("options", JSONObject().put("temperature", 0.0).put("num_predict", 200))

        return try {
            val request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build()
            val response = client.send(request, HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() != 200) return spans
            val raw = JSONObject(response.body()).optJSONObject("message")?.optString("content").orEmpty()
            parseVerdicts(raw, spans)
        } catch (_: Exception) {
            spans
        }
    }

    private fun parseVerdicts(raw: String, spans: List<Span>): List<Span> {
        var clean = raw.trim()
        if (clean.startsWith("```")) {
            clean = clean.substringAfter('\n').substringBeforeLast("```").trim()
        }
        try {
            val verdicts = JSONArray(clean)
            val dropIndices = mutableSetOf<Int>()
            for (i in 0 until verdicts.length()) {
                val v = verdicts.get(i)
                when (v) {
                    is JSONObject -> {
                        val idx = v.optInt("span", i + 1) - 1
                        if (v.optString("verdict", "").uppercase() == "DROP" && idx in spans.indices) {
                            dropIndices.add(idx)
                        }
                    }
                }
            }
            return spans.filterIndexed { i, _ -> i !in dropIndices }
        } catch (_: Exception) {
            // line-by-line fallback
        }
        val lines = clean.lines()
        val kept = mutableListOf<Span>()
        for (i in spans.indices) {
            if (i < lines.size && "DROP" in lines[i].uppercase()) continue
            kept.add(spans[i])
        }
        return if (kept.isEmpty() && spans.isNotEmpty()) spans else kept
    }
}
