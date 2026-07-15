package org.llmredactor.burp

class TextRedactor(
    private val detector: DetectorClient = DetectorClient(),
    private val fallback: RegexDetector = RegexDetector(),
) {
    fun redact(text: String): RedactionOutcome {
        if (text.isEmpty()) return RedactionOutcome(text, emptyList(), false)
        val prepared = prepare(text)
        return try {
            val spans = detector.detect(listOf(prepared.detectorText)).single().withoutProtected(prepared)
            RedactionOutcome(replace(text, spans), spans, false)
        } catch (_: Exception) {
            val spans = fallback.detect(prepared.detectorText).withoutProtected(prepared)
            RedactionOutcome(replace(text, spans), spans, true)
        }
    }

    fun redactBatch(texts: List<String>): List<RedactionOutcome> {
        val prepared = texts.map(::prepare)
        return try {
            detector.detect(prepared.map { it.detectorText }).mapIndexed { index, spans ->
                val safeSpans = spans.withoutProtected(prepared[index])
                RedactionOutcome(replace(texts[index], safeSpans), safeSpans, false)
            }
        } catch (_: Exception) {
            prepared.mapIndexed { index, value ->
                val spans = fallback.detect(value.detectorText).withoutProtected(value)
                RedactionOutcome(replace(texts[index], spans), spans, true)
            }
        }
    }

    /**
     * Encrypted JSON values are opaque protocol data: changing even one byte makes
     * them unverifiable. Hide their value from both detectors while preserving every
     * offset, then apply only spans outside the protected ranges to the original.
     */
    private fun prepare(text: String): PreparedText {
        val opaqueMatches = opaqueValues.flatMap { regex -> regex.findAll(text).toList() }
        val protected = opaqueMatches.map { match ->
            val value = match.groups[1]!!
            CodePointRange(text.codePointCount(0, value.range.first), text.codePointCount(0, value.range.last + 1))
        }
        if (protected.isEmpty()) return PreparedText(text, emptyList())

        val masked = text.toCharArray()
        opaqueMatches.forEach { match ->
            val value = match.groups[1]!!
            for (index in value.range) masked[index] = 'x'
        }
        return PreparedText(masked.concatToString(), protected)
    }

    private fun List<Span>.withoutProtected(prepared: PreparedText): List<Span> =
        filterNot { span -> prepared.protectedRanges.any { range -> span.start < range.end && range.start < span.end } }

    private data class PreparedText(val detectorText: String, val protectedRanges: List<CodePointRange>)
    private data class CodePointRange(val start: Int, val end: Int)

    companion object {
        private val opaqueValues = listOf(
            Regex(
                """(?i)"(?:encrypted(?:[_-]?(?:content|payload|data))?|cipher(?:text|[_-]?(?:content|payload|data))?|sealed(?:[_-]?(?:content|payload|data))?)"\s*:\s*"((?:\\.|[^"\\])*)""",
            ),
            // Image attachments need pixel redaction rather than text-span replacement.
            Regex("""(data:image/(?:png|jpeg);base64,[A-Za-z0-9+/=\r\n]+)"""),
        )
    }

    private fun replace(text: String, spans: List<Span>): String {
        val counters = mutableMapOf<String, Int>()
        val seen = mutableMapOf<String, String>()
        return spans.sortedByDescending { it.start }.fold(text) { output, span ->
            if (span.start < 0 || span.end < span.start) return@fold output
            val start = output.offsetByCodePoints(0, span.start)
            val end = output.offsetByCodePoints(0, span.end)
            val original = output.substring(start, end)
            val placeholder = seen.getOrPut(original) {
                val count = (counters[span.kind] ?: 0) + 1
                counters[span.kind] = count
                "⟨${span.kind.uppercase()}_$count⟩"
            }
            output.substring(0, start) + placeholder + output.substring(end)
        }
    }
}
