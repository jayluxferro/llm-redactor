package org.llmredactor.burp

class TextRedactor(
    private val detector: DetectorClient = DetectorClient(),
    private val fallback: RegexDetector = RegexDetector(),
) {
    /**
     * One string to redact. [prefix] and [suffix] are context the detectors
     * see but replacement never touches: a JSON value is detected as
     * `"password": "<value>"`, so key-anchored patterns (password, api_key,
     * aws_secret_key, ...) still fire once values are redacted one by one.
     */
    data class Field(val text: String, val prefix: String = "", val suffix: String = "")

    fun redact(text: String, naming: PlaceholderNaming = PlaceholderNaming()): RedactionOutcome =
        redactFields(listOf(Field(text)), naming).single()

    /**
     * Regex-only redaction that never contacts the detector. WebSocket frames
     * use it: even a loopback round trip can stall a streaming connection.
     */
    fun redactWithRegex(text: String, naming: PlaceholderNaming = PlaceholderNaming()): RedactionOutcome =
        redactFields(listOf(Field(text)), naming, regexOnly = true).single()

    fun redactBatch(texts: List<String>, naming: PlaceholderNaming = PlaceholderNaming()): List<RedactionOutcome> =
        redactFields(texts.map { Field(it) }, naming)

    /**
     * Redacts every field with one detector round trip (identical fields are
     * detected once) and one placeholder namespace. If the detector fails,
     * the whole batch uses the regex fallback and says so.
     */
    fun redactFields(
        fields: List<Field>,
        naming: PlaceholderNaming = PlaceholderNaming(),
        regexOnly: Boolean = false,
    ): List<RedactionOutcome> {
        if (fields.isEmpty()) return emptyList()
        val prepared = fields.map(::prepare)
        val distinct = LinkedHashMap<String, Int>()
        for (p in prepared) if (p.value.isNotEmpty()) distinct.getOrPut(p.detectorText) { distinct.size }
        val texts = distinct.keys.toList()

        var usedFallback = regexOnly
        val detected: List<List<Span>> = when {
            texts.isEmpty() -> emptyList()
            regexOnly -> texts.map(fallback::detect)
            else -> try {
                detector.detect(texts)
            } catch (_: Exception) {
                usedFallback = true
                texts.map(fallback::detect)
            }
        }

        return fields.mapIndexed { i, field ->
            val p = prepared[i]
            val spans = if (p.value.isEmpty()) emptyList() else p.toValueSpans(detected[distinct.getValue(p.detectorText)])
            RedactionOutcome(replace(field.text, spans, naming), spans, usedFallback)
        }
    }

    /**
     * Ciphertext must reach the server byte for byte. Its value is masked
     * (one `x` per code point, so offsets do not move) before either detector
     * sees it, and any span is cut back to the unprotected text afterwards.
     */
    private fun prepare(field: Field): Prepared {
        val text = field.text
        val prefixLength = field.prefix.codePointCount(0, field.prefix.length)
        val protected = opaqueRanges(text)
        if (protected.isEmpty()) {
            return Prepared(text, field.prefix + text + field.suffix, prefixLength, emptyList())
        }
        val index = CodePointIndex(text)
        val masked = StringBuilder(text.length)
        var cursor = 0
        for ((start, end) in protected) {
            if (start < cursor) continue
            masked.append(text, cursor, start)
            repeat(text.codePointCount(start, end)) { masked.append('x') }
            cursor = end
        }
        masked.append(text, cursor, text.length)
        val ranges = protected.map { (start, end) -> CodePointRange(index.toCodePoint(start), index.toCodePoint(end)) }
        return Prepared(text, field.prefix + masked + field.suffix, prefixLength, ranges)
    }

    private class Prepared(
        val value: String,
        val detectorText: String,
        val prefixLength: Int,
        val protectedRanges: List<CodePointRange>,
    ) {
        /** Detector spans over prefix+value+suffix -> spans over the value alone. */
        fun toValueSpans(spans: List<Span>): List<Span> {
            val valueLength = value.codePointCount(0, value.length)
            return spans.mapNotNull { span ->
                val start = maxOf(span.start - prefixLength, 0)
                val end = minOf(span.end - prefixLength, valueLength)
                if (end > start) span.copy(start = start, end = end) else null
            }.minusRanges(protectedRanges)
        }
    }

    /**
     * Replaces spans with placeholders. Spans are code points; overlapping or
     * out-of-range spans from the service are merged and clamped rather than
     * trusted (over-redacting is recoverable, a crash here forwarded the
     * request unredacted). Placeholders are assigned left to right.
     */
    private fun replace(text: String, spans: List<Span>, naming: PlaceholderNaming): String {
        if (spans.isEmpty()) return text
        val index = CodePointIndex(text)
        val limit = index.codePointCount
        val clamped = spans.mapNotNull { span ->
            val start = span.start.coerceIn(0, limit)
            val end = span.end.coerceIn(0, limit)
            if (end > start) span.copy(start = start, end = end) else null
        }
        val out = StringBuilder(text.length)
        var cursor = 0
        for (span in mergeOverlapping(clamped)) {
            val start = index.toUtf16(span.start)
            val end = index.toUtf16(span.end)
            out.append(text, cursor, start)
            out.append(naming.placeholderFor(text.substring(start, end), span.kind))
            cursor = end
        }
        out.append(text, cursor, text.length)
        return out.toString()
    }

    companion object {
        /**
         * Ciphertext and signed protocol envelopes cannot be safely rewritten.
         * A request carrying one passes through whole (BurpExtension), except
         * on the Responses API path, which only ever rewrites user-text fields.
         */
        fun isOpaqueProtocolPayload(text: String): Boolean =
            OPAQUE_MARKER.containsMatchIn(text) || FERNET.containsMatchIn(text)

        private const val OPAQUE_NAMES =
            "encrypted(?:[_-]?(?:content|payload|data))?" +
                "|cipher(?:text|[_-]?(?:content|payload|data))?" +
                "|sealed(?:[_-]?(?:content|payload|data))?"

        /** Any JSON member named like ciphertext, whatever its value type. */
        private val OPAQUE_MARKER = Regex("(?i)\"(?:$OPAQUE_NAMES)\"\\s*:")

        /** The same member when its value is a string; the match ends at the opening quote. */
        private val OPAQUE_KEY = Regex("(?i)\"(?:$OPAQUE_NAMES)\"\\s*:\\s*\"")

        /** JSON member names (unquoted, any case) whose whole value is ciphertext. */
        internal val OPAQUE_NAME = Regex("(?i)$OPAQUE_NAMES")

        /**
         * Fernet tokens (OpenAI's encrypted reasoning items are Fernet) start
         * with version 0x80 and a zero high timestamp word: "gAAAAA". Case
         * sensitive and bounded on both sides: the old pattern carried the
         * (?i) of the key regex, so any long word starting "gaaaa" made a
         * whole request pass through unredacted.
         */
        private val FERNET = Regex("""(?<![A-Za-z0-9_-])gAAAAA[A-Za-z0-9_-]{40,}={0,2}(?![A-Za-z0-9_=-])""")

        // A base64 data URL is never text; scanning it can only corrupt it.
        private val DATA_URL = Regex("""data:[A-Za-z]+/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/=\r\n]+""")

        /**
         * UTF-16 [start, end) ranges of protected values, sorted. The JSON
         * string after an opaque key is scanned by hand: the regex this
         * replaces, `"((?:\\.|[^"\\])*)`, recursed once per character in
         * java.util.regex and threw StackOverflowError on long values.
         */
        internal fun opaqueRanges(text: String): List<Pair<Int, Int>> {
            val ranges = ArrayList<Pair<Int, Int>>()
            for (m in OPAQUE_KEY.findAll(text)) {
                val start = m.range.last + 1
                var i = start
                while (i < text.length && text[i] != '"') i += if (text[i] == '\\') 2 else 1
                ranges += start to minOf(i, text.length)
            }
            for (m in FERNET.findAll(text)) ranges += m.range.first to m.range.last + 1
            for (m in DATA_URL.findAll(text)) ranges += m.range.first to m.range.last + 1
            if (ranges.size < 2) return ranges
            ranges.sortBy { it.first }
            val merged = ArrayList<Pair<Int, Int>>(ranges.size)
            for (range in ranges) {
                val last = merged.lastOrNull()
                if (last != null && range.first <= last.second) {
                    merged[merged.size - 1] = last.first to maxOf(last.second, range.second)
                } else {
                    merged += range
                }
            }
            return merged
        }
    }
}
