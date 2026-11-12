package org.llmredactor.burp

/**
 * Converts between UTF-16 indices (JVM strings and regex match ranges) and
 * code-point offsets, the unit of every [Span]: the Python detector counts
 * code points, so the fallback and the replacement code must too. Text with
 * no surrogate pairs (nearly all of it) needs no tables.
 */
internal class CodePointIndex(text: String) {
    private val codePointOf: IntArray?
    private val utf16Of: IntArray?
    val codePointCount: Int

    init {
        if (text.none(Character::isSurrogate)) {
            codePointOf = null
            utf16Of = null
            codePointCount = text.length
        } else {
            val count = text.codePointCount(0, text.length)
            val toCodePoint = IntArray(text.length + 1)
            val toUtf16 = IntArray(count + 1)
            var codePoint = 0
            var index = 0
            while (index < text.length) {
                toUtf16[codePoint] = index
                val width = Character.charCount(text.codePointAt(index))
                for (k in 0 until width) toCodePoint[index + k] = codePoint
                index += width
                codePoint++
            }
            toCodePoint[text.length] = count
            toUtf16[count] = text.length
            codePointOf = toCodePoint
            utf16Of = toUtf16
            codePointCount = count
        }
    }

    fun toCodePoint(utf16: Int): Int = codePointOf?.get(utf16) ?: utf16

    fun toUtf16(codePoint: Int): Int = utf16Of?.get(codePoint) ?: codePoint
}

/**
 * Overlapping spans become one span over their union, exactly as the Python
 * orchestrator's `_merge_overlapping` does: sorted by start then longest,
 * labelled by the most confident member (ties keep the earlier one, so the
 * order spans were produced in decides between equal candidates). Keeping
 * only the "winning" span, as this file once did, left whatever only the
 * losers covered in the clear.
 */
internal fun mergeOverlapping(spans: List<Span>): List<Span> {
    val valid = spans.filter { it.end > it.start && it.start >= 0 }
    if (valid.isEmpty()) return emptyList()
    val sorted = valid.sortedWith(compareBy<Span> { it.start }.thenByDescending { it.end - it.start })
    val merged = ArrayList<Span>(sorted.size)
    merged += sorted[0]
    for (span in sorted.subList(1, sorted.size)) {
        val previous = merged.last()
        if (span.start >= previous.end) {
            merged += span
            continue
        }
        val label = if (span.confidence > previous.confidence) span else previous
        merged[merged.size - 1] = label.copy(start = previous.start, end = maxOf(previous.end, span.end))
    }
    return merged
}

/** A half-open range of code points. */
internal data class CodePointRange(val start: Int, val end: Int)

/**
 * Cuts [ranges] out of every span. A span that straddles a protected range is
 * split around it rather than dropped: dropping it (the old behaviour) left the
 * unprotected part of, say, an NER span over "name + ciphertext" unredacted.
 */
internal fun List<Span>.minusRanges(ranges: List<CodePointRange>): List<Span> {
    if (ranges.isEmpty()) return this
    val sortedRanges = ranges.sortedBy { it.start }
    val out = ArrayList<Span>(size)
    for (span in this) {
        var cursor = span.start
        for (range in sortedRanges) {
            if (range.end <= cursor || range.start >= span.end) continue
            if (range.start > cursor) out += span.copy(start = cursor, end = range.start)
            cursor = maxOf(cursor, range.end)
            if (cursor >= span.end) break
        }
        if (cursor < span.end) out += span.copy(start = cursor, end = span.end)
    }
    return out
}
