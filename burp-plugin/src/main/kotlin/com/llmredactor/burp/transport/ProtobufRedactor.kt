package com.llmredactor.burp.transport

import com.llmredactor.burp.redact.RedactionResult
import com.llmredactor.burp.redact.Restorer
import java.io.ByteArrayOutputStream

/**
 * Schema-agnostic protobuf walker for length-delimited (wire type 2) payloads.
 *
 * - Recurses into nested sub-messages when the chunk is valid protobuf on the wire.
 * - Scans UTF-8 text in string/bytes fields (no per-field size cap; bounded by HTTP body).
 * - Redacts packed length-delimited repeats (proto2-style packed strings/bytes).
 * - Skips obvious binary blobs via [ProtobufTextPolicy].
 */
object ProtobufRedactor {

    /** Safety rail against pathological nesting, not a functional limit on normal RPC trees. */
    private const val MAX_NESTING_DEPTH = 64
    private const val MAX_FIELDS_PER_MESSAGE = 100_000

    fun redact(
        data: ByteArray,
        depth: Int = 0,
        transform: (String) -> RedactionResult,
    ): Pair<ByteArray, Map<String, String>> {
        val reverse = mutableMapOf<String, String>()
        val out = rewrite(data, depth) { chunk, d ->
            classifyChunk(chunk, d, transform, reverse)
        } ?: return data to emptyMap()
        return out to reverse
    }

    /** Visit every scannable UTF-8 string field without modifying the message. */
    fun forEachTextField(data: ByteArray, visit: (String) -> Unit) {
        rewrite(data, 0) { chunk, depth ->
            when {
                depth < MAX_NESTING_DEPTH && isValidProtobufMessage(chunk) -> {
                    forEachTextField(chunk, visit)
                    chunk
                }
                isTextLike(chunk) -> {
                    visit(chunk.toString(Charsets.UTF_8))
                    chunk
                }
                else -> {
                    unpackLengthDelimitedElements(chunk)?.forEach { elem ->
                        when {
                            isTextLike(elem) -> visit(elem.toString(Charsets.UTF_8))
                            depth < MAX_NESTING_DEPTH && isValidProtobufMessage(elem) ->
                                forEachTextField(elem, visit)
                        }
                    }
                    chunk
                }
            }
        }
    }

    fun restore(data: ByteArray, reverseMap: Map<String, String>): ByteArray {
        if (reverseMap.isEmpty()) return data
        return rewrite(data, 0) { chunk, depth ->
            when {
                depth < MAX_NESTING_DEPTH && isValidProtobufMessage(chunk) ->
                    restore(chunk, reverseMap)
                isTextLike(chunk) ->
                    Restorer.restore(chunk.toString(Charsets.UTF_8), reverseMap)
                        .toByteArray(Charsets.UTF_8)
                else -> {
                    tryRestorePackedLengthDelimited(chunk, depth, reverseMap) ?: chunk
                }
            }
        } ?: data
    }

    private fun classifyChunk(
        chunk: ByteArray,
        depth: Int,
        transform: (String) -> RedactionResult,
        reverse: MutableMap<String, String>,
    ): ByteArray {
        return when {
            depth < MAX_NESTING_DEPTH && isValidProtobufMessage(chunk) -> {
                val (nested, m) = redact(chunk, depth + 1, transform)
                reverse.putAll(m)
                nested
            }
            isTextLike(chunk) -> redactUtf8Chunk(chunk, transform, reverse)
            else -> tryRedactPackedLengthDelimited(chunk, depth, transform, reverse) ?: chunk
        }
    }

    private fun redactUtf8Chunk(
        chunk: ByteArray,
        transform: (String) -> RedactionResult,
        reverse: MutableMap<String, String>,
    ): ByteArray {
        val r = transform(chunk.toString(Charsets.UTF_8))
        reverse.putAll(r.reverseMap)
        return r.redactedText.toByteArray(Charsets.UTF_8)
    }

    /**
     * Proto2 packed repeated length-delimited elements: [len][bytes][len][bytes]…
     */
    private fun tryRedactPackedLengthDelimited(
        chunk: ByteArray,
        depth: Int,
        transform: (String) -> RedactionResult,
        reverse: MutableMap<String, String>,
    ): ByteArray? {
        val elements = unpackLengthDelimitedElements(chunk) ?: return null
        if (elements.size < 2) return null
        if (elements.any { elem ->
                !isTextLike(elem) && !(depth < MAX_NESTING_DEPTH && isValidProtobufMessage(elem))
            }) {
            return null
        }
        var changed = false
        val out = ByteArrayOutputStream(chunk.size)
        for (elem in elements) {
            val processed = classifyChunk(elem, depth, transform, reverse)
            if (!processed.contentEquals(elem)) changed = true
            writeVarint(out, processed.size.toLong())
            out.write(processed)
        }
        return if (changed) out.toByteArray() else null
    }

    private fun tryRestorePackedLengthDelimited(
        chunk: ByteArray,
        depth: Int,
        reverseMap: Map<String, String>,
    ): ByteArray? {
        val elements = unpackLengthDelimitedElements(chunk) ?: return null
        if (elements.size < 2) return null
        var changed = false
        val out = ByteArrayOutputStream(chunk.size)
        for (elem in elements) {
            val processed = when {
                depth < MAX_NESTING_DEPTH && isValidProtobufMessage(elem) ->
                    restore(elem, reverseMap)
                isTextLike(elem) ->
                    Restorer.restore(elem.toString(Charsets.UTF_8), reverseMap)
                        .toByteArray(Charsets.UTF_8)
                else -> elem
            }
            if (!processed.contentEquals(elem)) changed = true
            writeVarint(out, processed.size.toLong())
            out.write(processed)
        }
        return if (changed) out.toByteArray() else null
    }

    private fun unpackLengthDelimitedElements(chunk: ByteArray): List<ByteArray>? {
        var pos = 0
        val list = mutableListOf<ByteArray>()
        while (pos < chunk.size) {
            val lenRead = readVarint(chunk, pos) ?: return null
            if (lenRead.value < 0 || lenRead.value > Int.MAX_VALUE - 8) return null
            val len = lenRead.value.toInt()
            pos = lenRead.next
            if (pos + len > chunk.size) return null
            list.add(chunk.copyOfRange(pos, pos + len))
            pos += len
        }
        if (list.size < 2 || pos != chunk.size) return null
        return list
    }

    private fun rewrite(
        data: ByteArray,
        depth: Int,
        mapChunk: (ByteArray, Int) -> ByteArray,
    ): ByteArray? {
        val out = ByteArrayOutputStream(data.size)
        var pos = 0
        while (pos < data.size) {
            val tagRead = readVarint(data, pos) ?: return null
            val tag = tagRead.value
            pos = tagRead.next
            val wireType = (tag and 7).toInt()
            writeVarint(out, tag)
            when (wireType) {
                0 -> {
                    val v = readVarint(data, pos) ?: return null
                    writeVarint(out, v.value)
                    pos = v.next
                }
                1 -> {
                    if (pos + 8 > data.size) return null
                    out.write(data, pos, 8)
                    pos += 8
                }
                2 -> {
                    val lenRead = readVarint(data, pos) ?: return null
                    if (lenRead.value < 0 || lenRead.value > Int.MAX_VALUE - 8) return null
                    val len = lenRead.value.toInt()
                    pos = lenRead.next
                    if (pos + len > data.size) return null
                    val chunk = data.copyOfRange(pos, pos + len)
                    pos += len
                    val processed = mapChunk(chunk, depth)
                    writeVarint(out, processed.size.toLong())
                    out.write(processed)
                }
                5 -> {
                    if (pos + 4 > data.size) return null
                    out.write(data, pos, 4)
                    pos += 4
                }
                else -> return null
            }
        }
        return out.toByteArray()
    }

    /**
     * True when [b] is a complete protobuf message (parses to EOF with known wire types).
     */
    internal fun isValidProtobufMessage(b: ByteArray): Boolean {
        if (b.isEmpty()) return false
        var pos = 0
        var fields = 0
        while (pos < b.size) {
            val tagRead = readVarint(b, pos) ?: return false
            if (tagRead.value == 0L) return false
            pos = tagRead.next
            val wireType = (tagRead.value and 7).toInt()
            pos = skipValue(b, pos, wireType) ?: return false
            fields++
            if (fields > MAX_FIELDS_PER_MESSAGE) return false
        }
        return fields > 0
    }

    private fun skipValue(data: ByteArray, pos: Int, wireType: Int): Int? {
        return when (wireType) {
            0 -> readVarint(data, pos)?.next
            1 -> if (pos + 8 <= data.size) pos + 8 else null
            2 -> {
                val lenRead = readVarint(data, pos) ?: return null
                if (lenRead.value < 0 || lenRead.value > Int.MAX_VALUE - 8) return null
                val len = lenRead.value.toInt()
                val next = lenRead.next + len
                if (next > data.size) return null
                next
            }
            5 -> if (pos + 4 <= data.size) pos + 4 else null
            else -> null
        }
    }

    private fun isTextLike(b: ByteArray): Boolean {
        if (b.isEmpty()) return false
        if (isValidProtobufMessage(b)) return false
        if (!ProtobufTextPolicy.isValidUtf8(b)) return false
        val text = b.toString(Charsets.UTF_8)
        return ProtobufTextPolicy.shouldScanUtf8String(text)
    }

    private data class VarintRead(val value: Long, val next: Int)

    private fun readVarint(data: ByteArray, start: Int): VarintRead? {
        var result = 0L
        var shift = 0
        var i = start
        while (i < data.size && shift < 64) {
            val b = data[i].toInt() and 0xFF
            result = result or ((b and 0x7F).toLong() shl shift)
            i++
            if (b and 0x80 == 0) return VarintRead(result, i)
            shift += 7
        }
        return null
    }

    private fun writeVarint(out: ByteArrayOutputStream, value: Long) {
        var v = value
        while (true) {
            if (v and 0x7F.inv().toLong() == 0L) {
                out.write(v.toInt())
                return
            }
            out.write(((v and 0x7F) or 0x80).toInt())
            v = v ushr 7
        }
    }
}
