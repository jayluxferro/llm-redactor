package org.llmredactor.burp

import com.github.luben.zstd.ZstdInputStream
import com.github.luben.zstd.ZstdOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.InflaterInputStream
import java.util.zip.DeflaterOutputStream

data class BodyTransform(val body: ByteArray, val detections: Int, val usedFallback: Boolean, val reason: String? = null)

/**
 * Rewrites only bodies whose encoding can be safely decoded and re-encoded.
 * JSON, XML, form, multipart text payloads and generic textual content are
 * covered by scanning their UTF-8 text; protobuf uses its own wire walker.
 */
class BodyTransformer(private val redactor: TextRedactor) {
    fun transform(body: ByteArray, contentType: String?, contentEncoding: String?): BodyTransform {
        val encoding = contentEncoding?.lowercase()?.trim().orEmpty()
        val decoded = decode(body, encoding) ?: return BodyTransform(body, 0, false, "unsupported-encoding:$encoding")
        val isProtobuf = contentType?.lowercase()?.contains("protobuf") == true
        val result = if (isProtobuf) redactProtobuf(decoded) else redactUtf8(decoded)
        if (result.reason != null) return result.copy(body = body)
        return result.copy(body = encode(result.body, encoding) ?: body)
    }

    fun transformQuery(path: String): Pair<String, Int> {
        val marker = path.indexOf('?')
        if (marker < 0) return path to 0
        val query = path.substring(marker + 1)
        var detections = 0
        val redacted = query.split('&').joinToString("&") { piece ->
            val equals = piece.indexOf('=')
            if (equals < 0) return@joinToString piece
            val value = URLDecoder.decode(piece.substring(equals + 1), StandardCharsets.UTF_8)
            val outcome = redactor.redact(value)
            detections += outcome.spans.size
            piece.substring(0, equals + 1) + URLEncoder.encode(outcome.text, StandardCharsets.UTF_8)
        }
        return path.substring(0, marker + 1) + redacted to detections
    }

    private fun redactUtf8(bytes: ByteArray): BodyTransform {
        val text = bytes.toString(StandardCharsets.UTF_8)
        // Replacement characters mean this is binary or a legacy charset; leave it alone.
        if ('\uFFFD' in text) return BodyTransform(bytes, 0, false, "non-utf8-body")
        val outcome = redactor.redact(text)
        return BodyTransform(outcome.text.toByteArray(StandardCharsets.UTF_8), outcome.spans.size, outcome.usedFallback)
    }

    /** Schema-blind protobuf walker for length-delimited fields containing valid UTF-8. */
    private fun redactProtobuf(bytes: ByteArray): BodyTransform {
        return try {
            val out = ByteArrayOutputStream()
            var cursor = 0
            var count = 0
            var fallback = false
            while (cursor < bytes.size) {
                val (tag, afterTag) = readVarint(bytes, cursor)
                val wire = (tag and 7).toInt()
                out.write(bytes, cursor, afterTag - cursor)
                cursor = afterTag
                when (wire) {
                    0 -> { val (_, next) = readVarint(bytes, cursor); out.write(bytes, cursor, next - cursor); cursor = next }
                    1 -> { require(cursor + 8 <= bytes.size); out.write(bytes, cursor, 8); cursor += 8 }
                    2 -> {
                        val (length, afterLength) = readVarint(bytes, cursor)
                        require(length <= Int.MAX_VALUE && afterLength + length.toInt() <= bytes.size)
                        val payload = bytes.copyOfRange(afterLength, afterLength + length.toInt())
                        val transformed = redactUtf8(payload)
                        val replacement = if (transformed.reason == null) transformed.body else payload
                        writeVarint(out, replacement.size.toLong())
                        out.write(replacement)
                        count += transformed.detections
                        fallback = fallback || transformed.usedFallback
                        cursor = afterLength + length.toInt()
                    }
                    5 -> { require(cursor + 4 <= bytes.size); out.write(bytes, cursor, 4); cursor += 4 }
                    else -> throw IllegalArgumentException("unknown protobuf wire type")
                }
            }
            BodyTransform(out.toByteArray(), count, fallback)
        } catch (_: Exception) {
            BodyTransform(bytes, 0, false, "invalid-protobuf")
        }
    }

    private fun readVarint(data: ByteArray, start: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var index = start
        while (index < data.size && shift < 64) {
            val value = data[index++].toInt() and 0xff
            result = result or ((value and 0x7f).toLong() shl shift)
            if (value and 0x80 == 0) return result to index
            shift += 7
        }
        throw IllegalArgumentException("truncated varint")
    }

    private fun writeVarint(out: ByteArrayOutputStream, value: Long) {
        var current = value
        while (current and -128L != 0L) {
            out.write(((current and 127L) or 128L).toInt())
            current = current ushr 7
        }
        out.write(current.toInt())
    }

    private fun decode(bytes: ByteArray, encoding: String): ByteArray? = try {
        when (encoding) {
            "", "identity" -> bytes
            "gzip" -> GZIPInputStream(ByteArrayInputStream(bytes)).readBytes()
            "deflate" -> InflaterInputStream(ByteArrayInputStream(bytes)).readBytes()
            "zstd" -> ZstdInputStream(ByteArrayInputStream(bytes)).readBytes()
            else -> null // Brotli requires a native encoder; intentionally safe pass-through.
        }
    } catch (_: Exception) { null }

    private fun encode(bytes: ByteArray, encoding: String): ByteArray? = try {
        when (encoding) {
            "", "identity" -> bytes
            "gzip" -> ByteArrayOutputStream().also { output -> GZIPOutputStream(output).use { it.write(bytes) } }.toByteArray()
            "deflate" -> ByteArrayOutputStream().also { output -> DeflaterOutputStream(output).use { it.write(bytes) } }.toByteArray()
            "zstd" -> ByteArrayOutputStream().also { output -> ZstdOutputStream(output).use { it.write(bytes) } }.toByteArray()
            else -> null
        }
    } catch (_: Exception) { null }
}
