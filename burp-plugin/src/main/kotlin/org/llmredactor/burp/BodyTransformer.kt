package org.llmredactor.burp

import com.github.luben.zstd.ZstdInputStream
import com.github.luben.zstd.ZstdOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.InflaterInputStream
import java.util.zip.DeflaterOutputStream

data class BodyTransform(val body: ByteArray, val detections: Int, val usedFallback: Boolean, val reason: String? = null)

/**
 * Rewrites only bodies whose encoding can be safely decoded and re-encoded.
 * JSON, XML, form, multipart text payloads and generic textual content are
 * covered by scanning their UTF-8 text; protobuf uses its own wire walker. JPEG
 * and PNG request bodies use the optional local ONNX image-redaction endpoint.
 */
class BodyTransformer(
    private val redactor: TextRedactor,
    private val imageRedactor: ImageRedactor = LocalImageRedactor(),
) {
    fun transform(body: ByteArray, contentType: String?, contentEncoding: String?): BodyTransform {
        val encoding = contentEncoding?.lowercase()?.trim().orEmpty()
        val decoded = decode(body, encoding) ?: return BodyTransform(body, 0, false, "unsupported-encoding:$encoding")
        val mediaType = contentType?.substringBefore(';')?.lowercase()?.trim().orEmpty()
        if (mediaType in IMAGE_TYPES) return redactImage(body, decoded, mediaType, encoding)
        val isProtobuf = mediaType.contains("protobuf")
        val result = if (isProtobuf) redactProtobuf(decoded) else redactUtf8(decoded)
        if (result.reason != null) return result.copy(body = body)
        return result.copy(body = encode(result.body, encoding) ?: body)
    }

    private fun redactImage(
        original: ByteArray,
        decoded: ByteArray,
        mediaType: String,
        encoding: String,
    ): BodyTransform {
        if (!hasImageSignature(decoded, mediaType)) {
            return BodyTransform(original, 0, false, "invalid-image-body")
        }
        return try {
            val result = imageRedactor.redact(decoded, mediaType)
            val encoded = encode(result.body, encoding)
            if (encoded == null) BodyTransform(original, 0, false, "unsupported-encoding:$encoding")
            else BodyTransform(encoded, result.detections, false)
        } catch (_: Exception) {
            BodyTransform(original, 0, false, "image-redactor-unavailable")
        }
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

    fun isOpaqueProtocolPayload(body: ByteArray): Boolean {
        val text = body.toString(StandardCharsets.UTF_8)
        return '\uFFFD' !in text && TextRedactor.isOpaqueProtocolPayload(text)
    }

    private fun redactUtf8(bytes: ByteArray): BodyTransform {
        val text = bytes.toString(StandardCharsets.UTF_8)
        // Replacement characters mean this is binary or a legacy charset; leave it alone.
        if ('\uFFFD' in text) return BodyTransform(bytes, 0, false, "non-utf8-body")
        val embedded = redactEmbeddedImages(text)
        val outcome = redactor.redact(embedded.text)
        return BodyTransform(
            outcome.text.toByteArray(StandardCharsets.UTF_8),
            outcome.spans.size + embedded.detections,
            outcome.usedFallback,
        )
    }

    /** Redact inline data-URL image attachments before scanning the surrounding text. */
    private fun redactEmbeddedImages(text: String): EmbeddedImageTransform {
        var output = text
        var detections = 0
        dataImageUrl.findAll(text).toList().asReversed().forEach { match ->
            val mediaType = match.groups[1]!!.value.lowercase()
            val encoded = match.groups[2]!!.value.replace(Regex("\\s"), "")
            val replacement = try {
                val source = Base64.getDecoder().decode(encoded)
                if (!hasImageSignature(source, mediaType)) return@forEach
                val result = imageRedactor.redact(source, mediaType)
                detections += result.detections
                "data:$mediaType;base64," + Base64.getEncoder().encodeToString(result.body)
            } catch (_: Exception) {
                return@forEach
            }
            output = output.substring(0, match.range.first) + replacement + output.substring(match.range.last + 1)
        }
        return EmbeddedImageTransform(output, detections)
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

    private companion object {
        val IMAGE_TYPES = setOf("image/jpeg", "image/png")
        val dataImageUrl = Regex("""data:(image/(?:png|jpeg));base64,([A-Za-z0-9+/=\r\n]+)""")

        fun hasImageSignature(bytes: ByteArray, mediaType: String): Boolean = when (mediaType) {
            "image/png" -> bytes.size >= 8 && bytes.copyOfRange(0, 8).contentEquals(
                byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
            )
            "image/jpeg" -> bytes.size >= 3 && bytes[0] == 0xff.toByte() &&
                bytes[1] == 0xd8.toByte() && bytes[2] == 0xff.toByte()
            else -> false
        }
    }

    private data class EmbeddedImageTransform(val text: String, val detections: Int)
}
