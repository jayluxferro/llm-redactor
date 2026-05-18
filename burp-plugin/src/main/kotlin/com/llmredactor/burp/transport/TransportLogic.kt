package com.llmredactor.burp.transport

import com.llmredactor.burp.redact.Restorer
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.DeflaterOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.InflaterInputStream

/**
 * Pure request/response body transforms (no Burp API). Unit-tested for HTTP/1,
 * HTTP/2 framing pitfalls (Content-Length), gzip/deflate, JSON, and SSE.
 */
object TransportLogic {

    data class DecodedBody(
        val text: String,
        val wasCompressed: Boolean,
        val compression: Compression,
        val httpKind: HttpBodyCompression.Kind = HttpBodyCompression.Kind.IDENTITY,
    )

    enum class Compression { NONE, GZIP, DEFLATE, BROTLI, ZSTD, COMPRESS }

    data class EncodedBody(
        val bytes: ByteArray,
        /** Remove Content-Encoding on the wire (body is plaintext). */
        val stripContentEncoding: Boolean,
    )

    /** Skip encodings we cannot decode/re-encode. */
    fun isUnsupportedRequestContentEncoding(ce: String): Boolean {
        val v = ce.trim().lowercase()
        if (v.isEmpty() || v == "identity") return false
        return v.split(",").any { part ->
            val token = part.trim().substringBefore(";").trim()
            when (token) {
                "", "identity", "gzip", "x-gzip", "deflate", "br", "zstd", "compress", "x-compress" -> false
                else -> true
            }
        }
    }

    fun decodeResponseBody(rawBytes: ByteArray, contentEncoding: String): DecodedBody {
        val (decoded, kind) = HttpBodyCompression.decode(rawBytes, contentEncoding)
        val compression = when (kind) {
            HttpBodyCompression.Kind.GZIP -> Compression.GZIP
            HttpBodyCompression.Kind.DEFLATE -> Compression.DEFLATE
            HttpBodyCompression.Kind.BROTLI -> Compression.BROTLI
            HttpBodyCompression.Kind.ZSTD -> Compression.ZSTD
            HttpBodyCompression.Kind.COMPRESS -> Compression.COMPRESS
            HttpBodyCompression.Kind.IDENTITY -> Compression.NONE
        }
        return DecodedBody(
            text = String(decoded, Charsets.UTF_8),
            wasCompressed = kind != HttpBodyCompression.Kind.IDENTITY,
            compression = compression,
            httpKind = kind,
        )
    }

    fun encodeResponseBody(
        plaintext: String,
        decoded: DecodedBody,
        contentEncodingHeader: String,
    ): EncodedBody {
        val utf8 = plaintext.toByteArray(Charsets.UTF_8)
        val ce = contentEncodingHeader.trim().lowercase()
        if (!decoded.wasCompressed) {
            return EncodedBody(utf8, stripContentEncoding = ce.isNotEmpty() && ce != "identity")
        }
        val bytes = when (decoded.httpKind) {
            HttpBodyCompression.Kind.GZIP -> gzipBytes(utf8)
            HttpBodyCompression.Kind.DEFLATE -> deflateBytes(utf8)
            HttpBodyCompression.Kind.BROTLI -> HttpBodyCompression.encode(utf8, HttpBodyCompression.Kind.BROTLI)
            HttpBodyCompression.Kind.ZSTD -> HttpBodyCompression.encode(utf8, HttpBodyCompression.Kind.ZSTD)
            HttpBodyCompression.Kind.COMPRESS -> HttpBodyCompression.encode(utf8, HttpBodyCompression.Kind.COMPRESS)
            HttpBodyCompression.Kind.IDENTITY -> utf8
        }
        return EncodedBody(bytes, stripContentEncoding = false)
    }

    fun restoreJsonBody(body: String, map: Map<String, String>): String {
        val obj = JSONObject(body)
        obj.optJSONArray("choices")?.let { choices ->
            for (i in 0 until choices.length()) {
                choices.getJSONObject(i).optJSONObject("message")?.let { msg ->
                    msg.optString("content", null)
                        ?.let { msg.put("content", Restorer.restore(it, map)) }
                }
            }
            return obj.toString()
        }
        obj.optJSONArray("content")?.let { content ->
            for (i in 0 until content.length()) {
                val blk = content.getJSONObject(i)
                if (blk.optString("type") == "text") {
                    blk.optString("text", null)
                        ?.let { blk.put("text", Restorer.restore(it, map)) }
                }
            }
            return obj.toString()
        }
        return body
    }

    /**
     * SSE placeholder restoration with LCP (mirrors Python http_proxy.py).
     * Resets accumulation when OpenAI choice index changes.
     */
    fun restoreSseBody(body: String, map: Map<String, String>): String {
        val out = StringBuilder()
        var accumulated = ""
        var prevRestored = ""
        var lastChoiceIndex: Int? = null

        fun applyLcp(piece: String): String {
            accumulated += piece
            val newRestored = Restorer.restore(accumulated, map)
            var lcp = 0
            val lim = minOf(prevRestored.length, newRestored.length)
            while (lcp < lim && prevRestored[lcp] == newRestored[lcp]) lcp++
            prevRestored = newRestored
            return newRestored.substring(lcp)
        }

        for (line in body.split("\n")) {
            if (!line.startsWith("data: ")) {
                if (out.isNotEmpty()) out.append('\n')
                out.append(line)
                continue
            }
            val data = line.removePrefix("data: ").trim()
            if (data == "[DONE]") {
                if (out.isNotEmpty()) out.append('\n')
                out.append(line)
                continue
            }
            try {
                val event = JSONObject(data)
                when {
                    event.has("choices") -> {
                        event.optJSONArray("choices")?.let { choices ->
                            for (i in 0 until choices.length()) {
                                val choice = choices.getJSONObject(i)
                                val idx = choice.optInt("index", i)
                                if (lastChoiceIndex != null && idx != lastChoiceIndex) {
                                    accumulated = ""
                                    prevRestored = ""
                                }
                                lastChoiceIndex = idx
                                val delta = choice.optJSONObject("delta") ?: continue
                                val piece = delta.optString("content", null) ?: continue
                                delta.put("content", applyLcp(piece))
                            }
                        }
                    }
                    event.optString("type") == "content_block_delta" -> {
                        event.optJSONObject("delta")?.let { delta ->
                            if (delta.optString("type") == "text_delta") {
                                val piece = delta.optString("text", null)
                                if (piece != null) delta.put("text", applyLcp(piece))
                            }
                        }
                    }
                }
                if (out.isNotEmpty()) out.append('\n')
                out.append("data: $event")
            } catch (_: Exception) {
                if (out.isNotEmpty()) out.append('\n')
                out.append(line)
            }
        }
        return out.toString()
    }

    /**
     * org.json emits CESU-8 surrogate escapes; Python json.loads rejects them.
     */
    fun fixSurrogates(json: String): String {
        val sb = StringBuilder(json.length)
        var i = 0
        while (i < json.length) {
            if (i + 5 < json.length && json[i] == '\\' && json[i + 1] == 'u') {
                val high = json.substring(i + 2, i + 6).toIntOrNull(16)
                if (high != null && high in 0xD800..0xDBFF && i + 11 < json.length &&
                    json[i + 6] == '\\' && json[i + 7] == 'u') {
                    val low = json.substring(i + 8, i + 12).toIntOrNull(16)
                    if (low != null && low in 0xDC00..0xDFFF) {
                        val cp = 0x10000 + (high - 0xD800) * 0x400 + (low - 0xDC00)
                        sb.appendCodePoint(cp)
                        i += 12
                        continue
                    }
                }
            }
            sb.append(json[i])
            i++
        }
        return sb.toString()
    }

    fun scanForCesu8(b: ByteArray): Int {
        var i = 0
        while (i < b.size - 2) {
            if ((b[i].toInt() and 0xFF) == 0xED) {
                val b1 = b[i + 1].toInt() and 0xFF
                if (b1 in 0xA0..0xBF) return i
            }
            i++
        }
        return -1
    }

    fun gzipBytes(data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream(data.size)
        GZIPOutputStream(baos).use { it.write(data) }
        return baos.toByteArray()
    }

    fun deflateBytes(data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream(data.size)
        DeflaterOutputStream(baos).use { it.write(data) }
        return baos.toByteArray()
    }

    fun looksDeflate(b: ByteArray): Boolean =
        b.size >= 2 && (b[0].toInt() and 0xFF) == 0x78 &&
            ((b[1].toInt() and 0xFF) in listOf(0x01, 0x5E, 0x9C, 0xDA))
}
