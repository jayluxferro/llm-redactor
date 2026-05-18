package com.llmredactor.burp.transport

import java.io.ByteArrayOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * Connect-RPC binary framing (flags + 4-byte big-endian length + payload).
 *
 * Unary calls often send raw protobuf (no envelope). Streaming may send one or
 * more envelopes. Flags 0x01–0x03 indicate gzip-compressed payload bytes.
 */
object ConnectProtoCodec {

    data class Frame(val flags: Int, val payload: ByteArray)

    data class WireMessage(
        val frames: List<Frame>,
        /** True when the HTTP body was a single raw protobuf blob (no Connect envelope). */
        val rawProto: Boolean,
    )

    data class HttpBody(
        val bytes: ByteArray,
        val httpContentEncoding: HttpCompression,
    )

    enum class HttpCompression { IDENTITY, GZIP, DEFLATE, BROTLI, ZSTD, COMPRESS }

    fun decodeHttpBody(raw: ByteArray, contentEncodingHeader: String): HttpBody {
        val (decoded, kind) = HttpBodyCompression.decode(raw, contentEncodingHeader)
        return HttpBody(decoded, toCodecKind(kind))
    }

    fun encodeHttpBody(inner: ByteArray, httpCompression: HttpCompression): HttpBody {
        val requested = toCompressionKind(httpCompression)
        val (bytes, actual) = HttpBodyCompression.encodeWithKind(inner, requested)
        return HttpBody(bytes, toCodecKind(actual))
    }

    private fun toCodecKind(kind: HttpBodyCompression.Kind): HttpCompression =
        when (kind) {
            HttpBodyCompression.Kind.GZIP -> HttpCompression.GZIP
            HttpBodyCompression.Kind.DEFLATE -> HttpCompression.DEFLATE
            HttpBodyCompression.Kind.BROTLI -> HttpCompression.BROTLI
            HttpBodyCompression.Kind.ZSTD -> HttpCompression.ZSTD
            HttpBodyCompression.Kind.COMPRESS -> HttpCompression.COMPRESS
            HttpBodyCompression.Kind.IDENTITY -> HttpCompression.IDENTITY
        }

    private fun toCompressionKind(kind: HttpCompression): HttpBodyCompression.Kind =
        when (kind) {
            HttpCompression.GZIP -> HttpBodyCompression.Kind.GZIP
            HttpCompression.DEFLATE -> HttpBodyCompression.Kind.DEFLATE
            HttpCompression.BROTLI -> HttpBodyCompression.Kind.BROTLI
            HttpCompression.ZSTD -> HttpBodyCompression.Kind.ZSTD
            HttpCompression.COMPRESS -> HttpBodyCompression.Kind.COMPRESS
            HttpCompression.IDENTITY -> HttpBodyCompression.Kind.IDENTITY
        }

    fun parse(body: ByteArray): WireMessage {
        val frames = mutableListOf<Frame>()
        var offset = 0
        while (offset + 5 <= body.size) {
            val flags = body[offset].toInt() and 0xFF
            if (flags !in 0..3) break
            val len = readUint32Be(body, offset + 1)
            if (len < 0 || offset + 5 + len > body.size) break
            var payload = body.copyOfRange(offset + 5, offset + 5 + len)
            payload = decompressFrame(flags, payload)
            frames.add(Frame(flags, payload))
            offset += 5 + len
        }
        if (frames.isNotEmpty()) return WireMessage(frames, rawProto = false)
        return WireMessage(listOf(Frame(0, body)), rawProto = true)
    }

    fun serialize(wire: WireMessage): ByteArray {
        if (wire.rawProto && wire.frames.size == 1 && wire.frames[0].flags == 0) {
            return wire.frames[0].payload
        }
        val out = ByteArrayOutputStream()
        for (frame in wire.frames) {
            val (flags, payload) = compressFrame(frame.flags, frame.payload)
            out.write(flags)
            writeUint32Be(out, payload.size)
            out.write(payload)
        }
        return out.toByteArray()
    }

    fun redactPayloads(
        wire: WireMessage,
        transform: (ByteArray) -> Pair<ByteArray, Map<String, String>>,
    ): Pair<WireMessage, Map<String, String>> {
        val combined = mutableMapOf<String, String>()
        val frames = wire.frames.map { frame ->
            val (payload, map) = transform(frame.payload)
            combined.putAll(map)
            Frame(frame.flags, payload)
        }
        return WireMessage(frames, wire.rawProto) to combined
    }

    private fun decompressFrame(flags: Int, payload: ByteArray): ByteArray =
        if (flags in 1..3) gunzip(payload) else payload

    private fun compressFrame(originalFlags: Int, payload: ByteArray): Pair<Int, ByteArray> =
        if (originalFlags in 1..3) 1 to gzip(payload) else originalFlags to payload

    private fun tryGunzip(data: ByteArray): ByteArray =
        try {
            gunzip(data)
        } catch (_: Exception) {
            data
        }

    private fun gunzip(data: ByteArray): ByteArray =
        GZIPInputStream(data.inputStream()).use { it.readBytes() }

    private fun gzip(data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream(data.size)
        GZIPOutputStream(baos).use { it.write(data) }
        return baos.toByteArray()
    }

    private fun readUint32Be(b: ByteArray, offset: Int): Int =
        ((b[offset].toInt() and 0xFF) shl 24) or
            ((b[offset + 1].toInt() and 0xFF) shl 16) or
            ((b[offset + 2].toInt() and 0xFF) shl 8) or
            (b[offset + 3].toInt() and 0xFF)

    private fun writeUint32Be(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 24) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }
}
