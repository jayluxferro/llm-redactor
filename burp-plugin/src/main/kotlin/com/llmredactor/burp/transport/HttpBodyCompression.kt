package com.llmredactor.burp.transport

import com.aayushatharva.brotli4j.Brotli4jLoader
import com.aayushatharva.brotli4j.decoder.BrotliInputStream
import com.aayushatharva.brotli4j.encoder.BrotliOutputStream
import com.aayushatharva.brotli4j.encoder.Encoder
import com.github.luben.zstd.Zstd
import org.apache.commons.compress.compressors.CompressorStreamFactory
import org.apache.commons.compress.compressors.z.ZCompressorInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.DeflaterOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.InflaterInputStream

/**
 * HTTP Content-Encoding decode/encode for LLM request/response bodies.
 */
object HttpBodyCompression {

    enum class Kind { IDENTITY, GZIP, DEFLATE, BROTLI, ZSTD, COMPRESS }

    private var brotliReady: Boolean? = null

    private fun ensureBrotli(): Boolean {
        brotliReady?.let { return it }
        val ok = try {
            Brotli4jLoader.ensureAvailability()
            true
        } catch (_: Exception) {
            false
        }
        brotliReady = ok
        return ok
    }

    fun primaryEncoding(contentEncodingHeader: String): Kind {
        val token = contentEncodingHeader.trim().lowercase()
            .split(",")
            .firstOrNull()
            ?.trim()
            ?.substringBefore(";")
            ?.trim()
            ?: return Kind.IDENTITY
        return when (token) {
            "gzip", "x-gzip" -> Kind.GZIP
            "deflate" -> Kind.DEFLATE
            "br" -> Kind.BROTLI
            "zstd" -> Kind.ZSTD
            "compress", "x-compress" -> Kind.COMPRESS
            "identity", "" -> Kind.IDENTITY
            else -> Kind.IDENTITY
        }
    }

    fun isSupported(kind: Kind): Boolean =
        kind in setOf(Kind.IDENTITY, Kind.GZIP, Kind.DEFLATE, Kind.BROTLI, Kind.ZSTD, Kind.COMPRESS)

    fun decode(raw: ByteArray, contentEncodingHeader: String): Pair<ByteArray, Kind> {
        val gzipMagic = raw.size >= 2 &&
            (raw[0].toInt() and 0xFF) == 0x1F &&
            (raw[1].toInt() and 0xFF) == 0x8B
        val compressMagic = raw.size >= 2 &&
            (raw[0].toInt() and 0xFF) == 0x1F &&
            (raw[1].toInt() and 0xFF) == 0x9D
        val kind = when {
            gzipMagic -> Kind.GZIP
            compressMagic -> Kind.COMPRESS
            else -> primaryEncoding(contentEncodingHeader)
        }
        return try {
            val decoded = when (kind) {
                Kind.GZIP -> gunzip(raw)
                Kind.DEFLATE -> InflaterInputStream(ByteArrayInputStream(raw)).use { it.readBytes() }
                Kind.BROTLI -> if (ensureBrotli()) {
                    BrotliInputStream(ByteArrayInputStream(raw)).use { it.readBytes() }
                } else {
                    throw IllegalStateException("brotli native library unavailable")
                }
                Kind.ZSTD -> {
                    val size = Zstd.decompressedSize(raw)
                    val outLen = if (size > 0) size else (raw.size * 4).toLong()
                    Zstd.decompress(raw, outLen.toInt())
                }
                Kind.COMPRESS -> ZCompressorInputStream(ByteArrayInputStream(raw)).use { it.readBytes() }
                Kind.IDENTITY -> raw
            }
            Pair(decoded, kind)
        } catch (_: Exception) {
            Pair(raw, Kind.IDENTITY)
        }
    }

    fun encode(inner: ByteArray, kind: Kind): ByteArray =
        encodeWithKind(inner, kind).first

    /**
     * Encode body bytes. Unix `compress` has no writer in commons-compress 1.27 — when
     * re-encoding fails, returns plaintext and [Kind.IDENTITY] so callers strip the header.
     */
    fun encodeWithKind(inner: ByteArray, kind: Kind): Pair<ByteArray, Kind> =
        try {
            when (kind) {
                Kind.GZIP -> gzip(inner) to Kind.GZIP
                Kind.DEFLATE -> deflate(inner) to Kind.DEFLATE
                Kind.BROTLI -> brotli(inner) to Kind.BROTLI
                Kind.ZSTD -> Zstd.compress(inner) to Kind.ZSTD
                Kind.COMPRESS -> {
                    val baos = ByteArrayOutputStream(inner.size)
                    CompressorStreamFactory.getSingleton()
                        .createCompressorOutputStream(CompressorStreamFactory.Z, baos)
                        .use { it.write(inner) }
                    val out = baos.toByteArray()
                    if (hasUnixCompressMagic(out)) out to Kind.COMPRESS else inner to Kind.IDENTITY
                }
                Kind.IDENTITY -> inner to Kind.IDENTITY
            }
        } catch (_: Exception) {
            inner to Kind.IDENTITY
        }

    internal fun hasUnixCompressMagic(b: ByteArray): Boolean =
        b.size >= 2 &&
            (b[0].toInt() and 0xFF) == 0x1F &&
            (b[1].toInt() and 0xFF) == 0x9D

    private fun gunzip(data: ByteArray): ByteArray =
        GZIPInputStream(ByteArrayInputStream(data)).use { it.readBytes() }

    private fun gzip(data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream(data.size)
        GZIPOutputStream(baos).use { it.write(data) }
        return baos.toByteArray()
    }

    private fun deflate(data: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream(data.size)
        DeflaterOutputStream(baos).use { it.write(data) }
        return baos.toByteArray()
    }

    private fun brotli(data: ByteArray): ByteArray {
        if (!ensureBrotli()) throw IllegalStateException("brotli native library unavailable")
        val baos = ByteArrayOutputStream(data.size)
        BrotliOutputStream(baos, Encoder.Parameters.DEFAULT).use { it.write(data) }
        return baos.toByteArray()
    }
}
