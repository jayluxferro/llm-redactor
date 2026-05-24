package com.llmredactor.burp.transport

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class HttpBodyCompressionTest {

    @Test
    fun gzipRoundTrip() {
        val raw = "hello redactor gzip".toByteArray(Charsets.UTF_8)
        val gz = HttpBodyCompression.encode(raw, HttpBodyCompression.Kind.GZIP)
        val (decoded, kind) = HttpBodyCompression.decode(gz, "gzip")
        assertEquals(HttpBodyCompression.Kind.GZIP, kind)
        assertArrayEquals(raw, decoded)
    }

    @Test
    fun brotliRoundTrip() {
        val raw = "hello redactor brotli".toByteArray(Charsets.UTF_8)
        try {
            val br = HttpBodyCompression.encode(raw, HttpBodyCompression.Kind.BROTLI)
            val (decoded, kind) = HttpBodyCompression.decode(br, "br")
            assertEquals(HttpBodyCompression.Kind.BROTLI, kind)
            assertArrayEquals(raw, decoded)
        } catch (_: IllegalStateException) {
            // Native brotli library not on this platform — skip.
        }
    }

    @Test
    fun compressDecodeRoundTrip() {
        val raw = "hello redactor unix compress".toByteArray(Charsets.UTF_8)
        val hex = "1f9d9068cab061f306849c3264c28ca1f3460e883a6ed2e00131e64d1b3807e7cc01"
        val compressed = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val (decoded, kind) = HttpBodyCompression.decode(compressed, "compress")
        assertEquals(HttpBodyCompression.Kind.COMPRESS, kind)
        assertArrayEquals(raw, decoded)
    }

    @Test
    fun compressEncodeFallsBackToPlaintextWhenWriterUnavailable() {
        val raw = "hello".toByteArray(Charsets.UTF_8)
        val out = HttpBodyCompression.encode(raw, HttpBodyCompression.Kind.COMPRESS)
        val magic = out.size >= 2 &&
            (out[0].toInt() and 0xFF) == 0x1F &&
            (out[1].toInt() and 0xFF) == 0x9D
        if (magic) {
            val (decoded, kind) = HttpBodyCompression.decode(out, "compress")
            assertEquals(HttpBodyCompression.Kind.COMPRESS, kind)
            assertArrayEquals(raw, decoded)
        } else {
            assertArrayEquals(raw, out)
        }
    }

    @Test
    fun zstdRoundTrip() {
        val raw = "hello redactor zstd".toByteArray(Charsets.UTF_8)
        val z = HttpBodyCompression.encode(raw, HttpBodyCompression.Kind.ZSTD)
        val (decoded, kind) = HttpBodyCompression.decode(z, "zstd")
        assertEquals(HttpBodyCompression.Kind.ZSTD, kind)
        assertArrayEquals(raw, decoded)
    }
}
