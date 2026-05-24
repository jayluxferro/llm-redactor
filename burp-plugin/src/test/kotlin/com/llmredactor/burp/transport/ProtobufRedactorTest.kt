package com.llmredactor.burp.transport

import com.llmredactor.burp.pipeline.RedactionPipeline
import com.llmredactor.burp.redact.RedactionResult
import com.llmredactor.burp.redact.redact
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Schema-blind protobuf walker: nesting, embedded JSON, restore, depth cap, UTF-8 edge cases.
 */
class ProtobufRedactorTest {

    private val pipeline = RedactionPipeline(TestConfig.plugin())

    @Test
    fun redactsEmailInEmbeddedJsonStringField() {
        val json = """{"contact":"leak@corp.com","role":"admin"}"""
        val proto = wrapField(1, json.toByteArray(Charsets.UTF_8))
        val (out, map) = redact(proto)
        assertTrue(map.isNotEmpty())
        assertFalse(extractFirstStringField(out).contains("leak@corp.com"))
    }

    @Test
    fun redactThenRestoreRoundTrip() {
        val original = "Billing SSN 123-45-6789 on file"
        val proto = wrapField(1, original.toByteArray(Charsets.UTF_8))
        val (redacted, map) = redact(proto)
        assertTrue(map.isNotEmpty())
        val restored = ProtobufRedactor.restore(redacted, map)
        assertEquals(original, extractFirstStringField(restored))
    }

    @Test
    fun deepNestingStillRedactsWithinDepthCap() {
        var msg = wrapField(1, "notify ops@deep.test".toByteArray(Charsets.UTF_8))
        repeat(20) { msg = wrapField(1, msg) }
        val (out, map) = redact(msg)
        assertTrue(map.isNotEmpty())
        assertFalse(String(out).contains("ops@deep.test"))
    }

    @Test
    fun skipsMalformedUtf8Blob() {
        val invalid = byteArrayOf(0xC3.toByte(), 0x28.toByte()) // invalid UTF-8
        assertFalse(ProtobufTextPolicy.isValidUtf8(invalid))
        val proto = wrapField(1, invalid)
        val (out, map) = redact(proto)
        assertTrue(map.isEmpty())
        assertTrue(out.contentEquals(proto))
    }

    @Test
    fun preservesBinaryLengthDelimitedChunk() {
        val binary = ByteArray(64) { (it and 0xff).toByte() }
        val proto = wrapField(2, binary)
        val (out, map) = redact(proto)
        assertTrue(map.isEmpty())
        assertTrue(out.contentEquals(proto))
    }

    @Test
    fun processesUtf8FieldOver512Kb() {
        // Proves the walker does not skip large length-delimited fields (no 512 KB cap).
        val text = "x".repeat(513_000) + " huge@payload.test"
        val proto = wrapField(1, text.toByteArray(Charsets.UTF_8))
        val (out, map) = ProtobufRedactor.redact(proto) { body ->
            if ("huge@payload.test" in body) {
                RedactionResult(
                    redactedText = body.replace("huge@payload.test", "⟨EMAIL_1⟩"),
                    reverseMap = mapOf("⟨EMAIL_1⟩" to "huge@payload.test"),
                    placeholders = listOf("⟨EMAIL_1⟩"),
                )
            } else {
                RedactionResult(
                    redactedText = body,
                    reverseMap = emptyMap(),
                    placeholders = emptyList(),
                )
            }
        }
        assertTrue(map.isNotEmpty())
        assertFalse(String(out).contains("huge@payload.test"))
    }

    @Test
    fun redactsPackedLengthDelimitedStrings() {
        val packed = packLengthDelimited(
            "alice@a.com".toByteArray(Charsets.UTF_8),
            "bob@b.com".toByteArray(Charsets.UTF_8),
        )
        val proto = wrapField(1, packed)
        val (out, map) = redact(proto)
        assertTrue(map.isNotEmpty())
        assertFalse(String(out).contains("alice@a.com"))
        assertFalse(String(out).contains("bob@b.com"))
    }

    @Test
    fun forEachTextFieldVisitsNestedAndJson() {
        val inner = wrapField(1, """{"email":"nested@x.com"}""".toByteArray(Charsets.UTF_8))
        val outer = wrapField(1, inner)
        val seen = mutableListOf<String>()
        ProtobufRedactor.forEachTextField(outer) { seen.add(it) }
        assertTrue(seen.any { it.contains("nested@x.com") })
    }

    private fun redact(proto: ByteArray) =
        ProtobufRedactor.redact(proto) { text ->
            redact(text, pipeline.detectSpans(text), null)
        }

    private fun extractFirstStringField(proto: ByteArray): String {
        var pos = 0
        val (_, afterTag) = readVarint(proto, pos) ?: error("bad proto")
        pos = afterTag
        val (len, afterLen) = readVarint(proto, pos) ?: error("bad proto")
        pos = afterLen
        return String(proto, pos, len.toInt(), Charsets.UTF_8)
    }

    private fun packLengthDelimited(vararg elements: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (elem in elements) {
            writeVarint(out, elem.size.toLong())
            out.write(elem)
        }
        return out.toByteArray()
    }

    private fun wrapField(fieldNumber: Int, payload: ByteArray): ByteArray {
        val tag = (fieldNumber shl 3) or 2
        val out = java.io.ByteArrayOutputStream()
        writeVarint(out, tag.toLong())
        writeVarint(out, payload.size.toLong())
        out.write(payload)
        return out.toByteArray()
    }

    private fun readVarint(data: ByteArray, start: Int): Pair<Long, Int>? {
        var result = 0L
        var shift = 0
        var i = start
        while (i < data.size && shift < 64) {
            val b = data[i].toInt() and 0xFF
            result = result or ((b and 0x7F).toLong() shl shift)
            i++
            if (b and 0x80 == 0) return result to i
            shift += 7
        }
        return null
    }

    private fun writeVarint(out: java.io.ByteArrayOutputStream, value: Long) {
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
