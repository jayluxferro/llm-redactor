package com.llmredactor.burp.transport

import com.llmredactor.burp.detect.Span
import com.llmredactor.burp.pipeline.RedactionPipeline
import com.llmredactor.burp.redact.redact
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

class ConnectProtoTest {

    /** From proxy-atlas txn_ad101fa2a6efbc2f5c0261f1 (NameAgent request). */
    private val nameAgentReq = Base64.getDecoder().decode("Chp3aHkgYSBjaGVzcyBnYW1lIGluIHB5dGhvbg==")

  private val nameAgentResp = Base64.getDecoder().decode("CgxQeXRob24gQ2hlc3M=")

    @Test
    fun parseUnaryRawProtobuf() {
        val wire = ConnectProtoCodec.parse(nameAgentReq)
        assertTrue(wire.rawProto)
        assertEquals(1, wire.frames.size)
    }

    @Test
    fun redactEmailInProtobufRequest() {
        val pipeline = RedactionPipeline(TestConfig.plugin())
        val email = "jane@example.com"
        val reqWithPii = buildStringFieldProto("Contact $email for info")

        val outcome = BodyProcessor.redactRequest(
            reqWithPii,
            BodyFormat.CONNECT_PROTO,
            "",
            pipeline,
            null,
        )
        assertTrue(outcome != null && outcome.reverseMap.isNotEmpty())
        val wire = ConnectProtoCodec.parse(outcome!!.bytes)
        assertFalse(String(wire.frames[0].payload).contains(email))
    }

    @Test
    fun protobufRedactPreservesStructure() {
        val pipeline = RedactionPipeline(TestConfig.plugin())
        val req = buildStringFieldProto("SSN 123-45-6789 in text")
        val (out, map) = ProtobufRedactor.redact(req) { text ->
            redact(text, pipeline.detectSpans(text), null)
        }
        assertTrue(map.isNotEmpty())
        assertTrue(out.isNotEmpty())
    }

    @Test
    fun gzipHttpRoundTrip() {
        val inner = nameAgentReq
        val gz = ConnectProtoCodec.encodeHttpBody(
            inner,
            ConnectProtoCodec.HttpCompression.GZIP,
        ).bytes
        val decoded = ConnectProtoCodec.decodeHttpBody(gz, "gzip")
        assertEquals(ConnectProtoCodec.HttpCompression.GZIP, decoded.httpContentEncoding)
        assertTrue(decoded.bytes.contentEquals(inner))
    }

    @Test
    fun connectEnvelopeRoundTrip() {
        val payload = nameAgentReq
        val wire = ConnectProtoCodec.WireMessage(
            listOf(ConnectProtoCodec.Frame(1, payload)),
            rawProto = false,
        )
        val bytes = ConnectProtoCodec.serialize(wire)
        val parsed = ConnectProtoCodec.parse(bytes)
        assertFalse(parsed.rawProto)
        assertTrue(parsed.frames[0].payload.contentEquals(payload))
    }

    @Test
    fun nestedSubmessageWithInnerPii() {
        val inner = buildStringFieldProto("reach me at leak@corp.com")
        val outer = wrapField(1, inner)
        val pipeline = RedactionPipeline(TestConfig.plugin())
        val (out, map) = ProtobufRedactor.redact(outer) { text ->
            redact(text, pipeline.detectSpans(text), null)
        }
        assertTrue(map.isNotEmpty())
        assertFalse(String(out).contains("leak@corp.com"))
    }

    @Test
    fun validProtobufMessageRejectsPlainText() {
        val plain = "hello world".toByteArray(Charsets.UTF_8)
        assertFalse(ProtobufRedactor.isValidProtobufMessage(plain))
        assertTrue(ProtobufRedactor.isValidProtobufMessage(buildStringFieldProto("hello")))
    }

    @Test
    fun targetMatcherCursorPaths() {
        assertTrue(TargetMatcher.isTargetPath("/aiserver.v1.AiService/NameAgent", setOf("/v1/chat")))
        assertTrue(TargetMatcher.isTargetHost("api2.cursor.sh", setOf("cursor.sh")))
        assertEquals(BodyFormat.CONNECT_PROTO, BodyFormatDetector.detect("application/x-protobuf"))
        assertEquals(BodyFormat.CONNECT_PROTO, BodyFormatDetector.detect("application/proto"))
    }

    private fun buildStringFieldProto(text: String): ByteArray =
        wrapField(1, text.toByteArray(Charsets.UTF_8))

    private fun wrapField(fieldNumber: Int, payload: ByteArray): ByteArray {
        val tag = (fieldNumber shl 3) or 2
        val out = java.io.ByteArrayOutputStream()
        writeVarint(out, tag.toLong())
        writeVarint(out, payload.size.toLong())
        out.write(payload)
        return out.toByteArray()
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
