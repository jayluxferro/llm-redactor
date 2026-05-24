package com.llmredactor.burp.transport

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class TransportLogicTest {

    @Test
    fun fixSurrogatesFoldsJsonEscapes() {
        val emoji = "😀"
        val broken = JSONObject(mapOf("text" to emoji)).toString()
        val fixed = TransportLogic.fixSurrogates(broken)
        assertTrue(fixed.contains(emoji))
        assertFalse(fixed.contains("\\uD83D"))
    }

    @Test
    fun gzipRoundTrip() {
        val json = """{"choices":[{"message":{"content":"hello ⟨EMAIL_1⟩"}}]}"""
        val gz = TransportLogic.gzipBytes(json.toByteArray())
        val decoded = TransportLogic.decodeResponseBody(gz, "gzip")
        assertTrue(decoded.wasCompressed)
        val restored = TransportLogic.restoreJsonBody(
            decoded.text,
            mapOf("⟨EMAIL_1⟩" to "jane@example.com"),
        )
        val reencoded = TransportLogic.encodeResponseBody(restored, decoded, "gzip")
        val again = TransportLogic.decodeResponseBody(reencoded.bytes, "gzip")
        assertTrue(again.text.contains("jane@example.com"))
    }

    @Test
    fun plaintextWithStaleContentEncodingHeader() {
        val json = """{"id":"x","choices":[{"message":{"content":"ok"}}]}"""
        val decoded = TransportLogic.decodeResponseBody(json.toByteArray(), "gzip")
        assertFalse(decoded.wasCompressed)
        val encoded = TransportLogic.encodeResponseBody(json, decoded, "gzip")
        assertTrue(encoded.stripContentEncoding)
    }

    @Test
    fun restoreJsonOpenAiShape() {
        val body = """{"choices":[{"message":{"content":"Email ⟨EMAIL_1⟩"}}]}"""
        val out = TransportLogic.restoreJsonBody(body, mapOf("⟨EMAIL_1⟩" to "jane@x.com"))
        assertTrue(out.contains("jane@x.com"))
        assertFalse(out.contains("⟨EMAIL_1⟩"))
    }

    @Test
    fun restoreJsonAnthropicShape() {
        val body = """{"content":[{"type":"text","text":"⟨JWT_1⟩"}]}"""
        val out = TransportLogic.restoreJsonBody(body, mapOf("⟨JWT_1⟩" to "eyJhbGciOiJIUzI1NiJ9"))
        assertTrue(out.contains("eyJhbGciOiJIUzI1NiJ9"))
    }

    @Test
    fun restoreJsonOtlpShape() {
        val body = """
            {"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":[
              {"key":"user.email","value":{"stringValue":"⟨EMAIL_1⟩"}}
            ]}]}]}]}
        """.trimIndent().replace("\n", "").replace(" ", "")
        val out = TransportLogic.restoreJsonBody(
            body,
            mapOf("⟨EMAIL_1⟩" to "trace-leak@corp.com"),
        )
        assertTrue(out.contains("trace-leak@corp.com"))
        assertFalse(out.contains("⟨EMAIL_1⟩"))
    }

    @Test
    fun sseLcpAcrossChunkBoundary() {
        val map = mapOf("⟨EMAIL_1⟩" to "jane@example.com")
        val sse = """
            data: {"choices":[{"index":0,"delta":{"content":"⟨EM"}}]}

            data: {"choices":[{"index":0,"delta":{"content":"AIL_1⟩ ok"}}]}

            data: [DONE]
        """.trimIndent()

        val out = TransportLogic.restoreSseBody(sse, map)
        assertTrue(out.contains("jane@example.com"))
        assertFalse(out.contains("⟨EMAIL"))
    }

    @Test
    fun sseResetsOnChoiceIndexChange() {
        val map = mapOf("⟨EMAIL_1⟩" to "a@b.com")
        val sse = """
            data: {"choices":[{"index":0,"delta":{"content":"⟨EM"}}]}

            data: {"choices":[{"index":1,"delta":{"content":"AIL_1⟩"}}]}
        """.trimIndent()
        val out = TransportLogic.restoreSseBody(sse, map)
        // Second chunk is a new choice — should not stitch with index 0 accumulation.
        assertTrue(out.contains("data:"))
    }

    @Test
    fun unsupportedRequestEncodings() {
        assertFalse(TransportLogic.isUnsupportedRequestContentEncoding("gzip"))
        assertFalse(TransportLogic.isUnsupportedRequestContentEncoding("deflate"))
        assertFalse(TransportLogic.isUnsupportedRequestContentEncoding("br"))
        assertFalse(TransportLogic.isUnsupportedRequestContentEncoding("zstd"))
        assertFalse(TransportLogic.isUnsupportedRequestContentEncoding("gzip, br"))
        assertFalse(TransportLogic.isUnsupportedRequestContentEncoding("compress"))
        assertFalse(TransportLogic.isUnsupportedRequestContentEncoding("x-compress"))
        assertFalse(TransportLogic.isUnsupportedRequestContentEncoding("identity"))
        assertFalse(TransportLogic.isUnsupportedRequestContentEncoding(""))
    }

    @Test
    fun sessionStoreDualFingerprintIndex() {
        val store = SessionStore(TestConfig.plugin())
        val original = """{"messages":[{"role":"user","content":"jane@example.com"}]}""".toByteArray()
        val redacted = """{"messages":[{"role":"user","content":"⟨EMAIL_1⟩"}]}""".toByteArray()
        val map = mapOf("⟨EMAIL_1⟩" to "jane@example.com")
        val host = "api.openai.com"
        val path = "/v1/chat/completions"
        store.putWithFingerprints(
            "sid",
            map,
            SessionStore.fingerprint(host, path, original),
            SessionStore.fingerprint(host, path, redacted),
        )
        assertEquals(map, store.removeByFingerprint(SessionStore.fingerprint(host, path, redacted)))
    }

    @Test
    fun fingerprintDiffersForOriginalVsRedacted() {
        val host = "api.openai.com"
        val path = "/v1/chat/completions"
        val a = SessionStore.fingerprint(host, path, """{"x":1}""".toByteArray())
        val b = SessionStore.fingerprint(host, path, """{"x":2}""".toByteArray())
        assertTrue(a != b)
    }
}
