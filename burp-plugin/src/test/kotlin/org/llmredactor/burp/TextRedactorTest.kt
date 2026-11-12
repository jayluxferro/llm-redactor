package org.llmredactor.burp

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TextRedactorTest {
    private fun offline() = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))

    @Test fun `only the canonical Burp block response is acknowledged`() {
        assertTrue(blockedByBurp(400, "{\"detail\":\"Bad Request\"}"))
        assertTrue(blockedByBurp(400, "  {\"detail\":\"Bad Request\"}\n"))
        assertTrue(blockedByBurp(400, "{ \"detail\" : \"Bad Request\" }"))
        assertTrue(blockedByBurp(400, "{\n\"detail\":\"Bad Request\"\n}"))
        // Real upstream refusals in the same shape must reach the client as errors.
        assertFalse(blockedByBurp(403, "{\"detail\":\"Forbidden\"}"))
        assertFalse(blockedByBurp(403, "{\"detail\":\"Not authenticated\"}"))
        assertFalse(blockedByBurp(400, "{\"detail\":\"not found\"}"))
        assertFalse(blockedByBurp(400, "{\"detail\":\"\"}"))
        assertFalse(blockedByBurp(400, "{\"error\":\"bad request\"}"))
        assertFalse(blockedByBurp(500, "{\"detail\":\"Bad Request\"}"))
        assertFalse(blockedByBurp(401, "{\"detail\":\"Bad Request\"}"))
        assertFalse(blockedByBurp(400, "{\"detail\":\"Bad Request\",\"code\":400}"))
    }

    @Test fun `Responses API streams are never acknowledged`() {
        for (path in listOf("/backend-api/codex/responses", "/backend-api/codex/responses/abc", "/v1/responses")) {
            assertFalse(BlockedRequestCompatibility.isCanonicalBurpBlock(400, "{\"detail\":\"Bad Request\"}", "POST", path))
        }
    }

    @Test fun `regex fallback redacts email and keeps typed placeholder`() {
        val result = offline().redact("email alice@example.com")
        assertTrue(result.usedFallback)
        assertEquals("email ⟨EMAIL_1⟩", result.text)
    }

    @Test fun `redactWithRegex skips detector entirely`() {
        val result = offline().redactWithRegex("email alice@example.com and phone 555-123-4567")
        assertTrue(result.usedFallback)
        assertEquals("email ⟨EMAIL_1⟩ and phone ⟨PHONE_US_1⟩", result.text)
        assertEquals(2, result.spans.size)
    }

    @Test fun `query values are redacted`() {
        val transformer = BodyTransformer(offline())
        val (path, detections) = transformer.transformQuery("/x?email=alice%40example.com")
        assertEquals("/x?email=%E2%9F%A8EMAIL_1%E2%9F%A9", path)
        assertEquals(1, detections)
    }

    @Test fun `encrypted JSON values are never redacted`() {
        val encrypted = "gAAAAAB-example-alice@example.com-Lb0="
        val result = offline().redact("""{"encrypted_content":"$encrypted","email":"bob@example.com"}""")

        assertTrue(result.usedFallback)
        assertTrue(result.text.contains("\"encrypted_content\":\"$encrypted\""))
        assertTrue(result.text.contains("\"email\":\"⟨EMAIL_1⟩\""))
    }

    @Test fun `Fernet ciphertext is preserved outside known JSON fields`() {
        val ciphertext = "gAAAAABl9xF5uS1foJ2dK9lM4T3Q8W7Y6X5Z4C3V2B1N0M9L8K7J6H5G4F3E2D1C0="
        val result = offline().redact("token=$ciphertext email=alice@example.com")

        assertTrue(result.usedFallback)
        assertTrue(result.text.contains(ciphertext))
        assertTrue(result.text.contains("email=⟨EMAIL_1⟩"))
    }

    @Test fun `a span straddling ciphertext is cut around it, not dropped`() {
        // Dropping the whole span (the old behaviour) left the part outside
        // the ciphertext, e.g. a name an NER span also covered, in the clear.
        val spans = listOf(Span(0, 30, "person")).minusRanges(listOf(CodePointRange(10, 20)))
        assertEquals(listOf(Span(0, 10, "person"), Span(20, 30, "person")), spans)
        val ciphertext = "gAAAAABl9xF5uS1foJ2dK9lM4T3Q8W7Y6X5Z4C3V2B1N0M9L8K7J6H5G4F3E2D1C0="
        assertEquals("⟨EMAIL_1⟩ $ciphertext", offline().redact("alice@example.com $ciphertext").text)
    }

    @Test fun `encrypted protocol payload is identified for complete pass through`() {
        val payload = """{"encrypted_content":"gAAAAABl9xF5uS1foJ2dK9lM4T3Q8W7Y6X5Z4C3V2B1N0M9L8K7J6H5G4F3E2D1C0="}"""
        val transformer = BodyTransformer(offline())

        assertTrue(TextRedactor.isOpaqueProtocolPayload(payload))
        assertTrue(transformer.isOpaqueProtocolPayload(payload.encodeToByteArray()))
    }

    @Test fun `ordinary words that merely start like Fernet are not opaque`() {
        // The old marker inherited (?i) from the key pattern: any long word
        // starting "gaaaa" sent the whole request through unredacted.
        assertFalse(TextRedactor.isOpaqueProtocolPayload("Gaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaal!"))
        assertFalse(TextRedactor.isOpaqueProtocolPayload("gAAAAA-too-short"))
    }

    @Test fun `JPEG and PNG bodies use the local image redactor`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val imageRedactor = ImageRedactor { body, mediaType ->
            assertEquals("image/png", mediaType)
            assertContentEquals(png, body)
            RedactedImage(byteArrayOf(9, 8), detections = 2)
        }
        val transformer = BodyTransformer(offline(), imageRedactor)

        val result = transformer.transform(png, "image/png", null)
        assertContentEquals(byteArrayOf(9, 8), result.body)
        assertEquals(2, result.detections)
        assertEquals(null, result.reason)
    }

    @Test fun `base64 image attachments use the local image redactor`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val encodedPng = "iVBORw0KGgoBAgM="
        val imageRedactor = ImageRedactor { body, mediaType ->
            assertEquals("image/png", mediaType)
            assertContentEquals(png, body)
            RedactedImage(byteArrayOf(4, 5), detections = 1)
        }
        val transformer = BodyTransformer(offline(), imageRedactor)
        val result = transformer.transform(
            """{"image_url":"data:image/png;base64,$encodedPng"}""".encodeToByteArray(),
            "application/json",
            null,
        )

        assertEquals("""{"image_url":"data:image/png;base64,BAU="}""", result.body.decodeToString())
        assertEquals(1, result.detections)
    }

    @Test fun `invalid bytes labelled as an image are passed through`() {
        var called = false
        val transformer = BodyTransformer(
            offline(),
            ImageRedactor { _, _ ->
                called = true
                RedactedImage(byteArrayOf(), detections = 0)
            },
        )

        val original = byteArrayOf(1, 2, 3)
        val result = transformer.transform(original, "image/png", null)

        assertContentEquals(original, result.body)
        assertEquals("invalid-image-body", result.reason)
        assertEquals(false, called)
    }

    // ── redact() ──

    @Test fun `empty string returns empty outcome`() {
        val result = offline().redact("")
        assertEquals("", result.text)
        assertEquals(0, result.spans.size)
        assertEquals(false, result.usedFallback)
    }

    @Test fun `text with no PII returns unchanged`() {
        val result = offline().redact("just some regular text without any secrets")
        assertEquals("just some regular text without any secrets", result.text)
        assertEquals(0, result.spans.size)
    }

    @Test fun `different values of one kind get different placeholders, left to right`() {
        val result = offline().redact("alice@example.com and bob@example.com")
        assertEquals("⟨EMAIL_1⟩ and ⟨EMAIL_2⟩", result.text)
        assertEquals(2, result.spans.size)
    }

    @Test fun `same PII text appearing twice reuses same placeholder`() {
        val result = offline().redact("user alice@example.com copied alice@example.com")
        assertEquals("user ⟨EMAIL_1⟩ copied ⟨EMAIL_1⟩", result.text)
        assertEquals(2, result.spans.size)
    }

    @Test fun `non-BMP prefix keeps offsets right`() {
        val result = offline().redact("😀😀 alice@example.com 😀")
        assertEquals("😀😀 ⟨EMAIL_1⟩ 😀", result.text)
    }

    @Test fun `key context lets key-anchored patterns fire on a bare value`() {
        val redactor = offline()
        val field = TextRedactor.Field("hunter22hunter", prefix = "\"password\": \"", suffix = "\"")
        val result = redactor.redactFields(listOf(field), PlaceholderNaming()).single()
        assertEquals("⟨PASSWORD_1⟩", result.text)
        // The context is never part of the output, and an innocuous key changes nothing.
        val note = TextRedactor.Field("plain words", prefix = "\"note\": \"", suffix = "\"")
        assertEquals("plain words", redactor.redactFields(listOf(note), PlaceholderNaming()).single().text)
    }

    // ── redactBatch() ──

    @Test fun `batch shares one placeholder namespace`() {
        val results = offline().redactBatch(listOf("alice@example.com", "bob@example.com", "alice@example.com"))
        assertEquals(listOf("⟨EMAIL_1⟩", "⟨EMAIL_2⟩", "⟨EMAIL_1⟩"), results.map { it.text })
        assertTrue(results.all { it.usedFallback })
    }

    @Test fun `batch with mix of PII and clean texts`() {
        val results = offline().redactBatch(listOf("alice@example.com", "no pii here"))
        assertEquals(1, results[0].spans.size)
        assertEquals(0, results[1].spans.size)
    }

    @Test fun `empty batch returns empty list`() {
        assertEquals(0, offline().redactBatch(emptyList()).size)
    }

    @Test fun `all-empty batch needs no detector at all`() {
        val results = offline().redactBatch(listOf("", ""))
        assertEquals(listOf("", ""), results.map { it.text })
        assertTrue(results.none { it.usedFallback })
    }

    // ── redactWithRegex() ──

    @Test fun `redactWithRegex always sets usedFallback true`() {
        assertTrue(offline().redactWithRegex("no pii here").usedFallback)
    }

    @Test fun `redactWithRegex produces same output as failed redact`() {
        val redactor = offline()
        val viaRedact = redactor.redact("email alice@example.com")
        val viaRegex = redactor.redactWithRegex("email alice@example.com")
        assertEquals(viaRedact.text, viaRegex.text)
        assertEquals(viaRedact.spans.size, viaRegex.spans.size)
    }

    // ── opaque protection ──

    @Test fun `data URI in JSON is protected from redaction`() {
        val dataUri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
        val result = offline().redact("""{"image":"$dataUri"}""")
        assertTrue(result.text.contains(dataUri))
    }

    @Test fun `encrypted field with no surrounding PII produces zero spans`() {
        assertEquals(0, offline().redact("""{"encrypted_content":"gAAAAAB-example-ciphertext-Lb0="}""").spans.size)
    }

    @Test fun `multiple opaque fields with interstitial PII`() {
        val result = offline().redact(
            """{"encrypted_content":"gAAAAAB-a","email":"alice@example.com","ciphertext":"alice@example.org"}""",
        )
        assertEquals(1, result.spans.size)
        assertEquals("email", result.spans[0].kind)
        assertTrue(result.text.contains("⟨EMAIL_1⟩"))
        assertTrue(result.text.contains("gAAAAAB-a"))
        assertTrue(result.text.contains("\"ciphertext\":\"alice@example.org\""))
    }

    @Test fun `escaped quotes inside an encrypted value do not end it early`() {
        val result = offline().redact("""{"encrypted_content":"a\"bob@example.com\"b","x":"carol@example.com"}""")
        assertTrue(result.text.contains("""a\"bob@example.com\"b"""))
        assertTrue(result.text.contains("\"x\":\"⟨EMAIL_1⟩\""))
    }

    // ── isOpaqueProtocolPayload ──

    @Test fun `encrypted JSON key with colon is opaque`() {
        assertTrue(TextRedactor.isOpaqueProtocolPayload("""{"encrypted_content":"..."}"""))
        assertTrue(TextRedactor.isOpaqueProtocolPayload("""{"ciphertext":"..."}"""))
        assertTrue(TextRedactor.isOpaqueProtocolPayload("""{"sealed_payload":"..."}"""))
        assertTrue(TextRedactor.isOpaqueProtocolPayload("""{"encrypted":"..."}"""))
        assertTrue(TextRedactor.isOpaqueProtocolPayload("""{"encrypted_data": {"iv": "x"}}"""))
    }

    @Test fun `plain JSON with email is not opaque`() {
        assertEquals(false, TextRedactor.isOpaqueProtocolPayload("""{"email":"alice@example.com"}"""))
    }

    @Test fun `fernet token in plain text is opaque`() {
        val token = "gAAAAABl9xF5uS1foJ2dK9lM4T3Q8W7Y6X5Z4C3V2B1N0M9L8K7J6H5G4F3E2D1C0="
        assertTrue(TextRedactor.isOpaqueProtocolPayload("token=$token"))
    }

    @Test fun `empty string is not opaque`() {
        assertEquals(false, TextRedactor.isOpaqueProtocolPayload(""))
    }

    private fun blockedByBurp(status: Short, body: String): Boolean =
        BlockedRequestCompatibility.isCanonicalBurpBlock(status, body, "POST", "/otlp/v1/metric")
}
