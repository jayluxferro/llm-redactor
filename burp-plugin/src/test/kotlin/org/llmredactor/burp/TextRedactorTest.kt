package org.llmredactor.burp

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TextRedactorTest {
    @Test fun `canonical Burp block response is acknowledged generically`() {
        assertTrue(BlockedRequestCompatibility.isCanonicalBurpBlock(400, "{\"detail\":\"Bad Request\"}"))
        assertTrue(BlockedRequestCompatibility.isCanonicalBurpBlock(400, "  {\"detail\":\"Bad Request\"}\n"))
        assertTrue(BlockedRequestCompatibility.isCanonicalBurpBlock(400, "{\"detail\":\"not found\"}"))
        assertTrue(BlockedRequestCompatibility.isCanonicalBurpBlock(403, "{\"detail\":\"Forbidden\"}"))
        assertEquals(false, BlockedRequestCompatibility.isCanonicalBurpBlock(400, "{\"error\":\"bad request\"}"))
        assertEquals(false, BlockedRequestCompatibility.isCanonicalBurpBlock(500, "{\"detail\":\"Bad Request\"}"))
        assertEquals(false, BlockedRequestCompatibility.isCanonicalBurpBlock(400, "{\"detail\":\"Bad Request\",\"code\":400}"))
    }

    @Test fun `regex fallback redacts email and keeps typed placeholder`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redact("email alice@example.com")
        assertTrue(result.usedFallback)
        assertEquals("email ⟨EMAIL_1⟩", result.text)
    }

    @Test fun `redactWithRegex skips detector entirely`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redactWithRegex("email alice@example.com and phone 555-123-4567")
        assertTrue(result.usedFallback)
        assertTrue(result.text.contains("⟨EMAIL_1⟩"))
        assertTrue(result.text.contains("⟨PHONE_1⟩"))
        assertEquals(2, result.spans.size)
    }

    @Test fun `query values are redacted`() {
        val transformer = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")))
        val (path, detections) = transformer.transformQuery("/x?email=alice%40example.com")
        assertTrue(path.contains("%E2%9F%A8EMAIL_1%E2%9F%A9"))
        assertEquals(1, detections)
    }

    @Test fun `protobuf walker preserves message when no text fields exist`() {
        val transformer = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")))
        val input = byteArrayOf(0x08, 0x96.toByte(), 0x01)
        val result = transformer.transform(input, "application/protobuf", null)
        assertTrue(result.body.contentEquals(input))
    }

    @Test fun `encrypted JSON values are never redacted`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val encrypted = "gAAAAAB-example-alice@example.com-Lb0="
        val result = redactor.redact("""{"encrypted_content":"$encrypted","email":"bob@example.com"}""")

        assertTrue(result.usedFallback)
        assertTrue(result.text.contains("\"encrypted_content\":\"$encrypted\""))
        assertTrue(result.text.contains("\"email\":\"⟨EMAIL_1⟩\""))
    }

    @Test fun `Fernet ciphertext is preserved outside known JSON fields`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val ciphertext = "gAAAAABl9xF5uS1foJ2dK9lM4T3Q8W7Y6X5Z4C3V2B1N0M9L8K7J6H5G4F3E2D1C0="
        val result = redactor.redact("token=$ciphertext email=alice@example.com")

        assertTrue(result.usedFallback)
        assertTrue(result.text.contains(ciphertext))
        assertTrue(result.text.contains("email=⟨EMAIL_1⟩"))
    }

    @Test fun `encrypted protocol payload is identified for complete pass through`() {
        val payload = """{"encrypted_content":"gAAAAABl9xF5uS1foJ2dK9lM4T3Q8W7Y6X5Z4C3V2B1N0M9L8K7J6H5G4F3E2D1C0="}"""
        val transformer = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")))

        assertTrue(TextRedactor.isOpaqueProtocolPayload(payload))
        assertTrue(transformer.isOpaqueProtocolPayload(payload.encodeToByteArray()))
    }

    @Test fun `JPEG and PNG bodies use the local image redactor`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val imageRedactor = ImageRedactor { body, mediaType ->
            assertEquals("image/png", mediaType)
            assertContentEquals(png, body)
            RedactedImage(byteArrayOf(9, 8), detections = 2)
        }
        val transformer = BodyTransformer(
            TextRedactor(DetectorClient("http://127.0.0.1:1/nope")),
            imageRedactor,
        )

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
        val transformer = BodyTransformer(
            TextRedactor(DetectorClient("http://127.0.0.1:1/nope")),
            imageRedactor,
        )
        val result = transformer.transform(
            """{"image_url":"data:image/png;base64,$encodedPng"}""".encodeToByteArray(),
            "application/json",
            null,
        )

        assertEquals(
            """{"image_url":"data:image/png;base64,BAU="}""",
            result.body.decodeToString(),
        )
        assertEquals(1, result.detections)
    }

    @Test fun `invalid bytes labelled as an image are passed through`() {
        var called = false
        val transformer = BodyTransformer(
            TextRedactor(DetectorClient("http://127.0.0.1:1/nope")),
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

    // ── Additional redact() tests ──

    @Test fun `empty string returns empty outcome`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redact("")
        assertEquals("", result.text)
        assertEquals(0, result.spans.size)
        assertEquals(false, result.usedFallback)
    }

    @Test fun `text with no PII returns unchanged`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redact("just some regular text without any secrets")
        assertEquals("just some regular text without any secrets", result.text)
        assertEquals(0, result.spans.size)
    }

    @Test fun `multiple PII of same kind get sequential counters`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redact("alice@example.com and bob@example.com")
        assertTrue(result.usedFallback)
        assertTrue(result.text.contains("⟨EMAIL_1⟩"))
        assertTrue(result.text.contains("⟨EMAIL_2⟩"))
        assertEquals(2, result.spans.size)
    }

    @Test fun `same PII text appearing twice reuses same placeholder`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redact("user alice@example.com copied alice@example.com")
        assertTrue(result.usedFallback)
        val occurrences = "⟨EMAIL_1⟩".toRegex().findAll(result.text).count()
        assertEquals(2, occurrences)
        assertEquals(2, result.spans.size)
    }

    @Test fun `non-ASCII prefix with ASCII email has correct offsets`() {
        // 名前 is 2 BMP code points; offset for email after prefix is correct
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redact("名前 alice@example.com")
        assertTrue(result.usedFallback)
        assertTrue(result.text.contains("⟨EMAIL_1⟩"))
        assertEquals(1, result.spans.size)
    }

    // ── redactBatch() tests ──

    @Test fun `batch redacts multiple texts with fallback`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val results = redactor.redactBatch(listOf("alice@example.com", "bob@example.com"))
        assertEquals(2, results.size)
        assertTrue(results[0].usedFallback)
        assertTrue(results[1].usedFallback)
        assertTrue(results[0].text.contains("⟨EMAIL_1⟩"))
        assertTrue(results[1].text.contains("⟨EMAIL_1⟩"))
    }

    @Test fun `batch with mix of PII and clean texts`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val results = redactor.redactBatch(listOf("alice@example.com", "no pii here"))
        assertEquals(2, results.size)
        assertEquals(1, results[0].spans.size)
        assertEquals(0, results[1].spans.size)
    }

    @Test fun `empty batch returns empty list`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val results = redactor.redactBatch(emptyList())
        assertEquals(0, results.size)
    }

    @Test fun `batch all empty strings`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val results = redactor.redactBatch(listOf("", ""))
        assertEquals(2, results.size)
        results.forEach {
            assertEquals("", it.text)
            assertEquals(0, it.spans.size)
            // Detector fails → fallback path sets usedFallback=true
            assertTrue(it.usedFallback)
        }
    }

    // ── redactWithRegex() tests ──

    @Test fun `redactWithRegex always sets usedFallback true`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redactWithRegex("no pii here")
        assertTrue(result.usedFallback)
    }

    @Test fun `redactWithRegex produces same output as failed redact`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val viaRedact = redactor.redact("email alice@example.com")
        val viaRegex = redactor.redactWithRegex("email alice@example.com")
        assertEquals(viaRedact.text, viaRegex.text)
        assertEquals(viaRedact.spans.size, viaRegex.spans.size)
    }

    // ── Opaque protection edge cases ──

    @Test fun `data URI in JSON is protected from redaction`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val dataUri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
        val result = redactor.redact("""{"image":"$dataUri"}""")
        // The data URI should be preserved (not treated as PII to redact at text level)
        assertTrue(result.text.contains("data:image/png;base64,"))
    }

    @Test fun `encrypted field with no surrounding PII produces zero spans`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redact("""{"encrypted_content":"gAAAAAB-example-ciphertext-Lb0="}""")
        assertEquals(0, result.spans.size)
    }

    @Test fun `multiple opaque fields with interstitial PII`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redact(
            """{"encrypted_content":"gAAAAAB-a","email":"alice@example.com","cipher_text":"gAAAAAB-b"}""",
        )
        assertEquals(1, result.spans.size)
        assertEquals("email", result.spans[0].kind)
        assertTrue(result.text.contains("⟨EMAIL_1⟩"))
        // Encrypted values preserved
        assertTrue(result.text.contains("gAAAAAB-a"))
        assertTrue(result.text.contains("gAAAAAB-b"))
    }

    // ── isOpaqueProtocolPayload tests ──

    @Test fun `encrypted JSON key with colon is opaque`() {
        // Suffixes must match: encrypted→content|payload|data, cipher→text|content|payload|data, sealed→content|payload|data
        assertTrue(TextRedactor.isOpaqueProtocolPayload("""{"encrypted_content":"..."}"""))
        assertTrue(TextRedactor.isOpaqueProtocolPayload("""{"ciphertext":"..."}"""))
        assertTrue(TextRedactor.isOpaqueProtocolPayload("""{"sealed_payload":"..."}"""))
        assertTrue(TextRedactor.isOpaqueProtocolPayload("""{"encrypted":"..."}"""))
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

    // ── BlockedRequestCompatibility additional tests ──

    @Test fun `block detection matches empty detail message`() {
        assertTrue(BlockedRequestCompatibility.isCanonicalBurpBlock(400, "{\"detail\":\"\"}"))
    }

    @Test fun `block detection matches with whitespace around colons`() {
        assertTrue(BlockedRequestCompatibility.isCanonicalBurpBlock(400, "{ \"detail\" : \"msg\" }"))
    }

    @Test fun `block detection rejects status 401`() {
        assertEquals(false, BlockedRequestCompatibility.isCanonicalBurpBlock(401, "{\"detail\":\"Unauthorized\"}"))
    }

    @Test fun `block detection matches multiline JSON body with newlines`() {
        // \s includes \n, so multi-line JSON bodies also match.
        assertTrue(BlockedRequestCompatibility.isCanonicalBurpBlock(400, "{\n\"detail\":\"Bad Request\"\n}"))
    }
}
