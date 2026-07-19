package org.llmredactor.burp

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.DeflaterOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.InflaterInputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BodyTransformerTest {
    private fun transformer() = BodyTransformer(
        TextRedactor(DetectorClient("http://127.0.0.1:1/nope")),
    )

    // ── Content encoding round-trips ──

    @Test fun `Codex response request redacts only explicit user-text fields`() {
        val t = transformer()
        val body = """
            {"model":"gpt-5-codex","response_id":"alice@example.com","input":[
              {"type":"input_text","text":"Contact alice@example.com"}
            ],"metadata":{"owner":"bob@example.com"}}
        """.trimIndent().encodeToByteArray()

        val result = t.transformCodexResponseRequest(body, "application/json", null)
        val output = result.body.decodeToString()

        assertEquals(1, result.detections)
        assertTrue(output.contains("\"text\":\"Contact ⟨EMAIL_1⟩\""))
        assertTrue(output.contains("\"response_id\":\"alice@example.com\""))
        assertTrue(output.contains("\"owner\":\"bob@example.com\""))
    }

    @Test fun `Codex response request preserves invalid JSON`() {
        val t = transformer()
        val body = "{not json".encodeToByteArray()

        val result = t.transformCodexResponseRequest(body, "application/json", null)

        assertEquals("codex-protocol-invalid-json", result.reason)
        assertContentEquals(body, result.body)
    }

    @Test fun `identity encoding returns bytes unchanged`() {
        val t = transformer()
        val body = "hello world".encodeToByteArray()
        val result = t.transform(body, "text/plain", "identity")
        assertContentEquals(body, result.body)
    }

    @Test fun `null or empty encoding is treated as identity`() {
        val t = transformer()
        val body = "hello world".encodeToByteArray()
        val r1 = t.transform(body, "text/plain", null)
        val r2 = t.transform(body, "text/plain", "")
        assertContentEquals(body, r1.body)
        assertContentEquals(body, r2.body)
    }

    @Test fun `gzip round-trip decodes, redacts, and re-encodes`() {
        val t = transformer()
        val original = "email alice@example.com here"
        val compressed = ByteArrayOutputStream().use { bos ->
            GZIPOutputStream(bos).use { it.write(original.encodeToByteArray()) }
            bos.toByteArray()
        }
        val result = t.transform(compressed, "text/plain", "gzip")
        assertEquals(null, result.reason)
        val decompressed = GZIPInputStream(ByteArrayInputStream(result.body)).readBytes().decodeToString()
        assertTrue(decompressed.contains("⟨EMAIL_1⟩"))
        assertEquals(1, result.detections)
    }

    @Test fun `deflate round-trip decodes, redacts, and re-encodes`() {
        val t = transformer()
        val original = "email alice@example.com here"
        val compressed = ByteArrayOutputStream().use { bos ->
            DeflaterOutputStream(bos).use { it.write(original.encodeToByteArray()) }
            bos.toByteArray()
        }
        val result = t.transform(compressed, "text/plain", "deflate")
        assertEquals(null, result.reason)
        val decompressed = InflaterInputStream(ByteArrayInputStream(result.body)).readBytes().decodeToString()
        assertTrue(decompressed.contains("⟨EMAIL_1⟩"))
    }

    @Test fun `zstd round-trip decodes, redacts, and re-encodes`() {
        val t = transformer()
        val original = "email alice@example.com here"
        val baos = ByteArrayOutputStream()
        com.github.luben.zstd.ZstdOutputStream(baos).use { it.write(original.encodeToByteArray()) }
        val compressed = baos.toByteArray()
        val result = t.transform(compressed, "text/plain", "zstd")
        assertEquals(null, result.reason)
        val decompressed = com.github.luben.zstd.ZstdInputStream(ByteArrayInputStream(result.body)).use { it.readBytes() }.decodeToString()
        assertTrue(decompressed.contains("⟨EMAIL_1⟩"))
    }

    @Test fun `unsupported encoding returns reason and original body`() {
        val t = transformer()
        val body = "email alice@example.com".encodeToByteArray()
        val result = t.transform(body, "text/plain", "br")
        assertNotNull(result.reason)
        assertTrue(result.reason!!.startsWith("unsupported-encoding"))
        assertContentEquals(body, result.body)
        assertEquals(0, result.detections)
    }

    @Test fun `corrupt gzip data returns reason`() {
        val t = transformer()
        val corrupt = byteArrayOf(0x1f, 0x2e) // not valid gzip
        val result = t.transform(corrupt, "text/plain", "gzip")
        assertNotNull(result.reason)
        assertContentEquals(corrupt, result.body)
    }

    // ── UTF-8 text body redaction ──

    @Test fun `plain text body with email is redacted`() {
        val t = transformer()
        val body = "contact alice@example.com for help".encodeToByteArray()
        val result = t.transform(body, "text/plain", null)
        assertEquals(null, result.reason)
        val output = result.body.decodeToString()
        assertTrue(output.contains("⟨EMAIL_1⟩"))
        assertEquals(1, result.detections)
    }

    @Test fun `JSON body with PII is redacted`() {
        val t = transformer()
        val body = """{"email":"alice@example.com","name":"Alice"}""".encodeToByteArray()
        val result = t.transform(body, "application/json", null)
        assertEquals(null, result.reason)
        val output = result.body.decodeToString()
        assertTrue(output.contains("⟨EMAIL_1⟩"))
        assertTrue(output.contains("\"name\":\"Alice\""))
    }

    @Test fun `binary non-UTF-8 body is passed through with reason`() {
        val t = transformer()
        // Random bytes that decode with replacement characters
        val binary = byteArrayOf(0x80.toByte(), 0x81.toByte(), 0x82.toByte(), 0xff.toByte())
        val result = t.transform(binary, "application/octet-stream", null)
        assertNotNull(result.reason)
        assertContentEquals(binary, result.body)
    }

    // ── Content-type routing ──

    @Test fun `content type with charset parameter is handled`() {
        val t = transformer()
        val body = "email alice@example.com".encodeToByteArray()
        val result = t.transform(body, "application/json; charset=utf-8", null)
        assertEquals(null, result.reason)
    }

    // ── Protobuf walker ──

    @Test fun `protobuf with varint field is preserved`() {
        val t = transformer()
        // field 1, wire type 0 (varint), value 150
        val input = byteArrayOf(0x08, 0x96.toByte(), 0x01)
        val result = t.transform(input, "application/protobuf", null)
        assertContentEquals(input, result.body)
        assertEquals(0, result.detections)
    }

    @Test fun `protobuf with wire-type-1 fixed64 is preserved`() {
        val t = transformer()
        // field 1, wire type 1 (fixed64), 8 bytes
        val input = byteArrayOf(0x09, 1, 2, 3, 4, 5, 6, 7, 8)
        val result = t.transform(input, "application/protobuf", null)
        assertContentEquals(input, result.body)
    }

    @Test fun `protobuf with wire-type-5 fixed32 is preserved`() {
        val t = transformer()
        // field 1, wire type 5 (fixed32), 4 bytes
        val input = byteArrayOf(0x0d, 1, 2, 3, 4)
        val result = t.transform(input, "application/protobuf", null)
        assertContentEquals(input, result.body)
    }

    @Test fun `protobuf wire-type-2 with UTF-8 text is redacted`() {
        val t = transformer()
        val textPayload = "alice@example.com".encodeToByteArray()
        // field 1, wire type 2, length = textPayload.size
        val tag = byteArrayOf(0x0a) // field 1, wire type 2
        val length = byteArrayOf(textPayload.size.toByte())
        val input = tag + length + textPayload
        val result = t.transform(input, "application/protobuf", null)
        assertEquals(null, result.reason)
        assertTrue(result.body.decodeToString().contains("⟨EMAIL_1⟩"))
        assertEquals(1, result.detections)
    }

    @Test fun `protobuf wire-type-2 with binary payload is preserved`() {
        val t = transformer()
        // Non-UTF-8 payload in a wire-type-2 field
        val binaryPayload = byteArrayOf(0x80.toByte(), 0x81.toByte(), 0xff.toByte())
        val tag = byteArrayOf(0x0a)
        val length = byteArrayOf(binaryPayload.size.toByte())
        val input = tag + length + binaryPayload
        val result = t.transform(input, "application/protobuf", null)
        assertEquals(null, result.reason)
        // The outer protobuf succeeded; inner field preserved (won't be PII anyway)
        assertEquals(0, result.detections)
    }

    @Test fun `malformed protobuf returns invalid-protobuf reason`() {
        val t = transformer()
        // Truncated varint (continuation bit set but no more bytes)
        val input = byteArrayOf(0x80.toByte())
        val result = t.transform(input, "application/protobuf", null)
        assertEquals("invalid-protobuf", result.reason)
        assertContentEquals(input, result.body)
    }

    @Test fun `empty protobuf body is handled`() {
        val t = transformer()
        val result = t.transform(byteArrayOf(), "application/protobuf", null)
        assertEquals(null, result.reason)
        assertEquals(0, result.detections)
    }

    @Test fun `protobuf content type with x-protobuf variant is recognized`() {
        val t = transformer()
        val input = byteArrayOf(0x08, 0x01)
        val result = t.transform(input, "application/x-protobuf", null)
        assertEquals(null, result.reason)
    }

    // ── Query transform ──

    @Test fun `path without query returns unchanged`() {
        val t = transformer()
        val (path, detections) = t.transformQuery("/api/users")
        assertEquals("/api/users", path)
        assertEquals(0, detections)
    }

    @Test fun `query param without PII returns unchanged`() {
        val t = transformer()
        val (path, detections) = t.transformQuery("/api?name=bob")
        assertEquals("/api?name=bob", path)
        assertEquals(0, detections)
    }

    @Test fun `query param with email is redacted`() {
        val t = transformer()
        val (path, detections) = t.transformQuery("/api?email=alice@example.com")
        assertTrue(path.contains("%E2%9F%A8EMAIL_1%E2%9F%A9"))
        assertEquals(1, detections)
    }

    @Test fun `multiple query params only one with PII`() {
        val t = transformer()
        val (path, detections) = t.transformQuery("/api?name=bob&email=alice@example.com&role=admin")
        assertTrue(path.contains("name=bob"))
        assertTrue(path.contains("role=admin"))
        assertTrue(path.contains("%E2%9F%A8EMAIL_1%E2%9F%A9"))
        assertEquals(1, detections)
    }

    @Test fun `query param with missing value is preserved`() {
        val t = transformer()
        val (path, _) = t.transformQuery("/api?flag")
        assertEquals("/api?flag", path)
    }

    @Test fun `query param with empty value is preserved`() {
        val t = transformer()
        val (path, _) = t.transformQuery("/api?key=")
        assertEquals("/api?key=", path)
    }

    @Test fun `query string with multiple values of same kind counted separately`() {
        val t = transformer()
        val (path, detections) = t.transformQuery(
            "/api?a=alice@example.com&b=bob@example.com",
        )
        // Each value is redacted independently; both get ⟨EMAIL_1⟩ from separate redact() calls.
        assertTrue(path.contains("%E2%9F%A8EMAIL_1%E2%9F%A9"))
        assertEquals(2, detections)
    }

    // ── Image handling ──

    @Test fun `valid PNG body is forwarded to image redactor`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val imageRedactor = ImageRedactor { body, mediaType ->
            assertEquals("image/png", mediaType)
            assertContentEquals(png, body)
            RedactedImage(byteArrayOf(9, 8, 7), detections = 3)
        }
        val t = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")), imageRedactor)
        val result = t.transform(png, "image/png", null)
        assertContentEquals(byteArrayOf(9, 8, 7), result.body)
        assertEquals(3, result.detections)
        assertEquals(null, result.reason)
    }

    @Test fun `valid JPEG body is forwarded to image redactor`() {
        val jpeg = byteArrayOf(0xff.toByte(), 0xd8.toByte(), 0xff.toByte(), 0xe0.toByte(), 1, 2, 3)
        var called = false
        val imageRedactor = ImageRedactor { _, mediaType ->
            assertEquals("image/jpeg", mediaType)
            called = true
            RedactedImage(byteArrayOf(5, 6), detections = 0)
        }
        val t = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")), imageRedactor)
        val result = t.transform(jpeg, "image/jpeg", null)
        assertTrue(called)
        assertEquals(null, result.reason)
    }

    @Test fun `invalid image signature returns reason`() {
        val t = transformer()
        val invalid = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        val result = t.transform(invalid, "image/png", null)
        assertEquals("invalid-image-body", result.reason)
        assertContentEquals(invalid, result.body)
    }

    @Test fun `image redactor exception returns image-redactor-unavailable`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val imageRedactor = ImageRedactor { _, _ -> throw RuntimeException("down") }
        val t = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")), imageRedactor)
        val result = t.transform(png, "image/png", null)
        assertEquals("image-redactor-unavailable", result.reason)
        assertContentEquals(png, result.body)
    }

    @Test fun `image with gzip encoding is decoded before redaction`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val compressed = ByteArrayOutputStream().use { bos ->
            GZIPOutputStream(bos).use { it.write(png) }
            bos.toByteArray()
        }
        val imageRedactor = ImageRedactor { body, _ ->
            // body should be decompressed PNG bytes
            assertContentEquals(png, body)
            RedactedImage(byteArrayOf(1), detections = 1)
        }
        val t = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")), imageRedactor)
        val result = t.transform(compressed, "image/png", "gzip")
        // re-encoded result
        val decompressed = GZIPInputStream(ByteArrayInputStream(result.body)).readBytes()
        assertContentEquals(byteArrayOf(1), decompressed)
    }

    // ── Embedded images ──

    @Test fun `embedded PNG data URL is redacted in JSON`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val encoded = java.util.Base64.getEncoder().encodeToString(png)
        val imageRedactor = ImageRedactor { body, _ ->
            assertContentEquals(png, body)
            RedactedImage(byteArrayOf(4, 5), detections = 1)
        }
        val t = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")), imageRedactor)
        val body = """{"img":"data:image/png;base64,$encoded","email":"alice@example.com"}""".encodeToByteArray()
        val result = t.transform(body, "application/json", null)
        val output = result.body.decodeToString()
        assertTrue(output.contains("data:image/png;base64,"))
        assertTrue(output.contains("⟨EMAIL_1⟩"))
        assertEquals(2, result.detections) // 1 image + 1 email
    }

    @Test fun `embedded JPEG data URL is redacted`() {
        val jpeg = byteArrayOf(0xff.toByte(), 0xd8.toByte(), 0xff.toByte(), 0xe0.toByte())
        val encoded = java.util.Base64.getEncoder().encodeToString(jpeg)
        val imageRedactor = ImageRedactor { _, _ -> RedactedImage(byteArrayOf(9), detections = 1) }
        val t = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")), imageRedactor)
        val body = """{"img":"data:image/jpeg;base64,$encoded"}""".encodeToByteArray()
        val result = t.transform(body, "application/json", null)
        assertEquals(1, result.detections)
    }

    @Test fun `invalid base64 in data URL is silently skipped`() {
        val imageRedactor = ImageRedactor { _, _ ->
            error("should not be called")
        }
        val t = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")), imageRedactor)
        val body = """{"img":"data:image/png;base64,!!!not-valid-base64!!!"}""".encodeToByteArray()
        val result = t.transform(body, "application/json", null)
        // Original data URL preserved (skipped), no image detections
        val output = result.body.decodeToString()
        assertTrue(output.contains("data:image/png;base64,!!!not-valid-base64!!!"))
    }

    @Test fun `multiple embedded data URLs are all redacted`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val encoded = java.util.Base64.getEncoder().encodeToString(png)
        var callCount = 0
        val imageRedactor = ImageRedactor { _, _ ->
            callCount++
            RedactedImage(byteArrayOf(1), detections = 1)
        }
        val t = BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")), imageRedactor)
        val body = """{"a":"data:image/png;base64,$encoded","b":"data:image/png;base64,$encoded"}""".encodeToByteArray()
        val result = t.transform(body, "application/json", null)
        assertEquals(2, callCount)
        assertEquals(2, result.detections)
    }

    // ── Opaque protocol payload ──

    @Test fun `opaque protocol payload in bytes returns true`() {
        val t = transformer()
        val payload = """{"encrypted_content":"gAAAAAB..."}""".encodeToByteArray()
        assertTrue(t.isOpaqueProtocolPayload(payload))
    }

    @Test fun `clean text body is not opaque`() {
        val t = transformer()
        val payload = "hello world".encodeToByteArray()
        assertEquals(false, t.isOpaqueProtocolPayload(payload))
    }

    @Test fun `binary bytes are not opaque`() {
        val t = transformer()
        val payload = byteArrayOf(0x80.toByte(), 0x81.toByte())
        assertEquals(false, t.isOpaqueProtocolPayload(payload))
    }

    // ── Edge cases ──

    @Test fun `empty body returns empty result`() {
        val t = transformer()
        val result = t.transform(byteArrayOf(), null, null)
        assertEquals(0, result.detections)
        assertEquals(null, result.reason)
        assertEquals(0, result.body.size)
    }

    @Test fun `null content type with PII still redacts`() {
        val t = transformer()
        val body = "alice@example.com".encodeToByteArray()
        val result = t.transform(body, null, null)
        assertEquals(null, result.reason)
        assertEquals(1, result.detections)
    }

    @Test fun `body with only spaces and no PII`() {
        val t = transformer()
        val body = "   \n\t  ".encodeToByteArray()
        val result = t.transform(body, "text/plain", null)
        assertEquals(0, result.detections)
    }
}
