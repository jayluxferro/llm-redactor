package org.llmredactor.burp

import com.fasterxml.jackson.databind.ObjectMapper
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
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
    private val json = ObjectMapper()

    private fun transformer(imageRedactor: ImageRedactor = ImageRedactor { _, _ -> error("no image expected") }) =
        BodyTransformer(TextRedactor(DetectorClient("http://127.0.0.1:1/nope")), imageRedactor)

    private fun gzip(bytes: ByteArray): ByteArray =
        ByteArrayOutputStream().also { out -> GZIPOutputStream(out).use { it.write(bytes) } }.toByteArray()

    // ── Responses API (Codex) protocol JSON ──

    @Test fun `Responses request redacts only user-text fields`() {
        val body = """
            {"model":"gpt-5-codex","response_id":"alice@example.com","input":[
              {"type":"input_text","text":"Contact alice@example.com"}
            ],"metadata":{"owner":"bob@example.com"}}
        """.trimIndent().encodeToByteArray()

        val result = transformer().transformResponsesRequest(body, "application/json", null)
        val output = result.body.decodeToString()

        assertEquals(1, result.detections)
        assertTrue(output.contains("\"text\":\"Contact ⟨EMAIL_1⟩\""))
        assertTrue(output.contains("\"response_id\":\"alice@example.com\""))
        assertTrue(output.contains("\"owner\":\"bob@example.com\""))
    }

    @Test fun `Responses request redacts tool output and arguments but never encrypted reasoning`() {
        val fernet = "gAAAAABl9xF5uS1foJ2dK9lM4T3Q8W7Y6X5Z4C3V2B1N0M9L8K7J6H5G4F3E2D1C0="
        val body = """
            {"input":[
              {"type":"reasoning","id":"rs_1","encrypted_content":"$fernet","summary":[]},
              {"type":"function_call","call_id":"call_1","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"cat ~/.netrc\"],\"note\":\"mail alice@example.com\"}"},
              {"type":"function_call_output","call_id":"call_1","output":"login=bob@example.com password=hunter22hunter"}
            ]}
        """.trimIndent().encodeToByteArray()

        val result = transformer().transformResponsesRequest(body, "application/json", null)
        val root = json.readTree(result.body)
        val items = root.path("input")

        assertEquals(fernet, items[0].path("encrypted_content").asText())
        assertEquals("rs_1", items[0].path("id").asText())
        val arguments = json.readTree(items[1].path("arguments").asText()) // still valid JSON
        assertEquals("mail ⟨EMAIL_1⟩", arguments.path("note").asText())
        assertEquals("call_1", items[2].path("call_id").asText())
        val output = items[2].path("output").asText()
        assertTrue("bob@example.com" !in output && "hunter22hunter" !in output, output)
    }

    @Test fun `Responses request preserves invalid JSON`() {
        val body = "{not json".encodeToByteArray()
        val result = transformer().transformResponsesRequest(body, "application/json", null)
        assertEquals("responses-protocol-invalid-json", result.reason)
        assertContentEquals(body, result.body)
    }

    // ── JSON is redacted value by value ──

    @Test fun `numbers and layout survive and only string values change`() {
        // Text-scanning this body turned the timestamp into ⟨PHONE_US_1⟩: invalid JSON.
        val body = """{"created":1731400000,"amount":1.50,"big":123456789012345678901234567890,"text":"mail alice@example.com"}"""
        val result = transformer().transform(body.encodeToByteArray(), "application/json", null)
        assertEquals(
            """{"created":1731400000,"amount":1.50,"big":123456789012345678901234567890,"text":"mail ⟨EMAIL_1⟩"}""",
            result.body.decodeToString(),
        )
    }

    @Test fun `escape sequences are decoded before detection, not split`() {
        // Raw text saw "\nalice@..." and produced "\⟨EMAIL_1⟩", an invalid escape.
        val body = """{"text":"line1\nalice@example.com\t(tab)"}"""
        val result = transformer().transform(body.encodeToByteArray(), "application/json", null)
        val text = json.readTree(result.body).path("text").asText()
        assertEquals("line1\n⟨EMAIL_1⟩\t(tab)", text)
    }

    @Test fun `a JSON body with nothing to redact is forwarded byte for byte`() {
        val body = "{ \"a\" : 1.0 ,\n  \"b\": \"plain\" }".encodeToByteArray()
        val result = transformer().transform(body, "application/json", null)
        assertContentEquals(body, result.body)
        assertEquals(0, result.detections)
    }

    @Test fun `JSON inside a string value is redacted structurally`() {
        val inner = """{"path":"/tmp/x","content":"alice@example.com\nmore"}"""
        val body = json.writeValueAsString(mapOf("tool_calls" to listOf(mapOf("function" to mapOf("arguments" to inner)))))
        val result = transformer().transform(body.encodeToByteArray(), "application/json", null)
        val arguments = json.readTree(result.body).path("tool_calls")[0].path("function").path("arguments").asText()
        val parsed = json.readTree(arguments)
        assertEquals("⟨EMAIL_1⟩\nmore", parsed.path("content").asText())
        assertEquals("/tmp/x", parsed.path("path").asText())
    }

    @Test fun `key context catches JSON secrets that values alone would not`() {
        val body = """{"user":"bob","password":"correct horse battery"}"""
        val result = transformer().transform(body.encodeToByteArray(), "application/json", null)
        assertEquals("""{"user":"bob","password":"⟨PASSWORD_1⟩"}""", result.body.decodeToString())
    }

    @Test fun `ciphertext members are skipped whatever their shape`() {
        val body = """{"encrypted_data":{"note":"alice@example.com"},"text":"bob@example.com"}"""
        val result = transformer().transform(body.encodeToByteArray(), "application/json", null)
        assertEquals("""{"encrypted_data":{"note":"alice@example.com"},"text":"⟨EMAIL_1⟩"}""", result.body.decodeToString())
    }

    @Test fun `one placeholder namespace across all fields of a request`() {
        val body = """{"a":"alice@example.com","b":"bob@example.com","c":"alice@example.com"}"""
        val result = transformer().transform(body.encodeToByteArray(), "application/json", null)
        assertEquals("""{"a":"⟨EMAIL_1⟩","b":"⟨EMAIL_2⟩","c":"⟨EMAIL_1⟩"}""", result.body.decodeToString())
    }

    @Test fun `JSON lines are redacted line by line`() {
        val body = "{\"a\":\"alice@example.com\"}\n{\"b\":2}\r\n{\"c\":\"bob@example.com\"}\n"
        val result = transformer().transform(body.encodeToByteArray(), "application/x-ndjson", null)
        assertEquals("{\"a\":\"⟨EMAIL_1⟩\"}\n{\"b\":2}\r\n{\"c\":\"⟨EMAIL_2⟩\"}\n", result.body.decodeToString())
    }

    @Test fun `JSON without a JSON content type is still parsed`() {
        val body = """  {"n":1731400000,"t":"alice@example.com"}"""
        val result = transformer().transform(body.encodeToByteArray(), "text/plain", null)
        assertEquals("""{"n":1731400000,"t":"⟨EMAIL_1⟩"}""", result.body.decodeToString())
    }

    // ── content encodings ──

    @Test fun `identity encoding returns bytes unchanged`() {
        val body = "hello world".encodeToByteArray()
        assertContentEquals(body, transformer().transform(body, "text/plain", "identity").body)
    }

    @Test fun `null or empty encoding is treated as identity`() {
        val body = "hello world".encodeToByteArray()
        assertContentEquals(body, transformer().transform(body, "text/plain", null).body)
        assertContentEquals(body, transformer().transform(body, "text/plain", "").body)
    }

    @Test fun `gzip round-trip decodes, redacts, and re-encodes`() {
        val compressed = gzip("email alice@example.com here".encodeToByteArray())
        val result = transformer().transform(compressed, "text/plain", "gzip")
        assertEquals(null, result.reason)
        val decompressed = GZIPInputStream(ByteArrayInputStream(result.body)).readBytes().decodeToString()
        assertEquals("email ⟨EMAIL_1⟩ here", decompressed)
        assertEquals(1, result.detections)
    }

    @Test fun `an untouched compressed body is not recompressed`() {
        val compressed = gzip("nothing sensitive".encodeToByteArray())
        assertContentEquals(compressed, transformer().transform(compressed, "text/plain", "gzip").body)
    }

    @Test fun `deflate round-trip decodes, redacts, and re-encodes`() {
        val compressed = ByteArrayOutputStream().use { bos ->
            DeflaterOutputStream(bos).use { it.write("email alice@example.com here".encodeToByteArray()) }
            bos.toByteArray()
        }
        val result = transformer().transform(compressed, "text/plain", "deflate")
        assertEquals(null, result.reason)
        val decompressed = InflaterInputStream(ByteArrayInputStream(result.body)).readBytes().decodeToString()
        assertTrue(decompressed.contains("⟨EMAIL_1⟩"))
    }

    @Test fun `zstd round-trip decodes, redacts, and re-encodes`() {
        val baos = ByteArrayOutputStream()
        com.github.luben.zstd.ZstdOutputStream(baos).use { it.write("email alice@example.com here".encodeToByteArray()) }
        val result = transformer().transform(baos.toByteArray(), "text/plain", "zstd")
        assertEquals(null, result.reason)
        val decompressed = com.github.luben.zstd.ZstdInputStream(ByteArrayInputStream(result.body)).use { it.readBytes() }
        assertTrue(decompressed.decodeToString().contains("⟨EMAIL_1⟩"))
    }

    @Test fun `unsupported encoding returns reason and original body`() {
        val body = "email alice@example.com".encodeToByteArray()
        val result = transformer().transform(body, "text/plain", "br")
        assertTrue(result.reason!!.startsWith("unsupported-encoding"))
        assertContentEquals(body, result.body)
        assertEquals(0, result.detections)
    }

    @Test fun `corrupt gzip data returns reason`() {
        val corrupt = byteArrayOf(0x1f, 0x2e)
        val result = transformer().transform(corrupt, "text/plain", "gzip")
        assertNotNull(result.reason)
        assertContentEquals(corrupt, result.body)
    }

    // ── text bodies ──

    @Test fun `plain text body with email is redacted`() {
        val result = transformer().transform("contact alice@example.com for help".encodeToByteArray(), "text/plain", null)
        assertEquals("contact ⟨EMAIL_1⟩ for help", result.body.decodeToString())
        assertEquals(1, result.detections)
    }

    @Test fun `binary non-UTF-8 body is passed through with reason`() {
        val binary = byteArrayOf(0x80.toByte(), 0x81.toByte(), 0x82.toByte(), 0xff.toByte())
        val result = transformer().transform(binary, "application/octet-stream", null)
        assertEquals("non-utf8-body", result.reason)
        assertContentEquals(binary, result.body)
    }

    @Test fun `binary that happens to be valid UTF-8 is not text-scanned`() {
        val binary = byteArrayOf(0, 1, 2) + "alice@example.com".encodeToByteArray() + byteArrayOf(0)
        val result = transformer().transform(binary, "application/octet-stream", null)
        assertEquals("binary-body", result.reason)
        assertContentEquals(binary, result.body)
    }

    @Test fun `content type with charset parameter is handled`() {
        val result = transformer().transform("email alice@example.com".encodeToByteArray(), "application/json; charset=utf-8", null)
        assertEquals(null, result.reason)
        assertEquals("email ⟨EMAIL_1⟩", result.body.decodeToString())
    }

    // ── form bodies and query strings ──

    @Test fun `form values are redacted and untouched pairs keep their bytes`() {
        val body = "name=bob&email=alice%40example.com&note=a+b%21"
        val result = transformer().transform(body.encodeToByteArray(), "application/x-www-form-urlencoded", null)
        assertEquals("name=bob&email=%E2%9F%A8EMAIL_1%E2%9F%A9&note=a+b%21", result.body.decodeToString())
    }

    @Test fun `a malformed percent escape no longer disables query redaction`() {
        // URLDecoder threw on "%zz" and the whole request went out unredacted.
        val (path, detections) = transformer().transformQuery("/api?q=100%zz&email=alice@example.com")
        assertEquals("/api?q=100%zz&email=%E2%9F%A8EMAIL_1%E2%9F%A9", path)
        assertEquals(1, detections)
    }

    @Test fun `path without query returns unchanged`() {
        val (path, detections) = transformer().transformQuery("/api/users")
        assertEquals("/api/users", path)
        assertEquals(0, detections)
    }

    @Test fun `query param without PII returns unchanged`() {
        val (path, detections) = transformer().transformQuery("/api?name=bob")
        assertEquals("/api?name=bob", path)
        assertEquals(0, detections)
    }

    @Test fun `multiple query params only one with PII`() {
        val (path, detections) = transformer().transformQuery("/api?name=bob&email=alice@example.com&role=admin")
        assertEquals("/api?name=bob&email=%E2%9F%A8EMAIL_1%E2%9F%A9&role=admin", path)
        assertEquals(1, detections)
    }

    @Test fun `query param with missing or empty value is preserved`() {
        assertEquals("/api?flag", transformer().transformQuery("/api?flag").path)
        assertEquals("/api?key=", transformer().transformQuery("/api?key=").path)
    }

    @Test fun `different values in one query get different placeholders`() {
        val (path, detections) = transformer().transformQuery("/api?a=alice@example.com&b=bob@example.com")
        assertEquals("/api?a=%E2%9F%A8EMAIL_1%E2%9F%A9&b=%E2%9F%A8EMAIL_2%E2%9F%A9", path)
        assertEquals(2, detections)
    }

    @Test fun `a query value is detected with its key as context`() {
        val (path, _) = transformer().transformQuery("/login?password=hunter22hunter&next=/home")
        assertEquals("/login?password=%E2%9F%A8PASSWORD_1%E2%9F%A9&next=/home", path)
    }

    // ── multipart ──

    private fun multipart(vararg parts: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        out.write("preamble\r\n".encodeToByteArray())
        for ((headers, body) in parts) {
            out.write("--XyZ\r\n$headers\r\n\r\n".encodeToByteArray())
            out.write(body)
            out.write("\r\n".encodeToByteArray())
        }
        out.write("--XyZ--\r\nepilogue".encodeToByteArray())
        return out.toByteArray()
    }

    @Test fun `multipart text fields are redacted beside a binary file`() {
        val binary = byteArrayOf(0x50, 0x4b, 0x03, 0x04, 0xff.toByte(), 0x00, 0x80.toByte())
        val body = multipart(
            "Content-Disposition: form-data; name=\"email\"" to "alice@example.com".encodeToByteArray(),
            "Content-Disposition: form-data; name=\"file\"; filename=\"a.zip\"\r\nContent-Type: application/zip" to binary,
            "Content-Disposition: form-data; name=\"password\"" to "hunter22hunter".encodeToByteArray(),
        )
        val result = transformer().transform(body, "multipart/form-data; boundary=XyZ", null)
        val expected = multipart(
            "Content-Disposition: form-data; name=\"email\"" to "⟨EMAIL_1⟩".encodeToByteArray(),
            "Content-Disposition: form-data; name=\"file\"; filename=\"a.zip\"\r\nContent-Type: application/zip" to binary,
            "Content-Disposition: form-data; name=\"password\"" to "⟨PASSWORD_1⟩".encodeToByteArray(),
        )
        assertContentEquals(expected, result.body)
        assertEquals(2, result.detections)
    }

    @Test fun `multipart image parts go to the image redactor`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val body = multipart("Content-Disposition: form-data; name=\"img\"; filename=\"a.png\"\r\nContent-Type: image/png" to png)
        val t = transformer(ImageRedactor { bytes, _ ->
            assertContentEquals(png, bytes)
            RedactedImage(byteArrayOf(7), detections = 1)
        })
        val result = t.transform(body, "multipart/form-data; boundary=\"XyZ\"", null)
        assertContentEquals(
            multipart("Content-Disposition: form-data; name=\"img\"; filename=\"a.png\"\r\nContent-Type: image/png" to byteArrayOf(7)),
            result.body,
        )
    }

    // ── protobuf and gRPC ──

    private fun varint(value: Int): ByteArray {
        val out = ByteArrayOutputStream()
        var v = value
        while (v >= 0x80) {
            out.write((v and 0x7f) or 0x80)
            v = v ushr 7
        }
        out.write(v)
        return out.toByteArray()
    }

    private fun lengthDelimited(field: Int, payload: ByteArray) = varint(field shl 3 or 2) + varint(payload.size) + payload

    /** Field 1 (varint 150), field 2 (nested message whose field 3 is [text]). */
    private fun message(text: String) =
        byteArrayOf(0x08, 0x96.toByte(), 0x01) + lengthDelimited(2, lengthDelimited(3, text.encodeToByteArray()))

    @Test fun `nested protobuf strings are redacted with every length recomputed`() {
        val result = transformer().transform(message("mail alice@example.com"), "application/x-protobuf", null)
        assertContentEquals(message("mail ⟨EMAIL_1⟩"), result.body)
        assertEquals(1, result.detections)
    }

    @Test fun `protobuf with varint field is preserved`() {
        val input = byteArrayOf(0x08, 0x96.toByte(), 0x01)
        val result = transformer().transform(input, "application/protobuf", null)
        assertContentEquals(input, result.body)
        assertEquals(0, result.detections)
    }

    @Test fun `protobuf with fixed64 and fixed32 is preserved`() {
        for (input in listOf(byteArrayOf(0x09, 1, 2, 3, 4, 5, 6, 7, 8), byteArrayOf(0x0d, 1, 2, 3, 4))) {
            assertContentEquals(input, transformer().transform(input, "application/protobuf", null).body)
        }
    }

    @Test fun `protobuf wire-type-2 with UTF-8 text is redacted`() {
        val input = lengthDelimited(1, "alice@example.com".encodeToByteArray())
        val result = transformer().transform(input, "application/protobuf", null)
        assertContentEquals(lengthDelimited(1, "⟨EMAIL_1⟩".encodeToByteArray()), result.body)
        assertEquals(1, result.detections)
    }

    @Test fun `protobuf wire-type-2 with binary payload is preserved`() {
        val input = lengthDelimited(1, byteArrayOf(0x80.toByte(), 0x81.toByte(), 0xff.toByte()))
        val result = transformer().transform(input, "application/protobuf", null)
        assertEquals(null, result.reason)
        assertContentEquals(input, result.body)
    }

    @Test fun `malformed protobuf returns invalid-protobuf reason`() {
        val input = byteArrayOf(0x80.toByte())
        val result = transformer().transform(input, "application/protobuf", null)
        assertEquals("invalid-protobuf", result.reason)
        assertContentEquals(input, result.body)
    }

    @Test fun `empty protobuf body is handled`() {
        val result = transformer().transform(byteArrayOf(), "application/protobuf", null)
        assertEquals(null, result.reason)
        assertEquals(0, result.detections)
    }

    private fun frame(flags: Int, message: ByteArray) =
        byteArrayOf(flags.toByte()) + ByteBuffer.allocate(4).putInt(message.size).array() + message

    @Test fun `gRPC frames are redacted with their envelope lengths fixed`() {
        val body = frame(0, message("alice@example.com")) + frame(0, message("plain"))
        val result = transformer().transform(body, "application/grpc", null)
        assertContentEquals(frame(0, message("⟨EMAIL_1⟩")) + frame(0, message("plain")), result.body)
    }

    @Test fun `compressed gRPC messages are passed through with a reason`() {
        val body = frame(1, byteArrayOf(1, 2, 3))
        assertEquals("grpc-compressed-message", transformer().transform(body, "application/grpc", null).reason)
    }

    // ── images ──

    @Test fun `valid JPEG body is forwarded to image redactor`() {
        val jpeg = byteArrayOf(0xff.toByte(), 0xd8.toByte(), 0xff.toByte(), 0xe0.toByte(), 1, 2, 3)
        var called = false
        val t = transformer(ImageRedactor { _, mediaType ->
            assertEquals("image/jpeg", mediaType)
            called = true
            RedactedImage(byteArrayOf(5, 6), detections = 0)
        })
        val result = t.transform(jpeg, "image/jpeg", null)
        assertTrue(called)
        assertEquals(null, result.reason)
        assertContentEquals(jpeg, result.body) // nothing detected: the original goes out
    }

    @Test fun `invalid image signature returns reason`() {
        val invalid = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        val result = transformer().transform(invalid, "image/png", null)
        assertEquals("invalid-image-body", result.reason)
        assertContentEquals(invalid, result.body)
    }

    @Test fun `image redactor exception returns image-redactor-unavailable`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val result = transformer(ImageRedactor { _, _ -> throw RuntimeException("down") }).transform(png, "image/png", null)
        assertEquals("image-redactor-unavailable", result.reason)
        assertContentEquals(png, result.body)
    }

    @Test fun `image with gzip encoding is decoded before redaction`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val t = transformer(ImageRedactor { body, _ ->
            assertContentEquals(png, body)
            RedactedImage(byteArrayOf(1), detections = 1)
        })
        val result = t.transform(gzip(png), "image/png", "gzip")
        assertContentEquals(byteArrayOf(1), GZIPInputStream(ByteArrayInputStream(result.body)).readBytes())
    }

    @Test fun `embedded PNG data URL is redacted in JSON`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val encoded = java.util.Base64.getEncoder().encodeToString(png)
        val t = transformer(ImageRedactor { body, _ ->
            assertContentEquals(png, body)
            RedactedImage(byteArrayOf(4, 5), detections = 1)
        })
        val body = """{"img":"data:image/png;base64,$encoded","email":"alice@example.com"}""".encodeToByteArray()
        val result = t.transform(body, "application/json", null)
        assertEquals("""{"img":"data:image/png;base64,BAU=","email":"⟨EMAIL_1⟩"}""", result.body.decodeToString())
        assertEquals(2, result.detections)
    }

    @Test fun `invalid base64 in data URL is silently skipped`() {
        val body = """{"img":"data:image/png;base64,!!!not-valid-base64!!!"}""".encodeToByteArray()
        val result = transformer().transform(body, "application/json", null)
        assertContentEquals(body, result.body)
    }

    @Test fun `multiple embedded data URLs are all redacted`() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3)
        val encoded = java.util.Base64.getEncoder().encodeToString(png)
        var calls = 0
        val t = transformer(ImageRedactor { _, _ ->
            calls++
            RedactedImage(byteArrayOf(1), detections = 1)
        })
        val body = """{"a":"data:image/png;base64,$encoded","b":"x data:image/png;base64,$encoded y"}""".encodeToByteArray()
        val result = t.transform(body, "application/json", null)
        assertEquals(2, calls)
        assertEquals(2, result.detections)
    }

    // ── opaque protocol payloads ──

    @Test fun `opaque protocol payload is recognised after decompression`() {
        val payload = """{"encrypted_content":"gAAAAAB..."}""".encodeToByteArray()
        assertTrue(transformer().isOpaqueProtocolPayload(payload))
        // A gzip-compressed envelope used to slip past the check.
        assertTrue(transformer().isOpaqueProtocolPayload(gzip(payload), "gzip"))
    }

    @Test fun `clean and binary bodies are not opaque`() {
        assertEquals(false, transformer().isOpaqueProtocolPayload("hello world".encodeToByteArray()))
        assertEquals(false, transformer().isOpaqueProtocolPayload(byteArrayOf(0x80.toByte(), 0x81.toByte())))
    }

    // ── edge cases ──

    @Test fun `empty body returns empty result`() {
        val result = transformer().transform(byteArrayOf(), null, null)
        assertEquals(0, result.detections)
        assertEquals(null, result.reason)
        assertEquals(0, result.body.size)
    }

    @Test fun `null content type with PII still redacts`() {
        val result = transformer().transform("alice@example.com".encodeToByteArray(), null, null)
        assertEquals(null, result.reason)
        assertEquals(1, result.detections)
    }

    @Test fun `body with only spaces and no PII`() {
        assertEquals(0, transformer().transform("   \n\t  ".encodeToByteArray(), "text/plain", null).detections)
    }
}
