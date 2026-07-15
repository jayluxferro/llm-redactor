package org.llmredactor.burp

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TextRedactorTest {
    @Test fun `regex fallback redacts email and keeps typed placeholder`() {
        val redactor = TextRedactor(DetectorClient("http://127.0.0.1:1/nope"))
        val result = redactor.redact("email alice@example.com")
        assertTrue(result.usedFallback)
        assertEquals("email ⟨EMAIL_1⟩", result.text)
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

    @Test fun `JPEG and PNG bodies use the local image redactor`() {
        val imageRedactor = ImageRedactor { body, mediaType ->
            assertEquals("image/png", mediaType)
            assertContentEquals(byteArrayOf(1, 2, 3), body)
            RedactedImage(byteArrayOf(9, 8), detections = 2)
        }
        val transformer = BodyTransformer(
            TextRedactor(DetectorClient("http://127.0.0.1:1/nope")),
            imageRedactor,
        )

        val result = transformer.transform(byteArrayOf(1, 2, 3), "image/png", null)
        assertContentEquals(byteArrayOf(9, 8), result.body)
        assertEquals(2, result.detections)
        assertEquals(null, result.reason)
    }

    @Test fun `base64 image attachments use the local image redactor`() {
        val imageRedactor = ImageRedactor { body, mediaType ->
            assertEquals("image/png", mediaType)
            assertContentEquals(byteArrayOf(1, 2, 3), body)
            RedactedImage(byteArrayOf(4, 5), detections = 1)
        }
        val transformer = BodyTransformer(
            TextRedactor(DetectorClient("http://127.0.0.1:1/nope")),
            imageRedactor,
        )
        val result = transformer.transform(
            """{"image_url":"data:image/png;base64,AQID"}""".encodeToByteArray(),
            "application/json",
            null,
        )

        assertEquals(
            """{"image_url":"data:image/png;base64,BAU="}""",
            result.body.decodeToString(),
        )
        assertEquals(1, result.detections)
    }
}
