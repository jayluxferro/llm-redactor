package org.llmredactor.burp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DetectorClientTest {
    // ── Loopback validation ──

    @Test fun `loopback 127_0_0_1 passes validation`() {
        val client = DetectorClient("http://127.0.0.1:1/v1/redactor/detect-batch")
        // require check passes; connection will be refused → exception caught by caller
        try {
            client.detect(listOf("test"))
        } catch (_: java.net.ConnectException) {
            // expected — loopback validation passed, but no server running
        }
    }

    @Test fun `loopback localhost passes validation`() {
        val client = DetectorClient("http://localhost:1/v1/redactor/detect-batch")
        try {
            client.detect(listOf("test"))
        } catch (_: java.net.ConnectException) {
            // expected — validation passed
        }
    }

    @Test fun `non-loopback endpoint throws on detect`() {
        val client = DetectorClient("http://example.com/v1/redactor/detect-batch")
        assertFailsWith<IllegalArgumentException> {
            client.detect(listOf("test"))
        }
    }

    @Test fun `non-loopback ip throws on detect`() {
        val client = DetectorClient("http://192.168.1.1:7789/v1/redactor/detect-batch")
        assertFailsWith<IllegalArgumentException> {
            client.detect(listOf("test"))
        }
    }

    @Test fun `non-loopback endpoint throws on redactImage`() {
        val client = DetectorClient("http://example.com/v1/redactor/detect-batch")
        assertFailsWith<IllegalArgumentException> {
            client.redactImage(byteArrayOf(1, 2, 3), "image/png")
        }
    }

    // ── Constructor defaults ──

    @Test fun `default constructor uses expected loopback endpoint`() {
        val client = DetectorClient()
        try {
            client.detect(listOf("test"))
        } catch (_: java.net.ConnectException) {
            // Connection refused at default port 7789 → validation passed
        }
    }

    // ── Span parsing (tested indirectly through detect) ──
    // The private span() method parses JSON nodes with defaults.
    // It is exercised when a real detector responds. Since we can't
    // easily mock the HTTP layer, these are covered by integration
    // tests against a running detector service.

    // ── RedactedImage header parsing ──

    @Test fun `redactImage with loopback tries to connect to image endpoint`() {
        val client = DetectorClient("http://127.0.0.1:1/v1/redactor/detect-batch")
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47)
        try {
            client.redactImage(png, "image/png")
        } catch (_: java.net.ConnectException) {
            // expected — no server; endpoint construction and loopback check passed
        }
    }
}
