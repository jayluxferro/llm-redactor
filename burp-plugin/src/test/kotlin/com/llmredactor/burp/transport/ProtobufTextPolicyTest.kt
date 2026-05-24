package com.llmredactor.burp.transport

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ProtobufTextPolicyTest {

    @Test
    fun scansNaturalLanguage() {
        assertTrue(ProtobufTextPolicy.shouldScanUtf8String("Contact jane@example.com today"))
    }

    @Test
    fun skipsHexBlob() {
        assertFalse(ProtobufTextPolicy.shouldScanUtf8String("a".repeat(64)))
    }

    @Test
    fun scansEmbeddedJson() {
        assertTrue(ProtobufTextPolicy.shouldScanUtf8String("""{"email":"x@y.com"}"""))
    }

    @Test
    fun rejectsMalformedUtf8Bytes() {
        val invalid = byteArrayOf(0xC3.toByte(), 0x28.toByte())
        assertFalse(ProtobufTextPolicy.isValidUtf8(invalid))
    }
}
