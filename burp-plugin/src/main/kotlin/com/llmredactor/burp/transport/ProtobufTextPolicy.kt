package com.llmredactor.burp.transport

import java.nio.charset.StandardCharsets

/**
 * Heuristics for which protobuf length-delimited fields are worth scanning.
 * Wire format has no field names — reduces noise on hashes, tokens, and blobs.
 */
object ProtobufTextPolicy {

    private val HEX_BLOB = Regex("^[0-9a-fA-F]{32,}$")
    private val BASE64_BLOB = Regex("^[A-Za-z0-9+/]{40,}={0,2}$")
    private val UUID_ONLY = Regex(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    )

    /** Strict UTF-8 (no malformed sequences). */
    fun isValidUtf8(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return false
        return try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes))
            true
        } catch (_: CharacterCodingException) {
            false
        }
    }

    fun shouldScanUtf8String(text: String): Boolean {
        if (text.length < 3) return false
        if (text[0] == '\u0000') return false
        val trimmed = text.trim()
        if (trimmed.length < 3) return false

        // Embedded JSON / chat payloads in a string field (common in agent RPCs).
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) return true

        if (HEX_BLOB.matches(trimmed)) return false
        if (BASE64_BLOB.matches(trimmed)) return false
        if (UUID_ONLY.matches(trimmed)) return false

        var printable = 0
        for (ch in text) {
            if (ch == '\n' || ch == '\r' || ch == '\t' || ch in ' '..'~' || ch > '\u00a0') {
                printable++
            }
        }
        return printable * 4 >= text.length * 3
    }
}
