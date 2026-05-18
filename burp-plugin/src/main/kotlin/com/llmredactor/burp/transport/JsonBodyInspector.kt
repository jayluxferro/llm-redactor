package com.llmredactor.burp.transport

import org.json.JSONObject

/** OpenAI-style chat JSON helpers. */
object JsonBodyInspector {

    fun hasToolsOrFunctions(body: JSONObject): Boolean =
        body.has("tools") || body.has("functions")

    fun parseObject(bodyBytes: ByteArray): JSONObject? =
        try {
            val s = String(bodyBytes, Charsets.UTF_8)
            if (s.isBlank()) null else JSONObject(s)
        } catch (_: Exception) {
            null
        }
}
