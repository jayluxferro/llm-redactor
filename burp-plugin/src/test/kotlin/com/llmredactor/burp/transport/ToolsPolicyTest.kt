package com.llmredactor.burp.transport

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ToolsPolicyTest {

    @Test
    fun detectsToolsKey() {
        val body = JSONObject("""{"model":"gpt-4o","messages":[],"tools":[{"type":"function"}]}""")
        assertTrue(JsonBodyInspector.hasToolsOrFunctions(body))
    }

    @Test
    fun plainChatHasNoTools() {
        val body = JSONObject("""{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}""")
        assertFalse(JsonBodyInspector.hasToolsOrFunctions(body))
    }
}
