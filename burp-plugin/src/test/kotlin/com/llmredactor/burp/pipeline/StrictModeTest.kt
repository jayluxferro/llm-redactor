package com.llmredactor.burp.pipeline

import com.llmredactor.burp.detect.Span
import com.llmredactor.burp.transport.BodyFormat
import com.llmredactor.burp.transport.BodyProcessor
import com.llmredactor.burp.transport.TestConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class StrictModeTest {

    @Test
    fun strictRefusalSpans_filtersLowConfidenceWhenStrictOn() {
        val config = TestConfig.plugin()
        config.strict = true
        val pipeline = RedactionPipeline(config)
        val spans = listOf(
            Span(0, 16, "email", 1.0, "a@b.com", "regex"),
            Span(20, 25, "person", 0.35, "Alice", "ner"),
        )
        val refused = pipeline.strictRefusalSpans(spans)
        assertEquals(1, refused.size)
        assertEquals("person", refused[0].kind)
    }

    @Test
    fun strictRefusalSpans_emptyWhenStrictOff() {
        val pipeline = RedactionPipeline(TestConfig.plugin())
        val spans = listOf(Span(0, 5, "person", 0.1, "x", "ner"))
        assertTrue(pipeline.strictRefusalSpans(spans).isEmpty())
    }

    @Test
    fun collectSpans_jsonMessages_includesRegexDetections() {
        val pipeline = RedactionPipeline(TestConfig.plugin())
        val body = """
            {"messages":[{"role":"user","content":"Email jane@example.com please"}]}
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val spans = BodyProcessor.collectSpans(body, BodyFormat.JSON, "", pipeline)
        assertTrue(spans.any { it.kind == "email" })
        assertTrue(pipeline.strictRefusalSpans(spans).isEmpty())
    }
}
