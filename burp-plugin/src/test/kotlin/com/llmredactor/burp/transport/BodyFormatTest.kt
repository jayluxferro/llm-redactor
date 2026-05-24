package com.llmredactor.burp.transport

import com.llmredactor.burp.pipeline.RedactionPipeline
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.json.JSONObject

class BodyFormatTest {

    @Test
    fun tracesPathUsesProtobufFormat() {
        assertEquals(
            BodyFormat.CONNECT_PROTO,
            BodyFormatDetector.detect("application/x-protobuf"),
        )
        assertEquals(
            BodyFormat.JSON,
            BodyFormatDetector.detect("application/json"),
        )
    }

    @Test
    fun defaultPathsIncludeTraces() {
        val paths = TestConfig.plugin().targetPaths
        assertTrue(TargetMatcher.isTargetPath("/v1/traces", paths))
    }

    @Test
    fun redactsEmailInOtlpStyleJson() {
        val body = JSONObject()
            .put(
                "resourceSpans",
                org.json.JSONArray().put(
                    JSONObject().put(
                        "scopeSpans",
                        org.json.JSONArray().put(
                            JSONObject().put(
                                "spans",
                                org.json.JSONArray().put(
                                    JSONObject().put(
                                        "attributes",
                                        org.json.JSONArray().put(
                                            JSONObject()
                                                .put("key", "user.email")
                                                .put(
                                                    "value",
                                                    JSONObject().put("stringValue", "trace-leak@corp.com"),
                                                ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            .toString()
            .toByteArray(Charsets.UTF_8)

        val pipeline = RedactionPipeline(TestConfig.plugin())
        val outcome = BodyProcessor.redactRequest(
            body,
            BodyFormat.JSON,
            "",
            pipeline,
            null,
        )
        assertTrue(outcome != null && outcome.reverseMap.isNotEmpty())
        assertFalse(String(outcome!!.bytes).contains("trace-leak@corp.com"))
    }
}
