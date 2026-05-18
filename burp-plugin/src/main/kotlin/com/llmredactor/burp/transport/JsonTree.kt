package com.llmredactor.burp.transport

import com.llmredactor.burp.detect.Span
import com.llmredactor.burp.pipeline.RedactionPipeline
import com.llmredactor.burp.redact.Restorer
import org.json.JSONArray
import org.json.JSONObject

/** Recursive walk of JSON values for span collection and placeholder restore. */
object JsonTree {

    fun collectSpans(value: Any?, pipeline: RedactionPipeline): List<Span> =
        when (value) {
            null, JSONObject.NULL -> emptyList()
            is String -> pipeline.detectSpans(value)
            is JSONObject -> buildList {
                for (key in value.keys()) {
                    addAll(collectSpans(value.get(key), pipeline))
                }
            }
            is JSONArray -> buildList {
                for (i in 0 until value.length()) {
                    addAll(collectSpans(value.get(i), pipeline))
                }
            }
            else -> emptyList()
        }

    fun restoreBody(body: String, reverseMap: Map<String, String>): String {
        if (reverseMap.isEmpty() || body.isBlank()) return body
        return try {
            val root = JSONObject(body)
            (restoreValue(root, reverseMap) as JSONObject).toString()
        } catch (_: Exception) {
            body
        }
    }

    private fun restoreValue(value: Any?, reverseMap: Map<String, String>): Any? =
        when (value) {
            null, JSONObject.NULL -> value
            is String -> Restorer.restore(value, reverseMap)
            is JSONObject -> {
                val out = JSONObject()
                for (key in value.keys()) {
                    out.put(key, restoreValue(value.get(key), reverseMap))
                }
                out
            }
            is JSONArray -> {
                val out = JSONArray()
                for (i in 0 until value.length()) {
                    out.put(restoreValue(value.get(i), reverseMap))
                }
                out
            }
            else -> value
        }
}
