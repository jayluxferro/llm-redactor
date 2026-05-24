package com.llmredactor.burp.transport

import com.llmredactor.burp.detect.Span
import com.llmredactor.burp.pipeline.RedactionPipeline
import com.llmredactor.burp.redact.PlaceholderGenerator
import com.llmredactor.burp.redact.redact
import org.json.JSONArray
import org.json.JSONObject

/**
 * Unified redact (outbound) and optional restore (inbound) for JSON and Connect/protobuf.
 * Restore is off by default so agent responses (tool/file payloads) stay verbatim.
 */
object BodyProcessor {

    data class Summary(val totalSpans: Int, val kindCounts: Map<String, Int>)

    data class RedactOutcome(
        val bytes: ByteArray,
        val reverseMap: Map<String, String>,
        val summary: Summary,
        val httpCompression: ConnectProtoCodec.HttpCompression,
    )

    /**
     * Run detection on the same text fields that [redactRequest] would touch,
     * without mutating the body. Used for strict-mode refusal before redaction.
     */
    fun collectSpans(
        rawBytes: ByteArray,
        format: BodyFormat,
        contentEncoding: String,
        pipeline: RedactionPipeline,
    ): List<Span> {
        if (rawBytes.isEmpty() || format == BodyFormat.UNSUPPORTED) {
            return emptyList()
        }
        val http = ConnectProtoCodec.decodeHttpBody(rawBytes, contentEncoding)
        return when (format) {
            BodyFormat.JSON -> collectJsonSpans(http.bytes, pipeline)
            BodyFormat.CONNECT_PROTO -> collectProtoSpans(http.bytes, pipeline)
            else -> emptyList()
        }
    }

    fun redactRequest(
        rawBytes: ByteArray,
        format: BodyFormat,
        contentEncoding: String,
        pipeline: RedactionPipeline,
        tag: String?,
    ): RedactOutcome? {
        if (rawBytes.isEmpty() || format == BodyFormat.UNSUPPORTED) return null

        val http = ConnectProtoCodec.decodeHttpBody(rawBytes, contentEncoding)
        val inner = when (format) {
            BodyFormat.JSON -> redactJson(http.bytes, pipeline, tag)
            BodyFormat.CONNECT_PROTO -> redactConnectProto(http.bytes, pipeline, tag)
            else -> null
        } ?: return null
        val wire = ConnectProtoCodec.encodeHttpBody(inner.bytes, http.httpContentEncoding)
        return RedactOutcome(wire.bytes, inner.reverseMap, inner.summary, http.httpContentEncoding)
    }

    fun restoreResponse(
        rawBytes: ByteArray,
        format: BodyFormat,
        contentEncoding: String,
        reverseMap: Map<String, String>,
    ): ByteArray? {
        if (rawBytes.isEmpty() || reverseMap.isEmpty()) return null
        if (format == BodyFormat.UNSUPPORTED) return null

        val http = ConnectProtoCodec.decodeHttpBody(rawBytes, contentEncoding)
        val inner = when (format) {
            BodyFormat.JSON -> {
                val text = String(http.bytes, Charsets.UTF_8)
                TransportLogic.restoreJsonBody(text, reverseMap)
                    .let { TransportLogic.fixSurrogates(it) }
                    .toByteArray(Charsets.UTF_8)
            }
            BodyFormat.CONNECT_PROTO -> restoreConnectProto(http.bytes, reverseMap)
            else -> return null
        }
        return ConnectProtoCodec.encodeHttpBody(inner, http.httpContentEncoding).bytes
    }

    private data class JsonRedact(val bytes: ByteArray, val reverseMap: Map<String, String>, val summary: Summary)

    private fun collectJsonSpans(bodyBytes: ByteArray, pipeline: RedactionPipeline): List<Span> {
        val bodyStr = String(bodyBytes, Charsets.UTF_8)
        if (bodyStr.isBlank()) return emptyList()
        return try {
            JsonTree.collectSpans(JSONObject(bodyStr), pipeline)
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun collectProtoSpans(bodyBytes: ByteArray, pipeline: RedactionPipeline): List<Span> {
        val all = mutableListOf<Span>()
        val wire = ConnectProtoCodec.parse(bodyBytes)
        for (frame in wire.frames) {
            ProtobufRedactor.forEachTextField(frame.payload) { text ->
                all.addAll(pipeline.detectSpans(text))
            }
        }
        return all
    }

    private fun redactJson(
        bodyBytes: ByteArray,
        pipeline: RedactionPipeline,
        tag: String?,
    ): JsonRedact? {
        val bodyStr = String(bodyBytes, Charsets.UTF_8)
        if (bodyStr.isBlank()) return null
        val body = try {
            JSONObject(bodyStr)
        } catch (_: Exception) {
            return null
        }
        val gen = PlaceholderGenerator(tag)
        val combined = mutableMapOf<String, String>()
        val kinds = mutableMapOf<String, Int>()
        val redacted = redactJsonValue(body, pipeline, gen, combined, kinds) as? JSONObject ?: return null
        if (combined.isEmpty()) return null
        val out = TransportLogic.fixSurrogates(redacted.toString()).toByteArray(Charsets.UTF_8)
        return JsonRedact(out, combined, Summary(combined.size, kinds))
    }

    private fun redactJsonValue(
        value: Any?,
        pipeline: RedactionPipeline,
        gen: PlaceholderGenerator,
        combined: MutableMap<String, String>,
        kinds: MutableMap<String, Int>,
    ): Any? = when (value) {
        null, JSONObject.NULL -> value
        is String -> {
            val r = redact(value, pipeline.detectSpans(value), gen)
            combined.putAll(r.reverseMap)
            r.reverseMap.keys.forEach { ph -> kinds.merge(kindOf(ph), 1, Int::plus) }
            r.redactedText
        }
        is JSONObject -> {
            val out = JSONObject()
            for (key in value.keys()) {
                out.put(key, redactJsonValue(value.get(key), pipeline, gen, combined, kinds))
            }
            out
        }
        is JSONArray -> {
            val out = JSONArray()
            for (i in 0 until value.length()) {
                out.put(redactJsonValue(value.get(i), pipeline, gen, combined, kinds))
            }
            out
        }
        else -> value
    }

    private fun redactConnectProto(
        bodyBytes: ByteArray,
        pipeline: RedactionPipeline,
        tag: String?,
    ): JsonRedact? {
        val gen = PlaceholderGenerator(tag)
        val wire = ConnectProtoCodec.parse(bodyBytes)
        val (redactedWire, reverse) = ConnectProtoCodec.redactPayloads(wire) { payload ->
            val (out, map) = ProtobufRedactor.redact(payload) { text ->
                redact(text, pipeline.detectSpans(text), gen)
            }
            out to map
        }
        if (reverse.isEmpty()) return null
        val kinds = mutableMapOf<String, Int>()
        reverse.keys.forEach { ph -> kinds.merge(kindOf(ph), 1, Int::plus) }
        val serialized = ConnectProtoCodec.serialize(redactedWire)
        return JsonRedact(serialized, reverse, Summary(reverse.size, kinds))
    }

    private fun restoreConnectProto(bodyBytes: ByteArray, reverseMap: Map<String, String>): ByteArray {
        val wire = ConnectProtoCodec.parse(bodyBytes)
        val restored = ConnectProtoCodec.redactPayloads(wire) { payload ->
            ProtobufRedactor.restore(payload, reverseMap) to emptyMap()
        }.first
        return ConnectProtoCodec.serialize(restored)
    }

    private fun kindOf(ph: String): String =
        ph.removePrefix("⟨").removeSuffix("⟩").split("·").first()
            .split("_").dropLast(1).joinToString("_").lowercase()
}
