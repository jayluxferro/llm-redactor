package org.llmredactor.burp

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.net.ProxySelector
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** Calls only the local redactor service; callers fall back to RegexDetector on any failure. */
class DetectorClient(
    private val endpoint: String = "http://127.0.0.1:7789/v1/redactor/detect-batch",
    private val detectTimeout: Duration = Duration.ofSeconds(30),
) {
    private val mapper = ObjectMapper()

    // Burp (and the host JVM) may have an outbound proxy configured. The detector is
    // strictly loopback-only, so bypass any such proxy to avoid proxy loops or sending
    // detector payloads to an unintended listener.
    private val http = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(2))
        // Uvicorn serves this local endpoint over HTTP/1.1. Pinning the client avoids
        // Java's clear-text HTTP/2 (h2c) upgrade probe, which Uvicorn correctly logs
        // as an unsupported upgrade followed by an invalid HTTP/2 preface.
        .version(HttpClient.Version.HTTP_1_1)
        .proxy(ProxySelector.of(null))
        .build()

    /**
     * Spans for each text, in order. Large batches are split: the service
     * refuses more than 1,000 texts per call (413), which used to send every
     * big JSON body to the weaker regex fallback. The timeout allows for NER
     * on large bodies; 5 s did not, with the same result.
     */
    fun detect(texts: List<String>): List<List<Span>> {
        require(isLoopback(endpoint)) { "Detector endpoint must be loopback" }
        val out = ArrayList<List<Span>>(texts.size)
        for (chunk in chunked(texts)) out += detectChunk(chunk)
        return out
    }

    private fun chunked(texts: List<String>): List<List<String>> {
        val chunks = ArrayList<List<String>>()
        var current = ArrayList<String>()
        var chars = 0L
        for (text in texts) {
            if (current.isNotEmpty() && (current.size >= MAX_TEXTS_PER_CALL || chars + text.length > MAX_CHARS_PER_CALL)) {
                chunks += current
                current = ArrayList()
                chars = 0
            }
            current += text
            chars += text.length
        }
        if (current.isNotEmpty()) chunks += current
        return chunks
    }

    private fun detectChunk(texts: List<String>): List<List<Span>> {
        val payload = mapper.writeValueAsString(mapOf("texts" to texts))
        val request = HttpRequest.newBuilder(URI(endpoint))
            .timeout(detectTimeout)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload))
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofString())
        check(response.statusCode() == 200) { "detector returned ${response.statusCode()}" }
        val items = mapper.readTree(response.body()).path("items")
        check(items.isArray && items.size() == texts.size) { "detector returned an invalid batch" }
        return items.map { item ->
            check(item.isArray) { "detector returned an invalid span list" }
            item.map(::span)
        }
    }

    fun redactImage(body: ByteArray, mediaType: String): RedactedImage {
        require(isLoopback(endpoint)) { "Detector endpoint must be loopback" }
        val request = HttpRequest.newBuilder(endpointFor("/v1/redactor/redact-image"))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type", mediaType)
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofByteArray())
        check(response.statusCode() == 200) { "image redactor returned ${response.statusCode()}" }
        val detections = response.headers().firstValue("X-LLM-Redactor-Detections")
            .orElse("0").toIntOrNull() ?: 0
        return RedactedImage(response.body(), detections)
    }

    private fun span(node: JsonNode): Span {
        // A span without offsets cannot be applied; failing the batch sends it
        // to the regex fallback instead of silently redacting nothing.
        check(node.path("start").isInt && node.path("end").isInt) { "detector returned a span without offsets" }
        return Span(
            start = node.path("start").asInt(),
            end = node.path("end").asInt(),
            kind = node.path("kind").asText("sensitive"),
            confidence = node.path("confidence").asDouble(1.0),
            source = node.path("source").asText("local"),
        )
    }

    private fun endpointFor(path: String): URI {
        val base = URI(endpoint)
        return URI(base.scheme, base.userInfo, base.host, base.port, path, null, null)
    }

    companion object {
        const val MAX_TEXTS_PER_CALL = 500
        const val MAX_CHARS_PER_CALL = 2_000_000L

        /** URI.getHost() keeps IPv6 brackets, so "[::1]" is the form that arrives here. */
        internal fun isLoopback(value: String): Boolean {
            val host = try {
                URI(value).host
            } catch (_: Exception) {
                null
            } ?: return false
            return isLoopbackHost(host)
        }

        internal fun isLoopbackHost(host: String): Boolean {
            val h = host.lowercase().removePrefix("[").removeSuffix("]")
            return h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1" ||
                Regex("""127(?:\.\d{1,3}){3}""").matches(h)
        }
    }
}

data class RedactedImage(val body: ByteArray, val detections: Int)
