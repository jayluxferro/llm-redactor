package org.llmredactor.burp

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.net.URI
import java.net.ProxySelector
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** Calls only the local redactor service; callers fall back to RegexDetector on any failure. */
class DetectorClient(private val endpoint: String = "http://127.0.0.1:7789/v1/redactor/detect-batch") {
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

    fun detect(texts: List<String>): List<List<Span>> {
        require(isLoopback(endpoint)) { "Detector endpoint must be loopback" }
        val payload = mapper.writeValueAsString(mapOf("texts" to texts))
        val request = HttpRequest.newBuilder(URI(endpoint))
            .timeout(Duration.ofSeconds(5))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload))
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofString())
        check(response.statusCode() == 200) { "detector returned ${response.statusCode()}" }
        val items = mapper.readTree(response.body()).path("items")
        check(items.isArray && items.size() == texts.size) { "detector returned an invalid batch" }
        return items.map { item -> item.map(::span) }
    }

    private fun span(node: JsonNode) = Span(
        start = node.path("start").asInt(), end = node.path("end").asInt(),
        kind = node.path("kind").asText("sensitive"), confidence = node.path("confidence").asDouble(1.0),
        source = node.path("source").asText("local"),
    )

    private fun isLoopback(value: String): Boolean {
        val host = URI(value).host ?: return false
        return host == "localhost" || host == "127.0.0.1" || host == "::1"
    }
}
