package com.llmredactor.burp.transport

import com.llmredactor.burp.detect.Span
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * Optional HTTP client that calls a local NER endpoint to augment regex spans.
 *
 * The expected request/response contract:
 *   POST <endpoint>
 *   Body: {"text": "..."}
 *   Response: [{"start":0,"end":5,"kind":"person","confidence":0.92,"text":"Alice","source":"ner"}]
 *
 * Falls back silently (empty list) on any error, so regex-only mode is unaffected.
 *
 * This is compatible with the running llm-redactor HTTP proxy's NER endpoint.
 */
object NerClient {

    // Force HTTP/1.1 — Java's HttpClient defaults to HTTP/2, which sends an
    // "Upgrade: h2c" header on cleartext POSTs.  uvicorn with the standard
    // (websockets) extras consumes the request body during the upgrade
    // handshake, so the FastAPI handler sees an empty body.
    private val client: HttpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_1_1)
        .connectTimeout(Duration.ofSeconds(3))
        .build()

    fun detect(text: String, endpoint: String): List<Span> {
        if (endpoint.isBlank()) return emptyList()
        return try {
            val body = JSONObject().put("text", text).toString()
            val request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint.trimEnd('/')))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()

            val response = client.send(request, HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() != 200) return emptyList()

            parseSpans(response.body())
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun parseSpans(json: String): List<Span> {
        val arr = JSONArray(json)
        return (0 until arr.length()).map { i ->
            val obj = arr.getJSONObject(i)
            Span(
                start      = obj.getInt("start"),
                end        = obj.getInt("end"),
                kind       = obj.getString("kind"),
                confidence = obj.optDouble("confidence", 1.0),
                text       = obj.getString("text"),
                source     = obj.optString("source", "ner"),
            )
        }
    }

    /** Quick connectivity test — returns true if the endpoint responds with 200. */
    fun test(endpoint: String): Boolean {
        if (endpoint.isBlank()) return false
        return try {
            val body = JSONObject().put("text", "test").toString()
            val request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint.trimEnd('/')))
                .timeout(Duration.ofSeconds(3))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()
            val response = client.send(request, HttpResponse.BodyHandlers.ofString())
            response.statusCode() == 200
        } catch (_: Exception) {
            false
        }
    }
}
