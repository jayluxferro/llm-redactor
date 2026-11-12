package org.llmredactor.burp

import com.fasterxml.jackson.databind.ObjectMapper
import com.sun.net.httpserver.HttpServer
import java.net.ConnectException
import java.net.InetSocketAddress
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DetectorClientTest {
    private val mapper = ObjectMapper()
    private var server: HttpServer? = null

    @AfterTest fun stop() {
        server?.stop(0)
    }

    /**
     * A stand-in for `llm-redactor serve`: records each batch it receives and
     * answers with [respond] (texts -> status and JSON body).
     */
    private fun stub(respond: (List<String>) -> Pair<Int, String>): Pair<String, MutableList<List<String>>> {
        val batches = CopyOnWriteArrayList<List<String>>()
        val http = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        http.createContext("/v1/redactor/detect-batch") { exchange ->
            val texts = mapper.readTree(exchange.requestBody.readBytes()).path("texts").map { it.asText() }
            batches += texts
            val (status, body) = respond(texts)
            val bytes = body.toByteArray()
            exchange.sendResponseHeaders(status, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        http.start()
        server = http
        return "http://127.0.0.1:${http.address.port}/v1/redactor/detect-batch" to batches
    }

    /** Every text containing "Alice" gets a person span over it. */
    private fun personSpans(texts: List<String>): Pair<Int, String> {
        val items = texts.map { text ->
            val at = text.indexOf("Alice")
            if (at < 0) emptyList() else listOf(mapOf("start" to at, "end" to at + 5, "kind" to "person", "source" to "ner"))
        }
        return 200 to mapper.writeValueAsString(mapOf("items" to items))
    }

    // ── loopback validation ──

    @Test fun `loopback hosts are accepted, including bracketed IPv6`() {
        // (Other 127/8 addresses are accepted too, but macOS routes only 127.0.0.1.)
        for (endpoint in listOf("http://127.0.0.1:1/x", "http://localhost:1/x", "http://[::1]:1/x")) {
            // Validation passes; nothing listens on port 1.
            assertFailsWith<ConnectException>(endpoint) { DetectorClient(endpoint).detect(listOf("test")) }
        }
    }

    @Test fun `non-loopback endpoints are refused before any connection`() {
        for (endpoint in listOf("http://example.com/x", "http://192.168.1.1:7789/x", "http://127.0.0.1.evil.example/x")) {
            assertFailsWith<IllegalArgumentException>(endpoint) { DetectorClient(endpoint).detect(listOf("test")) }
        }
        assertFailsWith<IllegalArgumentException> {
            DetectorClient("http://example.com/x").redactImage(byteArrayOf(1, 2, 3), "image/png")
        }
    }

    @Test fun `loopback host check`() {
        assertTrue(DetectorClient.isLoopbackHost("[::1]"))
        assertTrue(DetectorClient.isLoopbackHost("LOCALHOST"))
        assertTrue(DetectorClient.isLoopbackHost("127.0.0.2"))
        assertFalse(DetectorClient.isLoopbackHost("127.0.0.1.nip.io"))
        assertFalse(DetectorClient.isLoopbackHost("::2"))
    }

    // ── against a stub service ──

    @Test fun `spans come back per text, in order`() {
        val (endpoint, _) = stub(::personSpans)
        val spans = DetectorClient(endpoint).detect(listOf("hi Alice", "nobody", "Alice"))
        assertEquals(listOf(listOf(3 to 8), emptyList(), listOf(0 to 5)), spans.map { list -> list.map { it.start to it.end } })
        assertEquals("person", spans[0][0].kind)
    }

    @Test fun `large batches are split under the service limit`() {
        // The service answers 413 above 1,000 texts; one big JSON body used
        // to hit that and silently drop to the regex fallback.
        val (endpoint, batches) = stub(::personSpans)
        val texts = List(1_200) { "text $it Alice" }
        val spans = DetectorClient(endpoint).detect(texts)
        assertEquals(1_200, spans.size)
        assertTrue(spans.all { it.size == 1 })
        assertEquals(listOf(500, 500, 200), batches.map { it.size })
    }

    @Test fun `a refused batch is an error, which sends callers to the fallback`() {
        val (endpoint, _) = stub { 413 to """{"error":"too many text fragments"}""" }
        assertFailsWith<IllegalStateException> { DetectorClient(endpoint).detect(listOf("x")) }
        val outcome = TextRedactor(DetectorClient(endpoint)).redact("alice@example.com")
        assertTrue(outcome.usedFallback)
        assertEquals("⟨EMAIL_1⟩", outcome.text)
    }

    @Test fun `a span without offsets fails the batch instead of redacting nothing`() {
        val (endpoint, _) = stub { texts -> 200 to mapper.writeValueAsString(mapOf("items" to texts.map { listOf(mapOf("kind" to "person")) })) }
        assertFailsWith<IllegalStateException> { DetectorClient(endpoint).detect(listOf("Alice")) }
    }

    @Test fun `the redactor sends each distinct text once and uses service spans`() {
        val (endpoint, batches) = stub(::personSpans)
        val redactor = TextRedactor(DetectorClient(endpoint))
        val outcomes = redactor.redactBatch(listOf("Alice says hi", "Alice says hi", "", "plain"))
        assertEquals(listOf("⟨PERSON_1⟩ says hi", "⟨PERSON_1⟩ says hi", "", "plain"), outcomes.map { it.text })
        assertTrue(outcomes.none { it.usedFallback })
        assertEquals(listOf(listOf("Alice says hi", "plain")), batches)
    }

    @Test fun `out-of-range service spans are clamped, not trusted`() {
        val (endpoint, _) = stub { texts ->
            200 to mapper.writeValueAsString(mapOf("items" to texts.map { listOf(mapOf("start" to 3, "end" to 999, "kind" to "x")) }))
        }
        assertEquals("abc⟨X_1⟩", TextRedactor(DetectorClient(endpoint)).redact("abcdef").text)
    }
}
