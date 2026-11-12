package org.llmredactor.burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.BinaryMessageAction
import burp.api.montoya.websocket.Direction
import burp.api.montoya.websocket.MessageHandler
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.TextMessageAction
import burp.api.montoya.websocket.WebSocketCreated
import burp.api.montoya.websocket.WebSocketCreatedHandler
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.Timer
import javax.swing.table.AbstractTableModel
import burp.api.montoya.core.ByteArray as BurpBytes

class BurpLlmRedactor : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("LLM Redactor")
        val activity = ActivityLog()
        // One HTTP client for text detection and image redaction.
        val detector = DetectorClient()
        val transformer = BodyTransformer(TextRedactor(detector), LocalImageRedactor(detector))
        api.http().registerHttpHandler(RequestRedactionHandler(transformer, activity))
        api.websockets().registerWebSocketCreatedHandler(WebSocketRedactionHandler(activity, transformer))
        api.userInterface().registerSuiteTab("LLM Redactor", ActivityPanel(activity))
        api.logging().logToOutput(
            "LLM Redactor loaded: HTTP request queries and bodies are redacted through the local " +
                "detector service (built-in detector when it is down); client-to-server WebSocket text " +
                "frames always use the built-in detector. Responses and binary WebSocket frames are not modified.",
        )
    }
}

/** Which requests are touched, and how. Pure functions, so they are unit-tested. */
internal object RedactionPolicy {
    // OpenAI Responses API endpoints (Codex's ChatGPT backend, the public API, Azure).
    private val RESPONSES_PATHS = listOf(
        "/backend-api/codex/responses",
        "/v1/responses",
        "/openai/v1/responses",
        "/openai/responses",
    )
    private val SIGNED_QUERY = Regex("(?i)[?&]X-(?:Amz|Goog)-Signature=")

    fun isResponsesApiPath(path: String): Boolean = RESPONSES_PATHS.any { path == it || path.startsWith("$it/") }

    fun isResponsesApiRequest(method: String, path: String): Boolean =
        method.equals("POST", ignoreCase = true) && isResponsesApiPath(path)

    /**
     * A signature covers the bytes we would rewrite, so the request goes out
     * as is (and is logged). SigV4 puts it in the Authorization header far
     * more often than in X-Amz-Content-Sha256, which was the only signal
     * checked before.
     */
    fun isSignedRequest(path: String, authorization: String?, hasAmzContentSha256: Boolean): Boolean =
        hasAmzContentSha256 ||
            authorization?.trimStart()?.startsWith("AWS4-HMAC-SHA256", ignoreCase = true) == true ||
            SIGNED_QUERY.containsMatchIn(path)
}

private class WebSocketRedactionHandler(
    private val activity: ActivityLog,
    private val transformer: BodyTransformer,
) : WebSocketCreatedHandler {
    override fun handleWebSocketCreated(created: WebSocketCreated) {
        val upgrade = created.upgradeRequest()
        val host = upgrade.httpService().host()
        if (DetectorClient.isLoopbackHost(host)) return
        val responsesApi = RedactionPolicy.isResponsesApiPath(upgrade.pathWithoutQuery())
        // One namespace per connection: frames of one conversation must not
        // reuse ⟨EMAIL_1⟩ for two different people.
        val naming = PlaceholderNaming()
        val binaryLogged = AtomicBoolean(false)
        created.webSocket().registerMessageHandler(object : MessageHandler {
            override fun handleTextMessage(message: TextMessage): TextMessageAction {
                if (message.direction() != Direction.CLIENT_TO_SERVER) return TextMessageAction.continueWith(message)
                return try {
                    redact(message)
                } catch (_: Exception) {
                    failed(message)
                } catch (_: StackOverflowError) {
                    failed(message)
                }
            }

            // Built-in detector only: even a loopback round trip can stall a
            // streaming connection until clients such as Codex give up on it.
            private fun redact(message: TextMessage): TextMessageAction {
                val payload = message.payload()
                val result = when {
                    responsesApi -> transformer.transformResponsesText(payload, naming, regexOnly = true)
                        ?: transformer.transformText(payload, null, naming, regexOnly = true)
                    TextRedactor.isOpaqueProtocolPayload(payload) -> {
                        activity.add(Activity("WebSocket", host, "passed-through", detail = "encrypted-protocol-payload"))
                        return TextMessageAction.continueWith(message)
                    }
                    else -> transformer.transformText(payload, null, naming, regexOnly = true)
                }
                if (result.detections == 0) return TextMessageAction.continueWith(message)
                activity.add(Activity("WebSocket", host, "redacted-built-in-detector", result.detections))
                return TextMessageAction.continueWith(result.text)
            }

            private fun failed(message: TextMessage): TextMessageAction {
                activity.add(Activity("WebSocket", host, "passed-through", detail = "redaction-error"))
                return TextMessageAction.continueWith(message)
            }

            override fun handleBinaryMessage(message: BinaryMessage): BinaryMessageAction {
                // Logged once per connection, not once per frame.
                if (message.direction() == Direction.CLIENT_TO_SERVER && binaryLogged.compareAndSet(false, true)) {
                    activity.add(Activity("WebSocket", host, "passed-through", detail = "binary-frames"))
                }
                return BinaryMessageAction.continueWith(message)
            }
        })
    }
}

private class RequestRedactionHandler(
    private val transformer: BodyTransformer,
    private val activity: ActivityLog,
) : HttpHandler {
    override fun handleHttpRequestToBeSent(request: HttpRequestToBeSent): RequestToBeSentAction {
        val host = request.httpService().host()
        if (DetectorClient.isLoopbackHost(host)) return RequestToBeSentAction.continueWith(request)
        val signed = RedactionPolicy.isSignedRequest(
            request.path(),
            request.headerValue("Authorization"),
            request.hasHeader("X-Amz-Content-Sha256"),
        )
        if (signed) {
            activity.add(Activity("HTTP", host, "passed-through", detail = "signed-request"))
            return RequestToBeSentAction.continueWith(request)
        }
        return try {
            redact(request, host)
        } catch (_: Exception) {
            activity.add(Activity("HTTP", host, "passed-through", detail = "transform-error"))
            RequestToBeSentAction.continueWith(request)
        } catch (_: StackOverflowError) {
            // A regex on hostile input; never let it escape into Burp's handler thread.
            activity.add(Activity("HTTP", host, "passed-through", detail = "transform-error"))
            RequestToBeSentAction.continueWith(request)
        }
    }

    private fun redact(request: HttpRequestToBeSent, host: String): RequestToBeSentAction {
        // One namespace for the query and every body field of this request.
        val naming = PlaceholderNaming()
        val query = transformer.transformQuery(request.path(), naming)
        val body = request.body().getBytes()
        val contentType = request.headerValue("Content-Type")
        val contentEncoding = request.headerValue("Content-Encoding")
        val result = when {
            body.isEmpty() -> BodyTransform(body, 0, false)
            // Before the opaque check: this path never touches encrypted items,
            // and Codex replays them in nearly every request after the first.
            RedactionPolicy.isResponsesApiRequest(request.method(), request.pathWithoutQuery()) ->
                transformer.transformResponsesRequest(body, contentType, contentEncoding, naming)
            transformer.isOpaqueProtocolPayload(body, contentEncoding) ->
                BodyTransform(body, 0, false, "encrypted-protocol-payload")
            else -> transformer.transform(body, contentType, contentEncoding, naming)
        }
        val bodyDetections = if (result.reason == null) result.detections else 0
        var updated: HttpRequest = request
        if (query.detections > 0) updated = updated.withPath(query.path)
        if (bodyDetections > 0) updated = updated.withBody(BurpBytes.byteArray(*result.body))
        val detections = query.detections + bodyDetections
        when {
            result.reason != null -> activity.add(
                Activity(
                    "HTTP",
                    host,
                    if (query.detections > 0) "query-redacted-body-passed-through" else "passed-through",
                    query.detections,
                    result.reason,
                ),
            )
            detections > 0 -> activity.add(
                Activity(
                    "HTTP",
                    host,
                    if (query.usedFallback || result.usedFallback) "redacted-regex-fallback" else "redacted-local-detector",
                    detections,
                ),
            )
        }
        return RequestToBeSentAction.continueWith(updated)
    }

    override fun handleHttpResponseReceived(response: HttpResponseReceived): ResponseReceivedAction {
        val request = response.initiatingRequest()
        val status = response.statusCode()
        // Status and size first: no other response is ever copied into a String here.
        if (status == 400.toShort() && response.body().length() <= 64 &&
            BlockedRequestCompatibility.isCanonicalBurpBlock(
                status,
                response.bodyToString(),
                request.method(),
                request.pathWithoutQuery(),
            )
        ) {
            // Burp may deliberately block fire-and-forget endpoints. Some clients
            // treat that local rejection as a transport failure, so acknowledge it
            // without allowing the request to leave Burp or retaining its payload.
            activity.add(
                Activity(
                    "HTTP",
                    request.httpService().host(),
                    "burp-block-acknowledged",
                    detail = "${request.method()} ${request.pathWithoutQuery()}",
                ),
            )
            return ResponseReceivedAction.continueWith(
                response.withStatusCode(204).withReasonPhrase("No Content").withBody(BurpBytes.byteArray(*byteArrayOf())),
            )
        }

        // Routing metadata only, and never the query string: presigned URLs
        // carry their signature there, and the log is shown on screen.
        if (status >= 400) {
            activity.add(
                Activity(
                    "HTTP",
                    request.httpService().host(),
                    "response-$status",
                    detail = "${request.method()} ${request.pathWithoutQuery()}",
                ),
            )
        }
        return ResponseReceivedAction.continueWith(response)
    }
}

/**
 * Acknowledge Burp's canonical local block response, `400 {"detail":"Bad Request"}`,
 * with a 204; it never permits egress. Only that exact response qualifies:
 * matching any one-field `{"detail": ...}` at 400 or 403 turned real upstream
 * refusals (FastAPI-style `403 {"detail":"Not authenticated"}`) into silent
 * successes. Responses API streams are excluded: they need the real event
 * sequence.
 */
internal object BlockedRequestCompatibility {
    private val canonicalBlock = Regex("""^\s*\{\s*"detail"\s*:\s*"Bad Request"\s*\}\s*$""")

    fun isCanonicalBurpBlock(statusCode: Short, body: String, method: String, path: String): Boolean =
        statusCode == 400.toShort() &&
            !RedactionPolicy.isResponsesApiRequest(method, path) &&
            canonicalBlock.matches(body)
}

private class ActivityPanel(private val activity: ActivityLog) : JPanel(BorderLayout()) {
    private val activityTableModel = ActivityTableModel()
    private val refreshTimer = Timer(500) { activityTableModel.replace(activity.snapshot()) }

    init {
        val header = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        header.add(JLabel("Live activity — payloads and detected values are never stored."))
        header.add(
            JButton("Clear").apply {
                addActionListener {
                    activity.clear()
                    activityTableModel.replace(emptyList<Activity>())
                }
            },
        )
        add(header, BorderLayout.NORTH)

        val table = JTable(activityTableModel).apply {
            fillsViewportHeight = true
            autoCreateRowSorter = true
        }
        add(JScrollPane(table), BorderLayout.CENTER)
        activityTableModel.replace(activity.snapshot())
    }

    override fun addNotify() {
        super.addNotify()
        refreshTimer.start()
    }

    override fun removeNotify() {
        refreshTimer.stop()
        super.removeNotify()
    }
}

private class ActivityTableModel : AbstractTableModel() {
    private var entries: List<Activity> = emptyList()

    fun replace(next: List<Activity>) {
        if (entries == next) return
        entries = next
        fireTableDataChanged()
    }

    override fun getRowCount() = entries.size
    override fun getColumnCount() = columns.size
    override fun getColumnName(column: Int) = columns[column]

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val entry = entries[rowIndex]
        return when (columnIndex) {
            0 -> timestamp.format(Instant.ofEpochMilli(entry.timestamp).atZone(ZoneId.systemDefault()))
            1 -> entry.protocol
            2 -> entry.host
            3 -> entry.outcome
            4 -> entry.detections
            5 -> entry.detail
            else -> ""
        }
    }

    private companion object {
        val columns = arrayOf("Time", "Protocol", "Host", "Outcome", "Detections", "Detail")
        val timestamp: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
    }
}
