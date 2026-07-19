package org.llmredactor.burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
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
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.Timer
import javax.swing.table.AbstractTableModel

class BurpLlmRedactor : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("LLM Redactor")
        val activity = ActivityLog()
        val redactor = TextRedactor()
        val transformer = BodyTransformer(redactor)
        api.http().registerHttpHandler(RequestRedactionHandler(transformer, activity))
        api.websockets().registerWebSocketCreatedHandler(WebSocketRedactionHandler(activity, redactor))
        api.userInterface().registerSuiteTab("LLM Redactor", ActivityPanel(activity))
        api.logging().logToOutput(
            "LLM Redactor loaded: all detector categories are enabled for HTTP requests; " +
                "WebSocket client-to-server text frames are redacted with regex fallback. " +
                "Responses and WebSocket binary frames are not modified.",
        )
    }
}

private class WebSocketRedactionHandler(
    private val activity: ActivityLog,
    private val redactor: TextRedactor,
) : WebSocketCreatedHandler {
    override fun handleWebSocketCreated(created: WebSocketCreated) {
        val host = created.upgradeRequest().httpService().host()
        created.webSocket().registerMessageHandler(object : MessageHandler {
            override fun handleTextMessage(message: TextMessage): TextMessageAction {
                if (message.direction() != Direction.CLIENT_TO_SERVER) return TextMessageAction.continueWith(message)
                return try {
                    // Use regex-only redaction for WebSocket frames: the local
                    // detector's HTTP round-trip can stall a streaming connection
                    // when the service is unavailable, causing clients such as
                    // Codex to close the stream.
                    val outcome = redactor.redactWithRegex(message.payload())
                    if (outcome.spans.isEmpty()) {
                        TextMessageAction.continueWith(message)
                    } else {
                        activity.add(Activity("WebSocket", host, "redacted", outcome.spans.size))
                        TextMessageAction.continueWith(outcome.text)
                    }
                } catch (_: Exception) {
                    activity.add(Activity("WebSocket", host, "passed-through", detail = "redaction-error"))
                    TextMessageAction.continueWith(message)
                }
            }

            override fun handleBinaryMessage(message: BinaryMessage): BinaryMessageAction {
                activity.add(Activity("WebSocket", host, "passed-through", detail = "binary-frame"))
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
        if (host == "127.0.0.1" || host == "localhost") return RequestToBeSentAction.continueWith(request)
        if (request.hasHeader("X-Amz-Content-Sha256") || request.path().contains("X-Amz-Signature=")) {
            activity.add(Activity("HTTP", host, "passed-through", detail = "signed-request"))
            return RequestToBeSentAction.continueWith(request)
        }
        if (transformer.isOpaqueProtocolPayload(request.body().getBytes())) {
            activity.add(Activity("HTTP", host, "passed-through", detail = "encrypted-protocol-payload"))
            return RequestToBeSentAction.continueWith(request)
        }
        return try {
            val (path, queryCount) = transformer.transformQuery(request.path())
            val result = if (isCodexResponsesRequest(request)) {
                transformer.transformCodexResponseRequest(
                    request.body().getBytes(),
                    request.headerValue("Content-Type"),
                    request.headerValue("Content-Encoding"),
                )
            } else {
                transformer.transform(
                    request.body().getBytes(),
                    request.headerValue("Content-Type"),
                    request.headerValue("Content-Encoding"),
                )
            }
            if (result.reason != null) {
                // Preserve query-parameter redactions even when the body cannot
                // be transformed (e.g. unsupported encoding).  Discarding the
                // modified path would leak PII that transformQuery already caught.
                val forwarded = if (queryCount > 0) request.withPath(path) else request
                activity.add(Activity("HTTP", host, "passed-through", detail = result.reason))
                RequestToBeSentAction.continueWith(forwarded)
            } else {
                val updated = request.withPath(path).withBody(ByteArray.byteArray(*result.body))
                val outcome = if (result.usedFallback) "redacted-regex-fallback" else "redacted-local-detector"
                activity.add(Activity("HTTP", host, outcome, result.detections + queryCount))
                RequestToBeSentAction.continueWith(updated)
            }
        } catch (_: Exception) {
            activity.add(Activity("HTTP", host, "passed-through", detail = "transform-error"))
            RequestToBeSentAction.continueWith(request)
        }
    }

    private fun isCodexResponsesRequest(request: HttpRequestToBeSent): Boolean =
        request.method().equals("POST", ignoreCase = true) &&
            (request.pathWithoutQuery() == CODEX_RESPONSES_PATH ||
                request.pathWithoutQuery().startsWith("$CODEX_RESPONSES_PATH/"))

    override fun handleHttpResponseReceived(response: HttpResponseReceived): ResponseReceivedAction {
        val request = response.initiatingRequest()
        if (
            BlockedRequestCompatibility.isCanonicalBurpBlock(
                response.statusCode(),
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
                response.withStatusCode(204).withReasonPhrase("No Content")
                    .withBody(ByteArray.byteArray(*kotlin.byteArrayOf())),
            )
        }

        // Store only routing metadata for failed responses. This makes an upstream
        // 4xx/5xx diagnosable without retaining prompts, headers, or response bodies.
        if (response.statusCode() >= 400) {
            activity.add(
                Activity(
                    "HTTP",
                    request.httpService().host(),
                    "response-${response.statusCode()}",
                    detail = "${request.method()} ${request.path()}",
                ),
            )
        }
        return ResponseReceivedAction.continueWith(response)
    }
}

private const val CODEX_RESPONSES_PATH = "/backend-api/codex/responses"

/** Acknowledge Burp's canonical local block response; it never permits egress.
 *  Different Burp extensions return different ``detail`` messages ("Bad Request",
 *  "Not Found", etc.).  Match any single-field ``{"detail":"..."}`` at 400/403 so
 *  the coding agent sees a clean 204 instead of a transport error. Stateful Codex
 *  response streams are excluded: they require the actual response event sequence. */
internal object BlockedRequestCompatibility {
    private val burpBlockPattern = Regex("""^\s*\{\s*"detail"\s*:\s*"[^"]*"\s*\}\s*$""")
    private const val codexResponsesPath = "/backend-api/codex/responses"

    fun isCanonicalBurpBlock(statusCode: Short, body: String, method: String, path: String): Boolean =
        !isCodexResponseStream(method, path) &&
            statusCode in setOf(400.toShort(), 403.toShort()) &&
            burpBlockPattern.matches(body)

    private fun isCodexResponseStream(method: String, path: String): Boolean =
        method.equals("POST", ignoreCase = true) &&
            (path == codexResponsesPath || path.startsWith("$codexResponsesPath/"))
}

private class ActivityPanel(private val activity: ActivityLog) : JPanel(BorderLayout()) {
    private val activityTableModel = ActivityTableModel()
    private val refreshTimer = Timer(500) { activityTableModel.replace(activity.snapshot()) }

    init {
        val header = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        header.add(JLabel("Live activity — payloads and detected values are never stored."))
        header.add(JButton("Clear").apply {
            addActionListener {
                activity.clear()
                activityTableModel.replace(emptyList<Activity>())
            }
        })
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
