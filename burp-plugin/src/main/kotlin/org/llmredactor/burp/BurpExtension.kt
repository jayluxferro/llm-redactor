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
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextArea

class BurpLlmRedactor : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("LLM Redactor")
        val activity = ActivityLog()
        val transformer = BodyTransformer(TextRedactor())
        api.http().registerHttpHandler(RequestRedactionHandler(transformer, activity))
        api.websockets().registerWebSocketCreatedHandler(WebSocketRedactionHandler(TextRedactor(), activity))
        api.userInterface().registerSuiteTab("LLM Redactor", ActivityPanel(activity))
        api.logging().logToOutput("LLM Redactor loaded: all detector categories are enabled; responses are not modified.")
    }
}

private class WebSocketRedactionHandler(
    private val redactor: TextRedactor,
    private val activity: ActivityLog,
) : WebSocketCreatedHandler {
    override fun handleWebSocketCreated(created: WebSocketCreated) {
        val host = created.upgradeRequest().httpService().host()
        created.webSocket().registerMessageHandler(object : MessageHandler {
            override fun handleTextMessage(message: TextMessage): TextMessageAction {
                if (message.direction() != Direction.CLIENT_TO_SERVER) return TextMessageAction.continueWith(message)
                val outcome = redactor.redact(message.payload())
                val status = if (outcome.usedFallback) "redacted-regex-fallback" else "redacted-local-detector"
                activity.add(Activity("WebSocket", host, status, outcome.spans.size))
                return TextMessageAction.continueWith(outcome.text)
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
        return try {
            val (path, queryCount) = transformer.transformQuery(request.path())
            val result = transformer.transform(
                request.body().getBytes(), request.headerValue("Content-Type"), request.headerValue("Content-Encoding"),
            )
            if (result.reason != null) {
                activity.add(Activity("HTTP", host, "passed-through", detail = result.reason))
                RequestToBeSentAction.continueWith(request)
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

    override fun handleHttpResponseReceived(response: HttpResponseReceived): ResponseReceivedAction =
        ResponseReceivedAction.continueWith(response)
}

private class ActivityPanel(private val activity: ActivityLog) : JPanel(BorderLayout()) {
    init {
        add(JLabel("Live — all categories; outbound HTTP only. Payloads are never stored."), BorderLayout.NORTH)
        val view = JTextArea("Activity is metadata-only.\n")
        view.isEditable = false
        add(view, BorderLayout.CENTER)
    }
}
