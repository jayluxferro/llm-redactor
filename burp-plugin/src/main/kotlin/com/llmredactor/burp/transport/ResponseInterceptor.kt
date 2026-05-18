package com.llmredactor.burp.transport

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import com.llmredactor.burp.config.PluginConfig
import com.llmredactor.burp.ui.LogPanel
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.concurrent.atomic.AtomicLong

class ResponseInterceptor(
    private val config: PluginConfig,
    private val store: SessionStore,
    private val stats: Stats,
    private val logPanel: LogPanel,
) : ProxyResponseHandler {

    override fun handleResponseReceived(
        interceptedResponse: InterceptedResponse
    ): ProxyResponseReceivedAction {
        val initiating = interceptedResponse.initiatingRequest()
        val host = try { initiating.httpService().host() } catch (_: Exception) { "" }
        val path = try { initiating.path() } catch (_: Exception) { "" }
        val reqBody = try { initiating.body().getBytes() } catch (_: Exception) { ByteArray(0) }

        val fingerprint = SessionStore.fingerprint(host, path, reqBody)
        val reverseMap = store.removeByFingerprint(fingerprint)

        if (config.debugDump && reverseMap == null) {
            try {
                if (TargetMatcher.isTargetHost(host, config.targetHosts)) {
                    debugLog("unmatched-resp status=${interceptedResponse.statusCode()} host=$host " +
                        "bodyLen=${interceptedResponse.body().length()} reqBodyLen=${reqBody.size} " +
                        "fp=${fingerprint.take(12)}")
                }
            } catch (_: Exception) {}
        }

        if (reverseMap == null) return ProxyResponseReceivedAction.continueWith(interceptedResponse)
        if (reverseMap.isEmpty()) return strip(interceptedResponse)

        // Outbound-only policy: agent/tool responses (file writes, patches, RPC payloads)
        // must reach the client verbatim. Drop the session map but do not rewrite the body.
        if (!config.restoreResponses) return strip(interceptedResponse)

        return try {
            val ct = interceptedResponse.headerValue("Content-Type") ?: ""
            val ceHeader = interceptedResponse.headerValue("Content-Encoding") ?: ""
            val format = BodyFormatDetector.detect(ct)
            val rawBytes = interceptedResponse.body().getBytes()

            if (rawBytes.isEmpty()) return strip(interceptedResponse)

            val restoredBytes = when {
                ct.contains("text/event-stream", ignoreCase = true) -> {
                    val decoded = TransportLogic.decodeResponseBody(rawBytes, ceHeader)
                    val text = TransportLogic.restoreSseBody(decoded.text, reverseMap)
                    TransportLogic.encodeResponseBody(text, decoded, ceHeader).bytes
                }
                format == BodyFormat.JSON -> {
                    val decoded = TransportLogic.decodeResponseBody(rawBytes, ceHeader)
                    val text = TransportLogic.restoreJsonBody(decoded.text, reverseMap)
                    TransportLogic.encodeResponseBody(text, decoded, ceHeader).bytes
                }
                format == BodyFormat.CONNECT_PROTO ->
                    BodyProcessor.restoreResponse(rawBytes, format, ceHeader, reverseMap)
                else -> {
                    debugLog("skip restore: format=$format ct='$ct'")
                    return strip(interceptedResponse)
                }
            }

            if (restoredBytes == null) return strip(interceptedResponse)

            stats.restores.incrementAndGet()
            logPanel.refreshStats()

            if (config.debugDump) {
                val n = debugCounter.incrementAndGet()
                dumpBytes("resp-$n-raw", rawBytes)
                dumpBytes("resp-$n-restored", restoredBytes)
                debugLog("resp-$n status=${interceptedResponse.statusCode()} fmt=$format " +
                    "raw=${rawBytes.size} out=${restoredBytes.size} spans=${reverseMap.size}")
            }

            var response = interceptedResponse
                .withBody(MontoyaByteArray.byteArray(*restoredBytes))
                .withRemovedHeader("X-Redactor-Session")
                .withRemovedHeader("Transfer-Encoding")
                .withUpdatedHeader("Content-Length", restoredBytes.size.toString())

            val stripCe = ceHeader.isNotEmpty() && ceHeader != "identity" &&
                !rawBytes.contentEquals(restoredBytes) &&
                restoredBytes.size >= 2 &&
                (restoredBytes[0].toInt() and 0xFF) != 0x1F

            if (stripCe) response = response.withRemovedHeader("Content-Encoding")

            ProxyResponseReceivedAction.continueWith(response)
        } catch (e: Exception) {
            debugLog("response exception: ${e.javaClass.simpleName}: ${e.message}")
            strip(interceptedResponse)
        }
    }

    private val debugCounter = AtomicLong(0)
    private val debugDir = Paths.get(System.getProperty("java.io.tmpdir"), "burp-redactor-debug")

    private fun dumpBytes(label: String, data: ByteArray) {
        if (!config.debugDump) return
        try { Files.write(debugDir.resolve("$label.bin"), data) } catch (_: Exception) {}
    }

    private fun debugLog(msg: String) {
        if (!config.debugDump) return
        try {
            val line = "[${java.time.Instant.now()}] $msg\n"
            Files.write(debugDir.resolve("trace.log"), line.toByteArray(Charsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND)
        } catch (_: Exception) {}
    }

    override fun handleResponseToBeSent(
        interceptedResponse: InterceptedResponse
    ): ProxyResponseToBeSentAction = ProxyResponseToBeSentAction.continueWith(interceptedResponse)

    private fun strip(response: InterceptedResponse): ProxyResponseReceivedAction =
        ProxyResponseReceivedAction.continueWith(
            response.withRemovedHeader("X-Redactor-Session")
        )
}
