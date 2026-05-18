package com.llmredactor.burp.transport

import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import com.llmredactor.burp.config.PluginConfig
import com.llmredactor.burp.pipeline.RedactionPipeline
import com.llmredactor.burp.ui.LogPanel
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

class RequestInterceptor(
    private val config: PluginConfig,
    private val store: SessionStore,
    private val pipeline: RedactionPipeline,
    private val logPanel: LogPanel,
    private val stats: Stats,
) : ProxyRequestHandler {

    override fun handleRequestReceived(
        interceptedRequest: InterceptedRequest
    ): ProxyRequestReceivedAction {
        if (!config.enabled) return ProxyRequestReceivedAction.continueWith(interceptedRequest)

        val host = interceptedRequest.httpService().host()
        if (!TargetMatcher.isTargetHost(host, config.targetHosts))
            return ProxyRequestReceivedAction.continueWith(interceptedRequest)

        val path = interceptedRequest.path()
        if (!TargetMatcher.isTargetPath(path, config.targetPaths))
            return ProxyRequestReceivedAction.continueWith(interceptedRequest)

        val ct = interceptedRequest.headerValue("Content-Type") ?: ""
        val format = BodyFormatDetector.detect(ct)
        if (format == BodyFormat.UNSUPPORTED)
            return ProxyRequestReceivedAction.continueWith(interceptedRequest)

        val ce = interceptedRequest.headerValue("Content-Encoding") ?: ""
        if (TransportLogic.isUnsupportedRequestContentEncoding(ce)) {
            debugLog("skip: Content-Encoding=$ce on $host$path")
            return ProxyRequestReceivedAction.continueWith(interceptedRequest)
        }

        val rawBytes = interceptedRequest.body().getBytes()
        if (rawBytes.isEmpty()) return ProxyRequestReceivedAction.continueWith(interceptedRequest)

        if (format == BodyFormat.JSON) {
            val decoded = ConnectProtoCodec.decodeHttpBody(rawBytes, ce)
            val json = JsonBodyInspector.parseObject(decoded.bytes)
            if (json != null && JsonBodyInspector.hasToolsOrFunctions(json)) {
                when (config.toolsPolicy.lowercase()) {
                    "refuse" -> {
                        stats.refusals.incrementAndGet()
                        logPanel.addRefusedReason(host, path, "tools_or_functions")
                        debugLog("tools refuse: $host$path")
                        return ProxyRequestReceivedAction.drop()
                    }
                    else -> {
                        if (config.logMatchedRequests) {
                            logPanel.addActivityRow(host, path, 0, "tools_bypass")
                        }
                        return ProxyRequestReceivedAction.continueWith(interceptedRequest)
                    }
                }
            }
        }

        if (config.strict) {
            val detected = BodyProcessor.collectSpans(rawBytes, format, ce, pipeline)
            val refused = pipeline.strictRefusalSpans(detected)
            if (refused.isNotEmpty()) {
                stats.refusals.incrementAndGet()
                logPanel.addRefusedEntry(host, path, refused)
                if (config.debugDump) {
                    debugLog(
                        "strict refuse: $host$path low_confidence=${refused.size} " +
                            refused.joinToString { "${it.kind}@${it.confidence}" },
                    )
                }
                return ProxyRequestReceivedAction.drop()
            }
        }

        return try {
            val tag = pipeline.newSessionTag()
            val outcome = BodyProcessor.redactRequest(rawBytes, format, ce, pipeline, tag)
            if (outcome == null) {
                if (config.logMatchedRequests) {
                    logPanel.addActivityRow(host, path, 0, "no_spans")
                }
                return ProxyRequestReceivedAction.continueWith(interceptedRequest)
            }

            val sessionId = UUID.randomUUID().toString()
            stats.requests.incrementAndGet()
            stats.spansRedacted.addAndGet(outcome.summary.totalSpans.toLong())

            val redactedBytes = outcome.bytes
            val cesuAt = TransportLogic.scanForCesu8(redactedBytes)
            if (cesuAt >= 0) {
                debugLog("ABORT: CESU-8 at $cesuAt on $host$path")
                return ProxyRequestReceivedAction.continueWith(interceptedRequest)
            }

            val fpOriginal = SessionStore.fingerprint(host, path, rawBytes)
            val fpRedacted = SessionStore.fingerprint(host, path, redactedBytes)
            store.putWithFingerprints(sessionId, outcome.reverseMap, fpOriginal, fpRedacted)

            if (config.debugDump) {
                val n = debugCounter.incrementAndGet()
                dumpBytes("req-$n-in", rawBytes)
                dumpBytes("req-$n-out", redactedBytes)
                debugLog("req-$n $host$path fmt=$format in=${rawBytes.size}B out=${redactedBytes.size}B " +
                    "spans=${outcome.summary.totalSpans} httpCe=${outcome.httpCompression}")
            }

            var modified = interceptedRequest
                .withBody(MontoyaByteArray.byteArray(*redactedBytes))
                .withRemovedHeader("Accept-Encoding")
                .withUpdatedHeader("Content-Length", redactedBytes.size.toString())
                .withRemovedHeader("Transfer-Encoding")

            when (outcome.httpCompression) {
                ConnectProtoCodec.HttpCompression.GZIP ->
                    modified = modified.withUpdatedHeader("Content-Encoding", "gzip")
                ConnectProtoCodec.HttpCompression.DEFLATE ->
                    modified = modified.withUpdatedHeader("Content-Encoding", "deflate")
                ConnectProtoCodec.HttpCompression.BROTLI ->
                    modified = modified.withUpdatedHeader("Content-Encoding", "br")
                ConnectProtoCodec.HttpCompression.ZSTD ->
                    modified = modified.withUpdatedHeader("Content-Encoding", "zstd")
                ConnectProtoCodec.HttpCompression.COMPRESS ->
                    modified = modified.withUpdatedHeader("Content-Encoding", "compress")
                ConnectProtoCodec.HttpCompression.IDENTITY ->
                    modified = modified.withRemovedHeader("Content-Encoding")
            }

            logPanel.addEntry(host, path, outcome.summary.totalSpans, outcome.summary.kindCounts)
            ProxyRequestReceivedAction.continueWith(modified)
        } catch (e: Exception) {
            debugLog("exception on $host$path: ${e.javaClass.simpleName}: ${e.message}")
            ProxyRequestReceivedAction.continueWith(interceptedRequest)
        }
    }

    private val debugCounter = AtomicLong(0)
    private val debugDir = Paths.get(System.getProperty("java.io.tmpdir"), "burp-redactor-debug")

    private fun ensureDebugDir() {
        try { Files.createDirectories(debugDir) } catch (_: Exception) {}
    }

    private fun dumpBytes(label: String, data: ByteArray) {
        if (!config.debugDump) return
        ensureDebugDir()
        try { Files.write(debugDir.resolve("$label.bin"), data) } catch (_: Exception) {}
    }

    private fun debugLog(msg: String) {
        if (!config.debugDump) return
        ensureDebugDir()
        try {
            val line = "[${java.time.Instant.now()}] $msg\n"
            Files.write(debugDir.resolve("trace.log"), line.toByteArray(Charsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND)
        } catch (_: Exception) {}
    }

    override fun handleRequestToBeSent(
        interceptedRequest: InterceptedRequest
    ): ProxyRequestToBeSentAction = ProxyRequestToBeSentAction.continueWith(interceptedRequest)
}
