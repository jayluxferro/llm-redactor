package com.llmredactor.burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.llmredactor.burp.config.PluginConfig
import com.llmredactor.burp.pipeline.RedactionPipeline
import com.llmredactor.burp.transport.RequestInterceptor
import com.llmredactor.burp.transport.ResponseInterceptor
import com.llmredactor.burp.transport.SessionStore
import com.llmredactor.burp.transport.Stats
import com.llmredactor.burp.ui.RedactorTab

/**
 * Burp Suite extension entry point (Montoya API).
 *
 * Load via Burp → Extensions → Add → Java → burp-llm-redactor.jar
 */
class BurpExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("LLM Redactor")
        try {
            val config = PluginConfig(api.persistence().extensionData())
            val stats = Stats()
            val store = SessionStore(config)
            val pipeline = RedactionPipeline(config)

            val tab = RedactorTab(config, store, stats)
            api.userInterface().registerSuiteTab("LLM Redactor", tab)

            api.proxy().registerRequestHandler(
                RequestInterceptor(config, store, pipeline, tab.logPanel, stats),
            )
            api.proxy().registerResponseHandler(
                ResponseInterceptor(config, store, stats, tab.logPanel),
            )

            api.logging().logToOutput(
                "LLM Redactor loaded — hosts: ${config.targetHosts.joinToString()} " +
                    "(JSON + Cursor Connect/protobuf)",
            )
        } catch (e: Exception) {
            api.logging().logToError("LLM Redactor failed to load: ${e.message}")
            api.logging().logToError(e.stackTraceToString())
            throw e
        }
    }
}
