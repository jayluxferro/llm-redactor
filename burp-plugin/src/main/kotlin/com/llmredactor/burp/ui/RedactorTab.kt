package com.llmredactor.burp.ui

import com.llmredactor.burp.config.PluginConfig
import com.llmredactor.burp.transport.SessionStore
import com.llmredactor.burp.transport.Stats
import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.BorderFactory
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.UIManager

/**
 * Root Burp Suite tab: header, enable pill, config + log.
 */
class RedactorTab(
    private val config: PluginConfig,
    store: SessionStore,
    stats: Stats,
) : JPanel(BorderLayout()) {

    val logPanel = LogPanel(config, stats, store)
    private val configPanel = ConfigPanel(config, store) { logPanel.refreshRetentionHint() }
    private val enablePill = EnablePill(config.enabled) { on ->
        config.enabled = on
    }

    init {
        UiTheme.styleRoot(this)

        val header = JPanel(BorderLayout()).apply {
            background = UiTheme.surface
            isOpaque = true
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, UiTheme.border),
                BorderFactory.createEmptyBorder(14, 20, 14, 20),
            )
        }

        val titleBlock = JPanel().apply {
            layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
            isOpaque = false
            add(JLabel("LLM Redactor").apply {
                font = UiTheme.fontTitle
                foreground = UiTheme.textColor
            })
            add(UiTheme.vGap(4))
            add(JLabel("Outbound redaction for LLM API traffic").apply {
                font = UiTheme.fontSmall
                foreground = UiTheme.textMuted
            })
        }

        val headerRight = JPanel(FlowLayout(FlowLayout.RIGHT, 0, 0)).apply {
            isOpaque = false
            add(enablePill)
        }

        header.add(titleBlock, BorderLayout.WEST)
        header.add(headerRight, BorderLayout.EAST)

        val tabs = JTabbedPane().apply {
            font = UiTheme.fontBody
            background = UiTheme.bg
            foreground = UiTheme.textColor
            border = BorderFactory.createEmptyBorder(8, 12, 12, 12)
        }
        tabs.addTab("  Settings  ", configPanel)
        tabs.addTab("  Activity  ", logPanel)

        UIManager.getDefaults()["TabbedPane.contentOpaque"] = true
        tabs.background = UiTheme.bg

        add(header, BorderLayout.NORTH)
        add(tabs, BorderLayout.CENTER)
    }

    fun syncEnableState() {
        enablePill.setOn(config.enabled)
    }
}
