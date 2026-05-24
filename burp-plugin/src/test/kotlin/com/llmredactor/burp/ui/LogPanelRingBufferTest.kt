package com.llmredactor.burp.ui

import com.llmredactor.burp.config.PluginConfig
import com.llmredactor.burp.transport.SessionStore
import com.llmredactor.burp.transport.Stats
import com.llmredactor.burp.transport.TestConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import javax.swing.SwingUtilities

class LogPanelRingBufferTest {

    @Test
    fun dropsOldestRowsWhenCapExceeded() {
        SwingUtilities.invokeAndWait {
            val config = PluginConfig(TestConfig.persistence()).apply {
                logRowCap = 50 // UI minimum; insertRow enforces the same floor
            }
            val panel = LogPanel(config, Stats(), SessionStore(config))
            repeat(53) { i ->
                panel.addActivityRowNow("host", "/path/$i", 0, "kind$i")
            }
            assertEquals(50, panel.activityRowCount())
            assertEquals("/path/52", panel.getPathAt(0))
            assertEquals("/path/3", panel.getPathAt(49))
        }
    }

    @Test
    fun refreshRetentionHintUsesSavedCap() {
        SwingUtilities.invokeAndWait {
            val config = PluginConfig(TestConfig.persistence()).apply {
                logRowCap = 1200
            }
            val panel = LogPanel(config, Stats(), SessionStore(config))
            config.logRowCap = 800
            panel.refreshRetentionHint()
            assertEquals("Newest first · keeps last 800 rows", panel.retentionHintText())
        }
    }
}
