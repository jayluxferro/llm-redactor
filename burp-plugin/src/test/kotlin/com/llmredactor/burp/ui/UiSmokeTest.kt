package com.llmredactor.burp.ui

import com.llmredactor.burp.transport.SessionStore
import com.llmredactor.burp.transport.Stats
import com.llmredactor.burp.transport.TestConfig
import org.junit.jupiter.api.Test
import javax.swing.SwingUtilities
import kotlin.test.assertNotNull

class UiSmokeTest {
    @Test
    fun constructsRedactorTabOnEdt() {
        SwingUtilities.invokeAndWait {
            val config = TestConfig.plugin()
            val store = SessionStore(config)
            val tab = RedactorTab(config, store, Stats())
            assertNotNull(tab.logPanel)
            assertNotNull(tab.logPanel)
        }
    }
}
