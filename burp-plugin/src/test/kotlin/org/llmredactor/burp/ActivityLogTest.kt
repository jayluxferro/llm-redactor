package org.llmredactor.burp

import kotlin.test.Test
import kotlin.test.assertEquals

class ActivityLogTest {
    @Test fun `activity log is bounded and clearable`() {
        val log = ActivityLog(cap = 2)
        log.add(Activity("HTTP", "first.example", "redacted-local-detector"))
        log.add(Activity("HTTP", "second.example", "redacted-local-detector"))
        log.add(Activity("WebSocket", "third.example", "passed-through"))

        assertEquals(listOf("second.example", "third.example"), log.snapshot().map { it.host })
        log.clear()
        assertEquals(emptyList(), log.snapshot())
    }
}
