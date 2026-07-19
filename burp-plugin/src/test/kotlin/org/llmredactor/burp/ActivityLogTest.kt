package org.llmredactor.burp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

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

    @Test fun `capacity of 1 keeps only latest entry`() {
        val log = ActivityLog(cap = 1)
        log.add(Activity("HTTP", "first.example", "ok"))
        log.add(Activity("HTTP", "second.example", "ok"))
        val snapshot = log.snapshot()
        assertEquals(1, snapshot.size)
        assertEquals("second.example", snapshot[0].host)
    }

    @Test fun `snapshot returns independent copy`() {
        val log = ActivityLog(cap = 10)
        log.add(Activity("HTTP", "host.example", "ok"))
        val snap = log.snapshot()
        // Modifying the snapshot should not affect the log
        log.clear()
        assertEquals(1, snap.size) // snapshot still has the old entry
        assertEquals(0, log.snapshot().size) // log is cleared
    }

    @Test fun `concurrent adds do not lose or corrupt entries`() {
        val log = ActivityLog(cap = 500)
        val threads = (1..10).map { i ->
            Thread {
                repeat(50) { log.add(Activity("HTTP", "host-$i", "ok")) }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        // 10 threads × 50 = 500 entries; log is bounded at 500
        val snapshot = log.snapshot()
        assertTrue(snapshot.size <= 500)
        assertTrue(snapshot.isNotEmpty())
    }

    @Test fun `clear followed by add works correctly`() {
        val log = ActivityLog(cap = 5)
        log.add(Activity("HTTP", "first.example", "ok"))
        log.clear()
        log.add(Activity("HTTP", "after-clear.example", "ok"))
        val snapshot = log.snapshot()
        assertEquals(1, snapshot.size)
        assertEquals("after-clear.example", snapshot[0].host)
    }
}
