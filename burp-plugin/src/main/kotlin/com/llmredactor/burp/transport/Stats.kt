package com.llmredactor.burp.transport

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Shared atomic counters updated by request/response interceptors. */
class Stats {
    val requests      = AtomicInteger(0)
    val spansRedacted = AtomicLong(0)
    val restores      = AtomicInteger(0)
    val refusals      = AtomicInteger(0)

    fun reset() {
        requests.set(0)
        spansRedacted.set(0)
        restores.set(0)
        refusals.set(0)
    }
}
