package org.llmredactor.burp

import java.util.ArrayDeque

/** Bounded metadata-only log. It deliberately never receives payload text. */
class ActivityLog(private val cap: Int = 500) {
    private val items = ArrayDeque<Activity>()

    @Synchronized fun add(activity: Activity) {
        while (items.size >= cap) items.removeFirst()
        items.addLast(activity)
    }

    @Synchronized fun snapshot(): List<Activity> = items.toList()

    @Synchronized fun clear() = items.clear()
}
