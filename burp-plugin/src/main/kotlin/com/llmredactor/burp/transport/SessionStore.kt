package com.llmredactor.burp.transport

import com.llmredactor.burp.config.PluginConfig
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe LRU store for per-request reverse maps.
 *
 * Sessions are stored by sessionId (UUID) and indexed by SHA-256 fingerprints
 * of both the original and redacted request bodies. Burp versions disagree on
 * whether [initiatingRequest] on the response path returns the client body or
 * the modified upstream body — dual indexing makes restore reliable either way.
 */
class SessionStore(config: PluginConfig) {

    @Volatile private var cap: Int = config.sessionCap

    private val store: MutableMap<String, Map<String, String>> =
        Collections.synchronizedMap(
            object : LinkedHashMap<String, Map<String, String>>(16, 0.75f, true) {
                override fun removeEldestEntry(
                    eldest: MutableMap.MutableEntry<String, Map<String, String>>
                ): Boolean = size > cap
            }
        )

    /** fingerprint → sessionId.  Fingerprint = SHA-256 of (host + path + body bytes). */
    private val fingerprints: MutableMap<String, String> = ConcurrentHashMap()

    @Volatile var evictions: Int = 0
        private set

    fun put(sessionId: String, reverseMap: Map<String, String>) {
        val prevSize = store.size
        store[sessionId] = reverseMap
        if (store.size <= prevSize && prevSize >= cap) evictions++
    }

    /** Like put(), but also indexes the session by a request fingerprint. */
    fun putWithFingerprint(sessionId: String, fingerprint: String, reverseMap: Map<String, String>) {
        put(sessionId, reverseMap)
        fingerprints[fingerprint] = sessionId
    }

    /**
     * Index the same session under multiple body fingerprints.
     *
     * Burp versions differ on whether [initiatingRequest] on the response path
     * returns the client-original body or the plugin-modified body sent upstream.
     * Indexing both avoids restore misses and corrupted Content-Length on retry.
     */
    fun putWithFingerprints(
        sessionId: String,
        reverseMap: Map<String, String>,
        vararg fingerprintKeys: String,
    ) {
        put(sessionId, reverseMap)
        for (fp in fingerprintKeys) {
            if (fp.isNotEmpty()) fingerprints[fp] = sessionId
        }
    }

    /** One-shot consume by sessionId. */
    fun remove(sessionId: String): Map<String, String>? = store.remove(sessionId)

    /** One-shot consume by fingerprint — used by the response handler. */
    fun removeByFingerprint(fingerprint: String): Map<String, String>? {
        val sessionId = fingerprints.remove(fingerprint) ?: return null
        return store.remove(sessionId)
    }

    fun size(): Int = store.size

    fun clear() {
        store.clear()
        fingerprints.clear()
        evictions = 0
    }

    fun resetEvictionCounter() {
        evictions = 0
    }

    fun updateCap(newCap: Int) { cap = newCap }

    companion object {
        /** Stable identifier for a request: SHA-256 of host + path + body bytes. */
        fun fingerprint(host: String, path: String, body: ByteArray): String {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(host.toByteArray(Charsets.UTF_8))
            md.update(0)
            md.update(path.toByteArray(Charsets.UTF_8))
            md.update(0)
            md.update(body)
            return md.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
