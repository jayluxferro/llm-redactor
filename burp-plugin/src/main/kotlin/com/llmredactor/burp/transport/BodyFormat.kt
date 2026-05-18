package com.llmredactor.burp.transport

/** Wire body format for redaction / restore. */
enum class BodyFormat {
    JSON,
    CONNECT_PROTO,
    /** Reserved for explicit pass-through (none configured by default). */
    SKIP,
    UNSUPPORTED,
}

object BodyFormatDetector {

    fun detect(contentType: String, path: String): BodyFormat {
        val ct = contentType.lowercase()
        return when {
            ct.contains("application/json") && !ct.contains("connect") -> BodyFormat.JSON
            ct.contains("application/proto") ||
                ct.contains("connect+proto") ||
                ct.contains("application/connect+proto") ||
                ct.contains("application/x-protobuf") ||
                ct.contains("application/protobuf") -> BodyFormat.CONNECT_PROTO
            ct.contains("application/grpc") -> BodyFormat.CONNECT_PROTO
            else -> BodyFormat.UNSUPPORTED
        }
    }
}

object TargetMatcher {

    fun isTargetHost(host: String, hosts: Set<String>): Boolean =
        hosts.any { host == it || host.endsWith(".$it") }

    fun isTargetPath(path: String, paths: Set<String>): Boolean {
        val p = path.substringBefore("?")
        if (p.startsWith("/aiserver.v1.")) return true
        return paths.any { p == it || p.startsWith("$it/") }
    }
}
