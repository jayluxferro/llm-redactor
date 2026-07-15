package org.llmredactor.burp

/** Redacts local image bytes or throws when the optional image service is unavailable. */
fun interface ImageRedactor {
    fun redact(body: ByteArray, mediaType: String): RedactedImage
}

class LocalImageRedactor(private val detector: DetectorClient = DetectorClient()) : ImageRedactor {
    override fun redact(body: ByteArray, mediaType: String): RedactedImage = detector.redactImage(body, mediaType)
}
