package org.llmredactor.burp

import com.fasterxml.jackson.core.StreamReadFeature
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.cfg.JsonNodeFeature
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.node.TextNode
import com.github.luben.zstd.ZstdInputStream
import com.github.luben.zstd.ZstdOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.zip.DeflaterOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.InflaterInputStream

/** [detections] > 0 with no [reason] means [body] is a rewritten body; otherwise it is the original. */
data class BodyTransform(val body: ByteArray, val detections: Int, val usedFallback: Boolean, val reason: String? = null)

data class QueryTransform(val path: String, val detections: Int, val usedFallback: Boolean)

data class TextTransform(val text: String, val detections: Int, val usedFallback: Boolean)

/**
 * Rewrites only bodies whose encoding can be safely decoded and re-encoded,
 * and only when something was detected (an untouched body is forwarded byte
 * for byte, compression included).
 *
 * Structured formats are redacted structurally: JSON string values one by one
 * (numbers, keys and layout of untouched documents are never altered), form
 * and query values after percent-decoding, multipart parts individually, and
 * protobuf/gRPC length-delimited strings with every enclosing length
 * recomputed. Scanning the serialized text instead, as this class once did,
 * turned a timestamp into `"created": ⟨PHONE_1⟩` (invalid JSON), split JSON
 * escapes (`\⟨EMAIL_1⟩`) and corrupted nested protobuf lengths.
 */
class BodyTransformer(
    private val redactor: TextRedactor,
    private val imageRedactor: ImageRedactor = LocalImageRedactor(),
) {
    fun transform(
        body: ByteArray,
        contentType: String?,
        contentEncoding: String?,
        naming: PlaceholderNaming = PlaceholderNaming(),
    ): BodyTransform {
        val encoding = normalizeEncoding(contentEncoding)
        val decoded = decode(body, encoding) ?: return BodyTransform(body, 0, false, "unsupported-encoding:$encoding")
        val media = mediaType(contentType)
        val result = when {
            media in IMAGE_TYPES -> redactImageBody(decoded, media)
            media.startsWith("application/grpc-web-text") -> BodyTransform(decoded, 0, false, "grpc-web-text")
            media in ENVELOPED_PROTOBUF -> redactEnveloped(decoded, json = false, naming)
            media in ENVELOPED_JSON -> redactEnveloped(decoded, json = true, naming)
            media.contains("protobuf") || media == "application/proto" -> redactProtobufBody(decoded, naming)
            media.startsWith("multipart/") -> redactMultipart(decoded, contentType.orEmpty(), naming)
            media == "application/x-www-form-urlencoded" -> redactFormBody(decoded, naming)
            else -> redactTextBody(decoded, media, naming)
        }
        if (result.reason != null || result.detections == 0) return result.copy(body = body)
        val encoded = encode(result.body, encoding)
            ?: return BodyTransform(body, 0, false, "unsupported-encoding:$encoding")
        return result.copy(body = encoded)
    }

    /**
     * OpenAI Responses API requests (`/v1/responses`, Codex's
     * `/backend-api/codex/responses`): protocol JSON in which only user-text
     * fields are redacted. IDs, metadata and encrypted reasoning items are
     * never touched, which is why this path also serves requests that carry
     * `encrypted_content`.
     */
    fun transformResponsesRequest(
        body: ByteArray,
        contentType: String?,
        contentEncoding: String?,
        naming: PlaceholderNaming = PlaceholderNaming(),
    ): BodyTransform {
        val encoding = normalizeEncoding(contentEncoding)
        val decoded = decode(body, encoding) ?: return BodyTransform(body, 0, false, "unsupported-encoding:$encoding")
        if (!mediaType(contentType).contains("json")) return BodyTransform(body, 0, false, "responses-protocol-non-json")
        val text = strictUtf8(decoded) ?: return BodyTransform(body, 0, false, "responses-protocol-invalid-json")
        // Protocol JSON that cannot be parsed is left untouched, never text-scanned.
        val result = transformResponsesText(text, naming)
            ?: return BodyTransform(body, 0, false, "responses-protocol-invalid-json")
        if (result.detections == 0) return BodyTransform(body, 0, result.usedFallback)
        val encoded = encode(result.text.toByteArray(StandardCharsets.UTF_8), encoding)
            ?: return BodyTransform(body, 0, false, "unsupported-encoding:$encoding")
        return BodyTransform(encoded, result.detections, result.usedFallback)
    }

    /** The Responses API rules for one JSON text (an HTTP body or a WebSocket frame); null if not JSON. */
    fun transformResponsesText(
        text: String,
        naming: PlaceholderNaming = PlaceholderNaming(),
        regexOnly: Boolean = false,
    ): TextTransform? {
        val root = parseJson(text) ?: return null
        val result = redactJsonRoots(listOf(root), JsonScope.RESPONSES_USER_TEXT, naming, regexOnly)
        return TextTransform(result.texts.single() ?: text, result.detections, result.usedFallback)
    }

    /** Text-level entry point shared by HTTP bodies and WebSocket frames. */
    fun transformText(
        text: String,
        mediaType: String? = null,
        naming: PlaceholderNaming = PlaceholderNaming(),
        regexOnly: Boolean = false,
    ): TextTransform {
        if (text.isEmpty()) return TextTransform(text, 0, false)
        val media = mediaType(mediaType)
        val opener = text.firstOrNull { !it.isWhitespace() }
        if (media.contains("json") || (opener != null && opener in JSON_OPENERS)) {
            parseJson(text)?.let { root ->
                val result = redactJsonRoots(listOf(root), JsonScope.ALL, naming, regexOnly)
                return TextTransform(result.texts.single() ?: text, result.detections, result.usedFallback)
            }
            redactJsonLines(text, naming, regexOnly)?.let { return it }
        }
        return redactPlainText(text, naming, regexOnly)
    }

    fun transformQuery(path: String, naming: PlaceholderNaming = PlaceholderNaming()): QueryTransform {
        val marker = path.indexOf('?')
        if (marker < 0) return QueryTransform(path, 0, false)
        val result = redactFormEncoded(path.substring(marker + 1), naming)
        return QueryTransform(path.substring(0, marker + 1) + result.text, result.detections, result.usedFallback)
    }

    /** Checked on the decoded body: a gzip-compressed envelope used to slip past this check. */
    fun isOpaqueProtocolPayload(body: ByteArray, contentEncoding: String? = null): Boolean {
        val decoded = decode(body, normalizeEncoding(contentEncoding)) ?: return false
        val text = strictUtf8(decoded) ?: return false
        return TextRedactor.isOpaqueProtocolPayload(text)
    }

    // ── text and JSON ─────────────────────────────────────────────────────

    private fun redactTextBody(bytes: ByteArray, media: String, naming: PlaceholderNaming): BodyTransform {
        val text = strictUtf8(bytes) ?: return BodyTransform(bytes, 0, false, "non-utf8-body")
        // Valid UTF-8 with NUL bytes is a binary format that happens to decode.
        if ('\u0000' in text && !isTextual(media)) return BodyTransform(bytes, 0, false, "binary-body")
        val result = transformText(text, media, naming)
        return BodyTransform(result.text.toByteArray(StandardCharsets.UTF_8), result.detections, result.usedFallback)
    }

    private fun redactPlainText(text: String, naming: PlaceholderNaming, regexOnly: Boolean): TextTransform {
        val images = redactEmbeddedImages(text)
        val outcome = redactor.redactFields(listOf(TextRedactor.Field(images.text)), naming, regexOnly).single()
        val detections = outcome.spans.size + images.detections
        return if (detections == 0) TextTransform(text, 0, outcome.usedFallback)
        else TextTransform(outcome.text, detections, outcome.usedFallback)
    }

    /** NDJSON / JSON Lines: every non-blank line one JSON document; null if that is not the case. */
    private fun redactJsonLines(text: String, naming: PlaceholderNaming, regexOnly: Boolean): TextTransform? {
        val lines = text.split('\n')
        val roots = ArrayList<JsonNode>()
        val lineOfRoot = ArrayList<Int>()
        lines.forEachIndexed { i, line ->
            if (line.isBlank()) return@forEachIndexed
            roots.add(parseJson(line) ?: return null) // JsonNode is Iterable: += would add its children
            lineOfRoot += i
        }
        if (roots.size < 2) return null
        val result = redactJsonRoots(roots, JsonScope.ALL, naming, regexOnly)
        if (result.detections == 0) return TextTransform(text, 0, result.usedFallback)
        val rebuilt = lines.toMutableList()
        result.texts.forEachIndexed { r, replacement ->
            if (replacement == null) return@forEachIndexed
            val i = lineOfRoot[r]
            rebuilt[i] = replacement + if (lines[i].endsWith('\r')) "\r" else ""
        }
        return TextTransform(rebuilt.joinToString("\n"), result.detections, result.usedFallback)
    }

    private enum class JsonScope { ALL, RESPONSES_USER_TEXT }

    /** A JSON document whose serialization changes when any string inside it does. */
    private class Document(val holder: JsonNode, val slot: Slot?) {
        var changed = false
    }

    /** Where a string lives: an object member or an array element. */
    private class Slot(val container: JsonNode, val key: String?, val index: Int, val owner: Document) {
        fun set(value: String) {
            if (key != null) (container as ObjectNode).put(key, value) else (container as ArrayNode).set(index, TextNode.valueOf(value))
            owner.changed = true
        }
    }

    private class Target(val slot: Slot, val value: String, val key: String?)

    private class Collected {
        val targets = ArrayList<Target>()
        val nested = ArrayList<Document>()
    }

    private class JsonResult(val texts: List<String?>, val detections: Int, val usedFallback: Boolean)

    /**
     * Redacts the string values of several JSON documents in one detector
     * batch. Each value is detected with its member name as context. A string
     * that itself holds a JSON object or array (tool-call `arguments`, Codex
     * tool `output`) is redacted structurally and re-serialized, so a
     * detection cannot break its escaping. Returns, per document, the new
     * text or null when it is unchanged.
     */
    private fun redactJsonRoots(
        roots: List<JsonNode>,
        scope: JsonScope,
        naming: PlaceholderNaming,
        regexOnly: Boolean,
    ): JsonResult {
        val collected = Collected()
        val documents = roots.map { root ->
            // A holder array gives even a bare top-level string a slot.
            val holder = mapper.createArrayNode().add(root)
            Document(holder, null).also { collect(holder, null, scope, it, collected) }
        }
        if (collected.targets.isEmpty()) return JsonResult(roots.map { null }, 0, false)

        var detections = 0
        val values = collected.targets.map { target ->
            val images = redactEmbeddedImages(target.value)
            detections += images.detections
            images.text
        }
        val fields = collected.targets.mapIndexed { i, target ->
            if (target.key == null) TextRedactor.Field(values[i])
            else TextRedactor.Field(values[i], prefix = "\"${target.key}\": \"", suffix = "\"")
        }
        val outcomes = redactor.redactFields(fields, naming, regexOnly)
        val usedFallback = outcomes.any { it.usedFallback }
        outcomes.forEachIndexed { i, outcome ->
            detections += outcome.spans.size
            if (outcome.text != collected.targets[i].value) collected.targets[i].slot.set(outcome.text)
        }
        if (detections == 0) return JsonResult(roots.map { null }, 0, usedFallback)
        // Innermost first: re-serializing a nested document marks its parent changed.
        for (document in collected.nested.asReversed()) {
            if (document.changed) document.slot!!.set(mapper.writeValueAsString(document.holder))
        }
        val texts = documents.map { if (it.changed) mapper.writeValueAsString(it.holder.get(0)) else null }
        return JsonResult(texts, detections, usedFallback)
    }

    private fun collect(node: JsonNode, contextKey: String?, scope: JsonScope, owner: Document, out: Collected) {
        if (node is ObjectNode) {
            for ((name, child) in node.properties()) {
                // Ciphertext members, whatever their shape, are never inspected.
                if (TextRedactor.OPAQUE_NAME.matches(name)) continue
                visit(child, Slot(node, name, -1, owner), name, scope, owner, out)
            }
        } else if (node is ArrayNode) {
            for (i in 0 until node.size()) visit(node.get(i), Slot(node, null, i, owner), contextKey, scope, owner, out)
        }
    }

    private fun visit(child: JsonNode, slot: Slot, key: String?, scope: JsonScope, owner: Document, out: Collected) {
        if (!child.isTextual) {
            collect(child, key, scope, owner, out)
            return
        }
        if (scope == JsonScope.RESPONSES_USER_TEXT && key?.lowercase() !in RESPONSES_USER_TEXT_KEYS) return
        val value = child.textValue()
        if (value.isEmpty()) return
        val embedded = parseEmbeddedJson(value)
        if (embedded != null) {
            // Within user text (tool arguments and output) every string is user data.
            val document = Document(embedded, slot)
            out.nested += document
            collect(embedded, key, JsonScope.ALL, document, out)
        } else {
            out.targets += Target(slot, value, key)
        }
    }

    private fun parseEmbeddedJson(value: String): JsonNode? {
        val first = value.firstOrNull { !it.isWhitespace() } ?: return null
        val last = value.lastOrNull { !it.isWhitespace() } ?: return null
        if (!((first == '{' && last == '}') || (first == '[' && last == ']'))) return null
        return parseJson(value)?.takeIf { it.isContainerNode }
    }

    private fun parseJson(text: String): JsonNode? =
        try {
            mapper.readTree(text)?.takeUnless { it.isMissingNode }
        } catch (_: Exception) {
            null
        }

    // ── form and query ────────────────────────────────────────────────────

    private fun redactFormBody(bytes: ByteArray, naming: PlaceholderNaming): BodyTransform {
        val text = strictUtf8(bytes) ?: return BodyTransform(bytes, 0, false, "non-utf8-body")
        val result = redactFormEncoded(text, naming)
        return BodyTransform(result.text.toByteArray(StandardCharsets.UTF_8), result.detections, result.usedFallback)
    }

    /**
     * `k=v&k2=v2`: each value is percent-decoded leniently, detected with its
     * key as context, and re-encoded only if it changed; untouched pairs keep
     * their exact bytes. A malformed escape such as `%zz` used to throw out of
     * URLDecoder and send the whole request unredacted.
     */
    private fun redactFormEncoded(encoded: String, naming: PlaceholderNaming): TextTransform {
        val pieces = encoded.split('&')
        val fields = ArrayList<TextRedactor.Field>()
        val pieceOfField = ArrayList<Int>()
        pieces.forEachIndexed { i, piece ->
            val equals = piece.indexOf('=')
            val rawValue = if (equals < 0) piece else piece.substring(equals + 1)
            if (rawValue.isEmpty()) return@forEachIndexed
            val value = percentDecode(rawValue) ?: return@forEachIndexed
            if (equals < 0) {
                fields += TextRedactor.Field(value)
            } else {
                val key = percentDecode(piece.substring(0, equals)) ?: piece.substring(0, equals)
                fields += TextRedactor.Field(value, prefix = "\"$key\": \"", suffix = "\"")
            }
            pieceOfField += i
        }
        if (fields.isEmpty()) return TextTransform(encoded, 0, false)
        val outcomes = redactor.redactFields(fields, naming)
        val usedFallback = outcomes.any { it.usedFallback }
        val detections = outcomes.sumOf { it.spans.size }
        if (detections == 0) return TextTransform(encoded, 0, usedFallback)
        val rebuilt = pieces.toMutableList()
        outcomes.forEachIndexed { j, outcome ->
            if (outcome.spans.isEmpty()) return@forEachIndexed
            val i = pieceOfField[j]
            val piece = pieces[i]
            val equals = piece.indexOf('=')
            val value = URLEncoder.encode(outcome.text, StandardCharsets.UTF_8)
            rebuilt[i] = if (equals < 0) value else piece.substring(0, equals + 1) + value
        }
        return TextTransform(rebuilt.joinToString("&"), detections, usedFallback)
    }

    /** `%XX` and `+` decoded, malformed escapes kept literally; null if the bytes are not UTF-8. */
    private fun percentDecode(text: String): String? {
        if ('%' !in text && '+' !in text) return text
        val out = ByteArrayOutputStream(text.length)
        var i = 0
        while (i < text.length) {
            val c = text[i]
            val high = if (c == '%' && i + 2 < text.length) Character.digit(text[i + 1], 16) else -1
            val low = if (high >= 0) Character.digit(text[i + 2], 16) else -1
            when {
                high >= 0 && low >= 0 -> {
                    out.write(high * 16 + low)
                    i += 3
                }
                c == '+' -> {
                    out.write(' '.code)
                    i++
                }
                else -> {
                    val codePoint = text.codePointAt(i)
                    out.write(String(Character.toChars(codePoint)).toByteArray(StandardCharsets.UTF_8))
                    i += Character.charCount(codePoint)
                }
            }
        }
        return strictUtf8(out.toByteArray())
    }

    // ── multipart ─────────────────────────────────────────────────────────

    /**
     * Each part on its own: text parts are redacted, PNG/JPEG parts go to the
     * image redactor, other files are left alone. Whole-body text scanning
     * failed the UTF-8 check as soon as any binary file was attached, so the
     * text fields beside an upload went out unredacted.
     */
    private fun redactMultipart(bytes: ByteArray, contentType: String, naming: PlaceholderNaming): BodyTransform {
        val boundary = BOUNDARY.find(contentType)?.let { it.groups[1]?.value ?: it.groups[2]?.value }
            ?: return BodyTransform(bytes, 0, false, "multipart-without-boundary")
        val delimiter = "--$boundary".toByteArray(StandardCharsets.ISO_8859_1)
        val positions = ArrayList<Int>()
        var from = 0
        while (true) {
            val at = indexOf(bytes, delimiter, from)
            if (at < 0) break
            if (at == 0 || (at >= 2 && bytes[at - 2] == CR && bytes[at - 1] == LF)) positions += at
            from = at + delimiter.size
        }
        if (positions.size < 2) return BodyTransform(bytes, 0, false, "invalid-multipart")

        class Part(val bodyStart: Int, val bodyEnd: Int, val headers: Map<String, String>)
        val parts = ArrayList<Part>()
        for (k in 0 until positions.size - 1) {
            val afterDelimiter = positions[k] + delimiter.size
            if (afterDelimiter + 1 < bytes.size && bytes[afterDelimiter] == DASH && bytes[afterDelimiter + 1] == DASH) break
            val lineEnd = indexOf(bytes, CRLF, afterDelimiter)
            val bodyEnd = positions[k + 1] - 2
            if (lineEnd < 0 || lineEnd > bodyEnd) return BodyTransform(bytes, 0, false, "invalid-multipart")
            val headerEnd = if (bytes.startsWith(CRLF, lineEnd + 2)) lineEnd else indexOf(bytes, CRLFCRLF, lineEnd)
            if (headerEnd < 0 || headerEnd + 4 > bodyEnd) return BodyTransform(bytes, 0, false, "invalid-multipart")
            val headerText = String(bytes, lineEnd + 2, maxOf(0, headerEnd - lineEnd - 2), StandardCharsets.ISO_8859_1)
            parts += Part(headerEnd + 4, bodyEnd, parseHeaders(headerText))
        }

        val replacements = HashMap<Int, ByteArray>()
        var detections = 0
        var usedFallback = false
        val textParts = ArrayList<Int>()
        val textFields = ArrayList<TextRedactor.Field>()
        parts.forEachIndexed { p, part ->
            val transferEncoding = part.headers["content-transfer-encoding"]?.trim()?.lowercase()
            if (transferEncoding != null && transferEncoding !in setOf("7bit", "8bit", "binary")) return@forEachIndexed
            val body = bytes.copyOfRange(part.bodyStart, part.bodyEnd)
            val media = mediaType(part.headers["content-type"])
            val disposition = part.headers["content-disposition"].orEmpty()
            when {
                media in IMAGE_TYPES -> {
                    val image = redactImageBody(body, media)
                    if (image.reason == null && image.detections > 0) {
                        replacements[p] = image.body
                        detections += image.detections
                    }
                }
                media.isEmpty() || media == "application/octet-stream" || isTextual(media) -> {
                    val text = strictUtf8(body) ?: return@forEachIndexed
                    if ('\u0000' in text) return@forEachIndexed
                    if (media.contains("json")) {
                        val result = transformText(text, media, naming)
                        usedFallback = usedFallback || result.usedFallback
                        if (result.detections > 0) {
                            replacements[p] = result.text.toByteArray(StandardCharsets.UTF_8)
                            detections += result.detections
                        }
                    } else {
                        val name = DISPOSITION_NAME.find(disposition)?.groupValues?.get(1)
                        textFields += if (name == null) TextRedactor.Field(text)
                        else TextRedactor.Field(text, prefix = "\"$name\": \"", suffix = "\"")
                        textParts += p
                    }
                }
            }
        }
        if (textFields.isNotEmpty()) {
            val outcomes = redactor.redactFields(textFields, naming)
            outcomes.forEachIndexed { j, outcome ->
                usedFallback = usedFallback || outcome.usedFallback
                if (outcome.spans.isEmpty()) return@forEachIndexed
                replacements[textParts[j]] = outcome.text.toByteArray(StandardCharsets.UTF_8)
                detections += outcome.spans.size
            }
        }
        if (detections == 0) return BodyTransform(bytes, 0, usedFallback)
        val out = ByteArrayOutputStream(bytes.size)
        var cursor = 0
        parts.forEachIndexed { p, part ->
            val replacement = replacements[p] ?: return@forEachIndexed
            out.write(bytes, cursor, part.bodyStart - cursor)
            out.write(replacement)
            cursor = part.bodyEnd
        }
        out.write(bytes, cursor, bytes.size - cursor)
        return BodyTransform(out.toByteArray(), detections, usedFallback)
    }

    private fun parseHeaders(text: String): Map<String, String> =
        text.split("\r\n").mapNotNull { line ->
            val colon = line.indexOf(':')
            if (colon <= 0) null else line.substring(0, colon).trim().lowercase() to line.substring(colon + 1).trim()
        }.toMap()

    // ── protobuf and gRPC ─────────────────────────────────────────────────

    private class ProtoField(
        val headerStart: Int,
        val payloadStart: Int,
        val payloadEnd: Int,
        val lengthDelimited: Boolean,
        val nested: List<ProtoField>?,
        val textIndex: Int,
    )

    private fun redactProtobufBody(bytes: ByteArray, naming: PlaceholderNaming): BodyTransform =
        redactProtobufMessage(bytes, naming)
            ?: BodyTransform(bytes, 0, false, "invalid-protobuf")

    /**
     * Schema-blind walk. A length-delimited field is first tried as a nested
     * message, then as UTF-8 text; strings are redacted in one batch and every
     * enclosing length is recomputed. Treating nested messages as text (the
     * old walker) edited bytes inside them without fixing their lengths.
     */
    private fun redactProtobufMessage(bytes: ByteArray, naming: PlaceholderNaming): BodyTransform? {
        val texts = ArrayList<String>()
        val fields = parseMessage(bytes, 0, bytes.size, 0, texts) ?: return null
        if (texts.isEmpty()) return BodyTransform(bytes, 0, false)
        val outcomes = redactor.redactFields(texts.map { TextRedactor.Field(it) }, naming)
        val usedFallback = outcomes.any { it.usedFallback }
        val detections = outcomes.sumOf { it.spans.size }
        if (detections == 0) return BodyTransform(bytes, 0, usedFallback)
        val out = ByteArrayOutputStream(bytes.size + 64)
        writeMessage(bytes, 0, bytes.size, fields, outcomes, out)
        return BodyTransform(out.toByteArray(), detections, usedFallback)
    }

    private fun parseMessage(bytes: ByteArray, start: Int, end: Int, depth: Int, texts: MutableList<String>): List<ProtoField>? {
        val fields = ArrayList<ProtoField>()
        val textsBefore = texts.size
        var cursor = start
        fun fail(): List<ProtoField>? {
            while (texts.size > textsBefore) texts.removeAt(texts.size - 1)
            return null
        }
        while (cursor < end) {
            val headerStart = cursor
            val (tag, afterTag) = readVarint(bytes, cursor, end) ?: return fail()
            if (tag ushr 3 == 0L) return fail() // field number 0 is invalid
            cursor = afterTag
            when ((tag and 7).toInt()) {
                0 -> cursor = (readVarint(bytes, cursor, end) ?: return fail()).second
                1 -> cursor = if (cursor + 8 <= end) cursor + 8 else return fail()
                5 -> cursor = if (cursor + 4 <= end) cursor + 4 else return fail()
                2 -> {
                    val (length, afterLength) = readVarint(bytes, cursor, end) ?: return fail()
                    if (length < 0 || length > end - afterLength) return fail()
                    val payloadEnd = afterLength + length.toInt()
                    val nested = if (length > 0 && depth < MAX_PROTOBUF_DEPTH) {
                        parseMessage(bytes, afterLength, payloadEnd, depth + 1, texts)
                    } else {
                        null
                    }
                    var textIndex = -1
                    if (nested == null && length > 0) {
                        strictUtf8(bytes.copyOfRange(afterLength, payloadEnd))?.let {
                            textIndex = texts.size
                            texts += it
                        }
                    }
                    fields += ProtoField(headerStart, afterLength, payloadEnd, true, nested, textIndex)
                    cursor = payloadEnd
                    continue
                }
                else -> return fail() // groups (3, 4) and reserved wire types
            }
            fields += ProtoField(headerStart, cursor, cursor, false, null, -1)
        }
        return fields
    }

    private fun writeMessage(
        bytes: ByteArray,
        start: Int,
        end: Int,
        fields: List<ProtoField>,
        outcomes: List<RedactionOutcome>,
        out: ByteArrayOutputStream,
    ) {
        var cursor = start
        for (field in fields) {
            if (!field.lengthDelimited) continue // copied verbatim with the surrounding bytes
            out.write(bytes, cursor, field.headerStart - cursor)
            // Re-emit the tag; the length is recomputed below.
            val (_, afterTag) = readVarint(bytes, field.headerStart, end)!!
            out.write(bytes, field.headerStart, afterTag - field.headerStart)
            val payload = when {
                field.nested != null -> ByteArrayOutputStream().also { inner ->
                    writeMessage(bytes, field.payloadStart, field.payloadEnd, field.nested, outcomes, inner)
                }.toByteArray()
                field.textIndex >= 0 && outcomes[field.textIndex].spans.isNotEmpty() ->
                    outcomes[field.textIndex].text.toByteArray(StandardCharsets.UTF_8)
                else -> bytes.copyOfRange(field.payloadStart, field.payloadEnd)
            }
            writeVarint(out, payload.size.toLong())
            out.write(payload)
            cursor = field.payloadEnd
        }
        out.write(bytes, cursor, end - cursor)
    }

    /**
     * gRPC / gRPC-Web / Connect streaming bodies: 5-byte envelopes (flags,
     * big-endian length) around each message. They were text-scanned before,
     * which edited messages without touching the envelope lengths.
     */
    private fun redactEnveloped(bytes: ByteArray, json: Boolean, naming: PlaceholderNaming): BodyTransform {
        class Frame(val flags: Int, val start: Int, val end: Int)
        val frames = ArrayList<Frame>()
        var cursor = 0
        while (cursor < bytes.size) {
            if (cursor + 5 > bytes.size) return BodyTransform(bytes, 0, false, "invalid-grpc-frame")
            val flags = bytes[cursor].toInt() and 0xff
            val length = ByteBuffer.wrap(bytes, cursor + 1, 4).int
            if (length < 0 || length > bytes.size - cursor - 5) return BodyTransform(bytes, 0, false, "invalid-grpc-frame")
            if (flags and 0x01 != 0) return BodyTransform(bytes, 0, false, "grpc-compressed-message")
            frames += Frame(flags, cursor + 5, cursor + 5 + length)
            cursor += 5 + length
        }
        var detections = 0
        var usedFallback = false
        val out = ByteArrayOutputStream(bytes.size + 64)
        for (frame in frames) {
            val message = bytes.copyOfRange(frame.start, frame.end)
            val redacted: ByteArray = if (frame.flags != 0) {
                message // trailers and other control frames
            } else if (json) {
                val text = strictUtf8(message)
                if (text == null) message else transformText(text, "application/json", naming).let {
                    detections += it.detections
                    usedFallback = usedFallback || it.usedFallback
                    if (it.detections > 0) it.text.toByteArray(StandardCharsets.UTF_8) else message
                }
            } else {
                val result = redactProtobufMessage(message, naming)
                    ?: return BodyTransform(bytes, 0, false, "invalid-protobuf")
                detections += result.detections
                usedFallback = usedFallback || result.usedFallback
                result.body
            }
            out.write(frame.flags)
            out.write(ByteBuffer.allocate(4).putInt(redacted.size).array())
            out.write(redacted)
        }
        return BodyTransform(out.toByteArray(), detections, usedFallback)
    }

    private fun readVarint(data: ByteArray, start: Int, end: Int): Pair<Long, Int>? {
        var result = 0L
        var shift = 0
        var index = start
        while (index < end && shift < 64) {
            val value = data[index++].toInt() and 0xff
            result = result or ((value and 0x7f).toLong() shl shift)
            if (value and 0x80 == 0) return result to index
            shift += 7
        }
        return null
    }

    private fun writeVarint(out: ByteArrayOutputStream, value: Long) {
        var current = value
        while (current and -128L != 0L) {
            out.write(((current and 127L) or 128L).toInt())
            current = current ushr 7
        }
        out.write(current.toInt())
    }

    // ── images ────────────────────────────────────────────────────────────

    private fun redactImageBody(decoded: ByteArray, mediaType: String): BodyTransform {
        if (!hasImageSignature(decoded, mediaType)) return BodyTransform(decoded, 0, false, "invalid-image-body")
        return try {
            val result = imageRedactor.redact(decoded, mediaType)
            BodyTransform(result.body, result.detections, false)
        } catch (_: Exception) {
            BodyTransform(decoded, 0, false, "image-redactor-unavailable")
        }
    }

    /** Redact inline data-URL image attachments before scanning the surrounding text. */
    private fun redactEmbeddedImages(text: String): EmbeddedImageTransform {
        if ("data:image/" !in text) return EmbeddedImageTransform(text, 0)
        val out = StringBuilder(text.length)
        var cursor = 0
        var detections = 0
        for (match in DATA_IMAGE_URL.findAll(text)) {
            val mediaType = match.groups[1]!!.value.lowercase()
            val encoded = match.groups[2]!!.value.filterNot { it == '\r' || it == '\n' }
            val replacement = try {
                val source = Base64.getDecoder().decode(encoded)
                if (!hasImageSignature(source, mediaType)) continue
                val result = imageRedactor.redact(source, mediaType)
                if (result.detections == 0) continue
                detections += result.detections
                "data:$mediaType;base64," + Base64.getEncoder().encodeToString(result.body)
            } catch (_: Exception) {
                continue
            }
            out.append(text, cursor, match.range.first).append(replacement)
            cursor = match.range.last + 1
        }
        if (detections == 0) return EmbeddedImageTransform(text, 0)
        out.append(text, cursor, text.length)
        return EmbeddedImageTransform(out.toString(), detections)
    }

    private data class EmbeddedImageTransform(val text: String, val detections: Int)

    // ── encodings ─────────────────────────────────────────────────────────

    private fun decode(bytes: ByteArray, encoding: String): ByteArray? = try {
        when (encoding) {
            "", "identity" -> bytes
            "gzip", "x-gzip" -> GZIPInputStream(ByteArrayInputStream(bytes)).use { it.readBytes() }
            "deflate" -> InflaterInputStream(ByteArrayInputStream(bytes)).use { it.readBytes() }
            "zstd" -> ZstdInputStream(ByteArrayInputStream(bytes)).use { it.readBytes() }
            else -> null // Brotli needs a native encoder; stacked codings are not unwrapped
        }
    } catch (_: Exception) {
        null
    }

    private fun encode(bytes: ByteArray, encoding: String): ByteArray? = try {
        when (encoding) {
            "", "identity" -> bytes
            "gzip", "x-gzip" -> ByteArrayOutputStream().also { o -> GZIPOutputStream(o).use { it.write(bytes) } }.toByteArray()
            "deflate" -> ByteArrayOutputStream().also { o -> DeflaterOutputStream(o).use { it.write(bytes) } }.toByteArray()
            "zstd" -> ByteArrayOutputStream().also { o -> ZstdOutputStream(o).use { it.write(bytes) } }.toByteArray()
            else -> null
        }
    } catch (_: Exception) {
        null
    }

    companion object {
        /**
         * Numbers keep their exact text value: big decimals, trailing zeros
         * (`1.50`), large integers. Duplicate keys and trailing garbage make
         * the body "not JSON" (text-scanned) instead of silently losing data
         * on re-serialization.
         */
        private val mapper: ObjectMapper = JsonMapper.builder()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .configure(JsonNodeFeature.STRIP_TRAILING_BIGDECIMAL_ZEROES, false)
            .build()

        private val IMAGE_TYPES = setOf("image/jpeg", "image/png")
        private val ENVELOPED_PROTOBUF = setOf(
            "application/grpc", "application/grpc+proto", "application/grpc-web",
            "application/grpc-web+proto", "application/connect+proto",
        )
        private val ENVELOPED_JSON = setOf("application/grpc+json", "application/grpc-web+json", "application/connect+json")
        private const val JSON_OPENERS = "{["
        private const val MAX_PROTOBUF_DEPTH = 32
        private val DATA_IMAGE_URL = Regex("""data:(image/(?:png|jpeg));base64,([A-Za-z0-9+/=\r\n]+)""")
        private val BOUNDARY = Regex("""(?i)boundary=(?:"([^"]+)"|([^;\s]+))""")
        private val DISPOSITION_NAME = Regex("""(?i)(?:^|;)\s*name="([^"]*)""")

        /**
         * Responses API members that hold user or tool text. `output` carries
         * tool results (file contents, command output), `arguments` and
         * `command` what the model ran; leaving them out sent exactly the
         * material most likely to hold secrets upstream verbatim.
         */
        val RESPONSES_USER_TEXT_KEYS = setOf(
            "content", "input", "instructions", "message", "prompt", "text",
            "output", "arguments", "command",
        )

        private const val CR = '\r'.code.toByte()
        private const val LF = '\n'.code.toByte()
        private const val DASH = '-'.code.toByte()
        private val CRLF = byteArrayOf(CR, LF)
        private val CRLFCRLF = byteArrayOf(CR, LF, CR, LF)

        internal fun mediaType(contentType: String?): String =
            contentType?.substringBefore(';')?.trim()?.lowercase().orEmpty()

        private fun normalizeEncoding(contentEncoding: String?): String = contentEncoding?.trim()?.lowercase().orEmpty()

        private fun isTextual(media: String): Boolean =
            media.startsWith("text/") || media.contains("json") || media.contains("xml") ||
                media == "application/x-www-form-urlencoded" || media == "application/javascript" ||
                media == "application/x-yaml" || media == "application/yaml"

        internal fun strictUtf8(bytes: ByteArray): String? = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: CharacterCodingException) {
            null
        }

        private fun indexOf(haystack: ByteArray, needle: ByteArray, from: Int): Int {
            if (needle.isEmpty()) return from
            var i = maxOf(from, 0)
            val last = haystack.size - needle.size
            while (i <= last) {
                if (haystack[i] == needle[0] && haystack.startsWith(needle, i)) return i
                i++
            }
            return -1
        }

        private fun ByteArray.startsWith(prefix: ByteArray, at: Int): Boolean {
            if (at < 0 || at + prefix.size > size) return false
            for (k in prefix.indices) if (this[at + k] != prefix[k]) return false
            return true
        }

        fun hasImageSignature(bytes: ByteArray, mediaType: String): Boolean = when (mediaType) {
            "image/png" -> bytes.size >= 8 && bytes.copyOfRange(0, 8).contentEquals(
                byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
            )
            "image/jpeg" -> bytes.size >= 3 && bytes[0] == 0xff.toByte() &&
                bytes[1] == 0xd8.toByte() && bytes[2] == 0xff.toByte()
            else -> false
        }
    }
}
