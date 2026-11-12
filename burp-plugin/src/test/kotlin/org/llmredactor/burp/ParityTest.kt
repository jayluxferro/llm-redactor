package org.llmredactor.burp

import com.fasterxml.jackson.databind.ObjectMapper
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Replays tests/test_burp_parity.py's fixture: for every sample, the built-in
 * detector must produce exactly the spans (code-point offsets and kinds) that
 * the Python detect_regex + orchestrator merge produced.
 */
class ParityTest {
    private val detector = RegexDetector()

    @Test fun `built-in detector matches the Python detectors on the parity corpus`() {
        val fixture = javaClass.getResourceAsStream("parity.json") ?: fail("parity.json missing from test resources")
        val samples = ObjectMapper().readTree(fixture).path("samples")
        assertTrue(samples.size() > 100, "the parity corpus is unexpectedly small")
        val mismatches = samples.mapNotNull { sample ->
            // Base64 in the fixture: its fake vendor tokens would otherwise be
            // secret-scanner bait in a public repository (see _render).
            val text = String(Base64.getDecoder().decode(sample.path("text_b64").asText()), Charsets.UTF_8)
            val expected = sample.path("spans").map { Triple(it[0].asInt(), it[1].asInt(), it[2].asText()) }
            val actual = detector.detect(text).map { Triple(it.start, it.end, it.kind) }
            if (expected == actual) null else "${text.take(60)}\n    python: $expected\n    kotlin: $actual"
        }
        assertEquals(emptyList(), mismatches, mismatches.joinToString("\n"))
    }
}

class Blake2bTest {
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    @Test fun `matches RFC 7693 and hashlib`() {
        assertEquals(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            hex(Blake2b.digest("abc".toByteArray())),
        )
        assertEquals(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
                "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            hex(Blake2b.digest(ByteArray(0))),
        )
        // Several blocks, the last one full: exercises the counter and final flag.
        val input = ByteArray(768) { (it % 256).toByte() }
        assertEquals(
            "323e97a7a859ee63c9013debb0ca995811e73117a2f574723416e596ebc184e3" +
                "7a59b66d2f597df4a7c1b0d1d41a1a7f28774f46a6864d56c57b9d6c5f7302fb",
            hex(Blake2b.digest(input)),
        )
    }
}

class WalletDetectorRobustnessTest {
    private val detector = RegexDetector()

    @Test fun `every bundled wordlist loads with its published size`() {
        // 13 lists; a word shared by several lists is one key, so this is a floor.
        assertTrue(WalletDetector.vocabulary.size > 20_000, "${WalletDetector.vocabulary.size} words")
        assertTrue("abandon" in WalletDetector.vocabulary)
    }

    @Test fun `long inputs never overflow the regex stack`() {
        // Each of these recursed once per repetition in a group-quantified
        // pattern and threw StackOverflowError somewhere past a few thousand.
        val inputs = listOf(
            "seed " + "abandon ability able about above absent ".repeat(20_000),
            "1 Main Street, " + "Springfield ".repeat(20_000),
            "a." + "b.".repeat(50_000) + "internal",
            "x." + "y.".repeat(50_000) + "eth",
            """{"encrypted_content":"""" + "a".repeat(200_000) + "\"}",
        )
        for (input in inputs) detector.detect(input)
        TextRedactor(DetectorClient("http://127.0.0.1:1/nope")).redact(inputs.last())
    }

    @Test fun `a long run of list words is still one seed phrase`() {
        val words = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        val spans = detector.detect("my words: $words $words")
        assertEquals(listOf("crypto_mnemonic"), spans.map { it.kind })
    }
}
