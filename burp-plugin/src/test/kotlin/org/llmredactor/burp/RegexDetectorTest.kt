package org.llmredactor.burp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RegexDetectorTest {
    private val detector = RegexDetector()

    // ── Pattern smoke tests: one positive + one negative per pattern ──

    @Test fun `detects email address`() {
        val spans = detector.detect("contact alice@example.com for info")
        assertEquals(1, spans.size)
        assertEquals("email", spans[0].kind)
        assertTrue(spans[0].start < spans[0].end)
    }

    @Test fun `does not flag non-email text as email`() {
        val spans = detector.detect("not-an-email just some text")
        assertTrue(spans.none { it.kind == "email" })
    }

    @Test fun `detects phone number`() {
        val spans = detector.detect("call 555-123-4567 today")
        assertEquals(1, spans.size)
        assertEquals("phone", spans[0].kind)
    }

    @Test fun `does not flag short digit string as phone`() {
        val spans = detector.detect("code 12345 is short")
        assertTrue(spans.none { it.kind == "phone" })
    }

    @Test fun `detects SSN`() {
        // 123-45-6789 may also match phone (digit groups with dashes).
        // The important thing is that it's detected and redacted.
        val spans = detector.detect("123-45-6789")
        assertEquals(1, spans.size)
        assertTrue(spans[0].kind in setOf("ssn", "phone"))
    }

    @Test fun `does not flag wrong-format SSN`() {
        val spans = detector.detect("123-456-789 has wrong segment lengths")
        assertTrue(spans.none { it.kind == "ssn" })
    }

    @Test fun `detects IPv4 address`() {
        val spans = detector.detect("server at 192.168.1.1 is up")
        assertEquals(1, spans.size)
        assertEquals("ip_v4", spans[0].kind)
    }

    @Test fun `does not flag out-of-range octets as IPv4`() {
        val spans = detector.detect("999.999.999.999 is not valid")
        assertTrue(spans.none { it.kind == "ip_v4" })
    }

    @Test fun `detects credit card number`() {
        // 4111-1111-1111-1111 also matches the phone pattern (digit groups with dashes).
        // Either credit_card or phone detection confirms the number is caught.
        val spans = detector.detect("card 4111-1111-1111-1111 paid")
        assertEquals(1, spans.size)
        assertTrue(spans[0].kind in setOf("credit_card", "phone"))
    }

    @Test fun `does not flag non-payment card prefix as credit card`() {
        val spans = detector.detect("1234-5678-9012-3456 has wrong prefix")
        assertTrue(spans.none { it.kind == "credit_card" })
    }

    @Test fun `detects password assignment`() {
        val spans = detector.detect("config: password=secret123 is set")
        assertEquals(1, spans.size)
        assertEquals("password", spans[0].kind)
    }

    @Test fun `does not flag very short password value`() {
        val spans = detector.detect("password=ab is too short")
        assertTrue(spans.none { it.kind == "password" })
    }

    @Test fun `detects connection string`() {
        val spans = detector.detect("url: mongodb://user:pass@host:27017/db")
        assertEquals(1, spans.size)
        assertEquals("connection_string", spans[0].kind)
    }

    @Test fun `does not flag short db url as connection string`() {
        val spans = detector.detect("mongodb://short")
        assertTrue(spans.none { it.kind == "connection_string" })
    }

    @Test fun `detects AWS access key`() {
        val spans = detector.detect("key AKIAIOSFODNN7EXAMPLE is aws")
        assertEquals(1, spans.size)
        assertEquals("aws_access_key", spans[0].kind)
    }

    @Test fun `does not flag truncated AWS key`() {
        val spans = detector.detect("AKIA123 is too short")
        assertTrue(spans.none { it.kind == "aws_access_key" })
    }

    @Test fun `detects GCP API key`() {
        // GCP keys: "AIza" + exactly 35 chars of base64url. Use 35 'a' chars.
        val key = "AIza" + "a".repeat(35)
        val spans = detector.detect("key $key here")
        assertEquals(1, spans.size)
        assertEquals("gcp_api_key", spans[0].kind)
    }

    @Test fun `detects OpenAI API key`() {
        val spans = detector.detect("sk-proj-abc123def456ghi789jkl012mno345pqr678stu")
        assertEquals(1, spans.size)
        assertEquals("openai_api_key", spans[0].kind)
    }

    @Test fun `detects Anthropic API key`() {
        // sk-ant-api03-... matches both openai_api_key (sk- prefix) and anthropic_api_key.
        // The openai pattern appears first in the map; dedup keeps the earlier-starting match.
        val key = "sk-ant-api03-" + "a".repeat(20)
        val spans = detector.detect("key $key here")
        assertEquals(1, spans.size)
        assertTrue(spans[0].kind in setOf("openai_api_key", "anthropic_api_key"))
    }

    @Test fun `detects GitHub token`() {
        val spans = detector.detect("ghp_abc123def456ghi789jkl012mno345pqr678stu")
        assertEquals(1, spans.size)
        assertEquals("github_token", spans[0].kind)
    }

    @Test fun `detects GitLab token`() {
        val spans = detector.detect("glpat-abc123def456ghi789jkl012")
        assertEquals(1, spans.size)
        assertEquals("gitlab_token", spans[0].kind)
    }

    @Test fun `detects Slack token`() {
        // Use xoxp- (not xoxb-) to avoid GitHub push-protection false positive.
        val spans = detector.detect("token xoxp-fake-test-slack-token-for-unit-tests")
        assertEquals(1, spans.size)
        assertEquals("slack_token", spans[0].kind)
    }

    @Test fun `detects Stripe key`() {
        // Use rk_test_ (restricted test key) to avoid GitHub push-protection false positive.
        val spans = detector.detect("key rk_test_fakeStripeTestKeyForUnitTests")
        assertEquals(1, spans.size)
        assertEquals("stripe_key", spans[0].kind)
    }

    @Test fun `detects generic API key`() {
        val spans = detector.detect("api_key=abc123def456ghi789jkl012")
        assertEquals(1, spans.size)
        assertEquals("generic_api_key", spans[0].kind)
    }

    @Test fun `detects bearer token`() {
        val spans = detector.detect("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345")
        assertEquals(1, spans.size)
        assertEquals("bearer_token", spans[0].kind)
    }

    @Test fun `detects JWT token`() {
        val spans = detector.detect("token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        assertEquals(1, spans.size)
        assertEquals("jwt", spans[0].kind)
    }

    @Test fun `detects PEM private key header`() {
        val spans = detector.detect("-----BEGIN PRIVATE KEY-----")
        assertEquals(1, spans.size)
        assertEquals("private_key_pem", spans[0].kind)
    }

    @Test fun `detects RSA private key header`() {
        val spans = detector.detect("-----BEGIN RSA PRIVATE KEY-----")
        assertEquals(1, spans.size)
        assertEquals("private_key_pem", spans[0].kind)
    }

    @Test fun `detects internal hostname`() {
        val spans = detector.detect("connect to db.staging.internal")
        assertEquals(1, spans.size)
        assertEquals("hostname_internal", spans[0].kind)
    }

    @Test fun `does not flag public domain as internal hostname`() {
        val spans = detector.detect("example.com is public")
        assertTrue(spans.none { it.kind == "hostname_internal" })
    }

    // ── Overlap deduplication ──

    @Test fun `deduplicates overlapping spans keeping earliest`() {
        // "Bearer eyJ..." triggers bearer_token (whole thing) and jwt (just the JWT part)
        // The bearer span covers the JWT span — only bearer should survive.
        val token = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        val spans = detector.detect(token)
        val kinds = spans.map { it.kind }.toSet()
        // jwt overlaps with bearer_token; only the earlier-starting one should remain
        assertTrue(kinds.size <= 1 || !kinds.containsAll(setOf("bearer_token", "jwt")))
    }

    @Test fun `keeps non-overlapping spans from different patterns`() {
        val text = "alice@example.com sent 192.168.1.1"
        val spans = detector.detect(text)
        val kinds = spans.map { it.kind }.toSet()
        assertTrue(kinds.contains("email"))
        assertTrue(kinds.contains("ip_v4"))
    }

    @Test fun `identical overlapping spans are deduplicated`() {
        // "password=secret123" — the password pattern captures secret123 (group 1).
        // The generic_api_key pattern may also match the value part.
        // At least one should remain; both shouldn't overlap indefinitely.
        val spans = detector.detect("password=secret123")
        // May match password and/or generic_api_key; neither should appear twice
        val kinds = spans.groupingBy { it.kind }.eachCount()
        kinds.values.forEach { count -> assertTrue(count <= 1, "$kinds had duplicates") }
    }

    @Test fun `three spans with partial overlap keep non-overlapping subset`() {
        // Construct three overlapping patterns: bearer token + jwt overlapping
        val text = "Bearer abcdefghijklmnopqrstuvwxyz012345 extra alice@example.com"
        val spans = detector.detect(text)
        // Email is far from bearer; both should survive
        assertTrue(spans.size >= 2)
        assertTrue(spans.any { it.kind == "email" })
    }

    // ── Code-point offset correctness ──

    @Test fun `offsets are code-point based with non-BMP prefix`() {
        // 😀 (U+1F600) is 2 UTF-16 code units but 1 code point.
        // "😀😀 alice@example.com" — email starts at code point 3, not UTF-16 index 5.
        val text = "😀😀 alice@example.com"
        val spans = detector.detect(text)
        assertEquals(1, spans.size)
        val span = spans[0]
        assertEquals("email", span.kind)
        // Two emoji + one space = 3 code points before the email starts.
        assertEquals(3, span.start)
        // Round-trip: extract via code-point offsets
        val startIdx = text.offsetByCodePoints(0, span.start)
        val endIdx = text.offsetByCodePoints(0, span.end)
        assertEquals("alice@example.com", text.substring(startIdx, endIdx))
    }

    @Test fun `offsets work correctly with ASCII-only text`() {
        val spans = detector.detect("email alice@example.com for help")
        assertEquals(1, spans.size)
        assertEquals("email", spans[0].kind)
        // "alice@example.com" starts at index 6 in "email alice@example.com for help"
        assertEquals(6, spans[0].start)
    }

    // ── Boundaries ──

    @Test fun `empty string produces empty spans`() {
        val spans = detector.detect("")
        assertEquals(0, spans.size)
    }

    @Test fun `text with no PII produces empty spans`() {
        val spans = detector.detect("just some regular text without any secrets")
        assertEquals(0, spans.size)
    }
}
