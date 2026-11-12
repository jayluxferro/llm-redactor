package org.llmredactor.burp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Spot checks with readable expectations. Exhaustive agreement with the
 * Python detectors is ParityTest's job; these pin the behaviours that were
 * once wrong here and the ones this file's readers will look for.
 */
class RegexDetectorTest {
    private val detector = RegexDetector()

    private fun kinds(text: String) = detector.detect(text).map { it.kind }

    private fun covered(text: String) = detector.detect(text).map {
        text.substring(text.offsetByCodePoints(0, it.start), text.offsetByCodePoints(0, it.end))
    }

    @Test fun `detects email address`() {
        assertEquals(listOf("alice@example.com"), covered("contact alice@example.com for info"))
        assertEquals(listOf("email"), kinds("contact alice@example.com for info"))
    }

    @Test fun `phone numbers use the Python kinds`() {
        assertEquals(listOf("phone_us"), kinds("call 555-123-4567 today"))
        assertEquals(listOf("phone_intl"), kinds("office +44 20 7946 0958"))
        assertEquals(emptyList(), kinds("code 12345 is short"))
    }

    @Test fun `version numbers and timestamps are not phone numbers`() {
        // The old catch-all phone pattern took any 6+ digits in 2-4 digit groups.
        assertEquals(emptyList(), kinds("release 2.4.1 build 20261112 port 8080 id 123456"))
    }

    @Test fun `detects SSN and not the wrong shape`() {
        assertEquals(listOf("ssn"), kinds("123-45-6789"))
        assertEquals(emptyList(), kinds("123-456-789 has wrong segment lengths"))
    }

    @Test fun `detects IPv4 and IPv6`() {
        assertEquals(listOf("ip_v4"), kinds("server at 192.168.1.1 is up"))
        assertEquals(listOf("ip_v6"), kinds("host fe80:0000:0000:0000:0202:b3ff:fe1e:8329"))
        assertEquals(emptyList(), kinds("999.999.999.999 is not valid"))
    }

    @Test fun `detects credit card number`() {
        assertEquals(listOf("credit_card"), kinds("card 4111-1111-1111-1111 paid"))
        assertTrue("credit_card" !in kinds("1234-5678-9012-3456 has wrong prefix"))
    }

    @Test fun `checksummed identifiers must validate`() {
        assertEquals(listOf("iban"), kinds("GB82 WEST 1234 5698 7654 32"))
        assertEquals(emptyList(), kinds("GB82 WEST 1234 5698 7654 33"))
        assertEquals(listOf("npi"), kinds("NPI 1234567893"))
        assertTrue("npi" !in kinds("NPI 1234567890"))
    }

    @Test fun `password assignments, quoted values whole`() {
        assertEquals(listOf("secret123"), covered("config: password=secret123 is set"))
        assertEquals(listOf("my secret passphrase here"), covered("PASSWORD=\"my secret passphrase here\""))
        assertEquals(listOf("C!UNSFj!p9AM"), covered("\"password\": \"C!UNSFj!p9AM\""))
        assertEquals(emptyList(), kinds("password=ab is too short"))
    }

    @Test fun `detects connection string`() {
        assertEquals(listOf("connection_string"), kinds("url: mongodb://user:pass@host:27017/db"))
        assertEquals(emptyList(), kinds("mongodb://short"))
    }

    @Test fun `cloud and vendor keys`() {
        assertEquals(listOf("aws_access_key"), kinds("key AKIAIOSFODNN7EXAMPLE is aws"))
        assertEquals(listOf("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), covered("\"aws_secret_key\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\""))
        assertEquals(listOf("gcp_api_key"), kinds("key AIza" + "a".repeat(35) + " here"))
        assertEquals(listOf("openai_api_key"), kinds("sk-proj-abc123def456ghi789jkl012mno345pqr678stu"))
        assertEquals(listOf("github_token"), kinds("ghp_abc123def456ghi789jkl012mno345pqr678stu"))
        assertEquals(listOf("github_token"), kinds("github_pat_" + "AbCdEfGhIjKlMnOpQrStUv" + "_" + "a".repeat(59)))
        assertEquals(listOf("gitlab_token"), kinds("glpat-abc123def456ghi789jkl012"))
        assertEquals(listOf("stripe_key"), kinds("key rk_test_fakeStripeTestKeyForUnitTests"))
        assertEquals(listOf("huggingface_token"), kinds("use hf_" + "a".repeat(34)))
    }

    @Test fun `generic assignments and auth headers`() {
        assertEquals(listOf("generic_api_key"), kinds("api_key=abc123def456ghi789jkl012"))
        assertEquals(listOf("bearer_token"), kinds("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"))
        assertEquals(listOf("jwt"), kinds("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"))
    }

    @Test fun `a PEM private key is covered from BEGIN to END`() {
        // The old pattern matched the BEGIN line alone and sent the key body upstream.
        val pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Aq4X9Z\n-----END RSA PRIVATE KEY-----"
        assertEquals(listOf(pem), covered("key:\n$pem\nthanks"))
        val ssh = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----"
        assertEquals(listOf("ssh_private_key"), kinds(ssh))
    }

    @Test fun `internal hostnames are covered whole`() {
        assertEquals(listOf("db.staging.internal"), covered("connect to db.staging.internal"))
        // Stopping at the internal label left ".globex.net" in the clear.
        assertEquals(listOf("cache-04.corp.globex.net"), covered("cache-04.corp.globex.net"))
        assertEquals(emptyList(), kinds("example.com is public"))
    }

    @Test fun `wallets, keys and seed phrases`() {
        assertEquals(listOf("crypto_btc"), kinds("send to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
        assertEquals(listOf("crypto_btc"), kinds("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
        assertEquals(listOf("crypto_eth"), kinds("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"))
        assertEquals(listOf("crypto_dot"), kinds("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"))
        assertEquals(listOf("crypto_private_key"), kinds("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"))
        assertEquals(
            listOf("crypto_private_key"),
            kinds("PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
        )
        // A bare 32-byte hex value is usually a hash: no key keyword, no redaction.
        assertEquals(emptyList(), kinds("tx 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060 mined"))
        val seed = "legal winner thank year wave sausage worth useful legal winner thank yellow"
        assertEquals(emptyList(), kinds(seed)) // the public test vector: 4 repeated words, not random
        val phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        assertEquals(listOf(phrase), covered("seed: $phrase"))
    }

    @Test fun `mistyped addresses fail their checksum and pass`() {
        assertEquals(emptyList(), kinds("send to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3"))
    }

    // ── overlap merging ──

    @Test fun `overlapping spans merge into their union`() {
        // "Bearer <jwt>": bearer_token covers the JWT; one span, the earlier label.
        val text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assertEquals(listOf(text), covered(text))
        assertEquals(listOf("bearer_token"), kinds(text))
    }

    @Test fun `keeps non-overlapping spans from different patterns`() {
        assertEquals(listOf("email", "ip_v4"), kinds("alice@example.com sent 192.168.1.1"))
    }

    // ── code-point offsets ──

    @Test fun `offsets are code-point based with non-BMP prefix`() {
        val text = "😀😀 alice@example.com"
        val span = detector.detect(text).single()
        assertEquals(3, span.start)
        assertEquals("alice@example.com", covered(text).single())
    }

    @Test fun `offsets work correctly with ASCII-only text`() {
        assertEquals(6, detector.detect("email alice@example.com for help").single().start)
    }

    @Test fun `empty and clean texts produce no spans`() {
        assertEquals(emptyList(), kinds(""))
        assertEquals(emptyList(), kinds("just some regular text without any secrets"))
    }
}
