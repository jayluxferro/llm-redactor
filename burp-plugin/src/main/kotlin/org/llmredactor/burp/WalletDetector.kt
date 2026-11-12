package org.llmredactor.burp

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.NamedParameterSpec
import java.text.Normalizer
import java.util.regex.Pattern

/**
 * Port of src/llm_redactor/detect/wallets.py: blockchain addresses, public
 * keys, private keys and seed phrases. Each candidate is decoded and checked
 * against its format's own checksum, which is what keeps false positives near
 * zero. The structure follows the Python function for function so a change
 * there has an obvious counterpart here; tests/test_burp_parity.py pins the
 * Python output into a fixture that ParityTest replays against this file.
 *
 * Offsets given to [Sink] are UTF-16 indices; RegexDetector converts them to
 * code points.
 *
 * One deliberate structural difference: java.util.regex recurses once per
 * repetition of a group, so a Python-style `(?:word gap){11,}` pre-filter
 * overflows the stack on a long run of words (this extension once crashed on
 * long JSON strings for the same reason). Seed phrases and ENS names are
 * therefore found with plain character-class regexes plus code.
 */
internal object WalletDetector {
    fun interface Sink {
        fun hit(start: Int, end: Int, kind: String)
    }

    fun scan(text: String, sink: Sink) {
        scanMnemonics(text, sink)
        scanEns(text, sink)
        scanKeypairArrays(text, sink)
        scanHex(text, sink)
        scanEvm(text, sink)
        scanBech32(text, sink)
        scanCashAddr(text, sink)
        scanBase32(text, sink)
        scanBase58(text, sink)
    }

    /** Run a classifier; if it throws, report [fallback]: a bug must never unredact a key. */
    private inline fun failClosed(fallback: String, classify: () -> String?): String? =
        try {
            classify()
        } catch (_: Exception) {
            fallback
        }

    // ── Base58 ────────────────────────────────────────────────────────────

    private const val B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    // Ripple permutes the same 58 symbols so that its account IDs start with "r".
    private const val XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
    private val B58_INDEX = alphabetIndex(B58_ALPHABET)
    private val XRP_INDEX = alphabetIndex(XRP_ALPHABET)
    private val FIFTY_EIGHT = BigInteger.valueOf(58)

    private val B58_TOKEN = Regex("(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{25,120}(?![A-Za-z0-9])")

    private fun alphabetIndex(alphabet: String): IntArray =
        IntArray(128) { -1 }.also { table -> alphabet.forEachIndexed { i, c -> table[c.code] = i } }

    private fun b58decode(token: String, xrp: Boolean = false): ByteArray {
        val index = if (xrp) XRP_INDEX else B58_INDEX
        val zero = if (xrp) XRP_ALPHABET[0] else B58_ALPHABET[0]
        var n = BigInteger.ZERO
        for (ch in token) n = n.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(index[ch.code].toLong()))
        val pad = token.length - token.trimStart(zero).length
        return ByteArray(pad) + n.toFixedBytes((n.bitLength() + 7) / 8)
    }

    private fun BigInteger.toFixedBytes(size: Int): ByteArray {
        val raw = toByteArray() // two's complement: may carry a leading sign byte
        val out = ByteArray(size)
        val n = minOf(raw.size, size)
        System.arraycopy(raw, raw.size - n, out, size - n, n)
        return out
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** Verify and strip a Base58Check checksum (first 4 bytes of SHA-256^2). */
    private fun b58check(raw: ByteArray): ByteArray? {
        if (raw.size < 5) return null
        val payload = raw.copyOfRange(0, raw.size - 4)
        val digest = sha256(sha256(payload))
        for (i in 0 until 4) if (digest[i] != raw[raw.size - 4 + i]) return null
        return payload
    }

    // One-byte version prefixes of 20-byte-hash addresses (payload = 21 bytes).
    private val B58_ADDRESS_VERSIONS = mapOf(
        0x00 to "crypto_btc", 0x05 to "crypto_btc", 0x6F to "crypto_btc", 0xC4 to "crypto_btc",
        0x30 to "crypto_ltc", 0x32 to "crypto_ltc",
        0x1E to "crypto_doge", 0x16 to "crypto_doge",
        0x41 to "crypto_trx",
    )
    private val TEZOS_SECRET = listOf("edsk", "spsk", "p2sk", "BLsk", "edesk", "spesk", "p2esk", "BLesk")
    private val TEZOS_PUBLIC = listOf("edpk", "sppk", "p2pk", "BLpk")
    private val TEZOS_ADDRESS = listOf("tz1", "tz2", "tz3", "tz4", "KT1", "sr1")

    private fun classifyBase58Check(token: String, payload: ByteArray): String? {
        val n = payload.size
        if (TEZOS_SECRET.any(token::startsWith)) return "crypto_private_key"
        if (TEZOS_PUBLIC.any(token::startsWith)) return "crypto_public_key"
        if (TEZOS_ADDRESS.any(token::startsWith) && n == 23) return "crypto_xtz"
        if (n == 21) return B58_ADDRESS_VERSIONS[payload[0].toInt() and 0xff] ?: "crypto_address"
        if (n == 22 || n == 23) return "crypto_address"
        if (n == 33 || (n == 34 && payload[33] == 0x01.toByte())) return "crypto_private_key" // WIF
        // BIP32: the key field starts at offset 45; 0x00 marks a private key.
        if (n == 78) return if (payload[45] == 0.toByte()) "crypto_xprv" else "crypto_xpub"
        if (n == 39 && token.startsWith("6P")) return "crypto_private_key" // BIP38
        return null
    }

    private fun classifyXrp(payload: ByteArray): String? {
        val n = payload.size
        fun starts(vararg prefix: Int) = prefix.indices.all { payload[it] == prefix[it].toByte() }
        if (n == 21 && starts(0x00)) return "crypto_xrp"
        if (n == 31 && (starts(0x05, 0x44) || starts(0x04, 0x93))) return "crypto_xrp" // X-address
        if ((n == 17 && starts(0x21)) || (n == 19 && starts(0x01, 0xe1, 0x4b))) return "crypto_private_key"
        if (n == 33) return "crypto_private_key"
        if (n == 34) return "crypto_public_key"
        return null
    }

    private const val XRP_LEADS = "rsXTnpa"

    /** Polkadot-style account: prefix + 32/33-byte key + 2-byte BLAKE2b checksum. */
    private fun isSs58(raw: ByteArray): Boolean {
        if (raw.isEmpty()) return false
        val first = raw[0].toInt() and 0xff
        if (first >= 128) return false
        val prefixLength = if (first < 64) 1 else 2
        if (raw.size - prefixLength != 34 && raw.size - prefixLength != 35) return false
        val body = raw.copyOfRange(0, raw.size - 2)
        val digest = Blake2b.digest("SS58PRE".toByteArray(Charsets.US_ASCII) + body)
        return digest[0] == raw[raw.size - 2] && digest[1] == raw[raw.size - 1]
    }

    private val SOLANA_PUBLIC_IDS = setOf(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", // SPL Token-2022
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", // Associated Token Account
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", // Memo v2
        "So11111111111111111111111111111111111111112", // wrapped SOL mint
        "ComputeBudget111111111111111111111111111111", // Compute Budget
        "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s", // Metaplex Token Metadata
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", // USDC mint
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // USDT mint
    )

    /** camelCase identifiers have the exact shape of a Solana key; see wallets.py. */
    private fun looksLikeIdentifier(token: String): Boolean {
        val letters = token.count { it.isLetter() }
        val vowels = token.count { it in "aeiouAEU" }
        val digits = token.length - letters
        return digits <= 2 && vowels >= 0.30 * letters
    }

    private fun insideBase64(text: String, start: Int, end: Int): Boolean {
        val before = if (start > 0) text[start - 1] else '\u0000'
        val after = if (end < text.length) text[end] else '\u0000'
        return before == '+' || after == '+' || after == '=' || (before == '/' && after == '/')
    }

    private fun isSolanaPubkey(token: String, raw: ByteArray): Boolean =
        raw.size == 32 &&
            token.length in 32..44 &&
            token !in SOLANA_PUBLIC_IDS &&
            token.any { it.isUpperCase() } &&
            token.any { it.isLowerCase() } &&
            !looksLikeIdentifier(token)

    /**
     * The JDK can sign with Ed25519 but has no "public key of this seed" call.
     * A key-pair generator fed the seed as its randomness computes exactly
     * that. Whether the provider consumes randomness that way is checked once
     * against RFC 8032's first test vector; if it does not, every candidate
     * counts as a key (over-redact, never leak), as wallets.py does without
     * its crypto library.
     */
    private val ed25519Usable: Boolean by lazy {
        try {
            val seed = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            val expected = hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            ed25519PublicKey(seed).contentEquals(expected)
        } catch (_: Exception) {
            false
        }
    }

    private class SeedAsRandomness(private val seed: ByteArray) : SecureRandom() {
        override fun nextBytes(bytes: ByteArray) {
            for (i in bytes.indices) bytes[i] = seed[i % seed.size]
        }
    }

    private fun ed25519PublicKey(seed: ByteArray): ByteArray {
        val generator = KeyPairGenerator.getInstance("Ed25519")
        generator.initialize(NamedParameterSpec.ED25519, SeedAsRandomness(seed))
        val encoded = generator.generateKeyPair().public.encoded // X.509: the raw key is the tail
        return encoded.copyOfRange(encoded.size - 32, encoded.size)
    }

    /** seed(32) || public(32): Solana / NEAR secret keys, not transaction signatures. */
    private fun isEd25519Keypair(secret: ByteArray): Boolean {
        if (secret.size != 64) return false
        if (!ed25519Usable) return true
        return ed25519PublicKey(secret.copyOfRange(0, 32)).contentEquals(secret.copyOfRange(32, 64))
    }

    // Monero base58 works on 8-byte blocks -> 11 chars; a short final block of
    // k bytes takes XMR_BLOCK_CHARS[k] chars.
    private val XMR_BLOCK_CHARS = intArrayOf(0, 2, 3, 5, 6, 7, 9, 10, 11)
    private val XMR_NETWORK_BYTES = setOf(18, 19, 42, 24, 25, 36, 53, 54, 63)

    private fun moneroDecode(token: String): ByteArray? {
        if (XMR_BLOCK_CHARS.indexOf(token.length % 11) < 0) return null
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < token.length) {
            val block = token.substring(i, minOf(i + 11, token.length))
            val size = if (block.length == 11) 8 else XMR_BLOCK_CHARS.indexOf(block.length)
            var value = BigInteger.ZERO
            for (ch in block) value = value.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(B58_INDEX[ch.code].toLong()))
            if (value.shiftRight(8 * size).signum() != 0) return null // overflows its block
            out.write(value.toFixedBytes(size))
            i += 11
        }
        return out.toByteArray()
    }

    private fun isMonero(token: String): Boolean {
        if (token.length != 95 && token.length != 106) return false
        val raw = moneroDecode(token) ?: return false
        return (raw[0].toInt() and 0xff) in XMR_NETWORK_BYTES
    }

    private fun isCardanoByron(token: String, raw: ByteArray): Boolean =
        (token.startsWith("Ae2") || token.startsWith("Ddz")) &&
            raw.size >= 3 && raw[0] == 0x82.toByte() && raw[1] == 0xd8.toByte() && raw[2] == 0x18.toByte()

    private fun base58Kind(token: String): String? {
        val raw = b58decode(token)
        b58check(raw)?.let { payload -> classifyBase58Check(token, payload)?.let { return it } }
        if (token[0] in XRP_LEADS) {
            b58check(b58decode(token, xrp = true))?.let { payload -> classifyXrp(payload)?.let { return it } }
        }
        if (isSs58(raw)) return "crypto_dot"
        if (isSolanaPubkey(token, raw)) return "crypto_sol"
        if (raw.size == 64 && isEd25519Keypair(raw)) return "crypto_private_key"
        if (isMonero(token)) return "crypto_xmr"
        if (isCardanoByron(token, raw)) return "crypto_ada"
        return null
    }

    private fun scanBase58(text: String, sink: Sink) {
        for (m in B58_TOKEN.findAll(text)) {
            val start = m.range.first
            val end = m.range.last + 1
            val kind = failClosed("crypto_address") { base58Kind(m.value) }
            // Only the checksum-free Solana guess is vetoed inside base64 blobs.
            if (kind == "crypto_sol" && insideBase64(text, start, end)) continue
            if (kind != null) sink.hit(start, end, kind)
        }
    }

    // ── bech32 / bech32m (BIP-173 / BIP-350) ─────────────────────────────

    private const val BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private const val BECH32M_CONST = 0x2BC830A3
    private val BECH32_GEN = intArrayOf(0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    private val BECH32_TOKEN = Regex(
        "(?<![A-Za-z0-9_\\-])" +
            "(?:[a-z][a-z0-9_\\-]{0,40}1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,1500}" +
            "|[A-Z][A-Z0-9_\\-]{0,40}1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{6,1500})" +
            "(?![A-Za-z0-9])",
    )

    private fun bech32Polymod(values: IntArray): Int {
        var chk = 1
        for (v in values) {
            val top = chk ushr 25
            chk = ((chk and 0x1FFFFFF) shl 5) xor v
            for (i in 0 until 5) if ((top shr i) and 1 == 1) chk = chk xor BECH32_GEN[i]
        }
        return chk
    }

    /** (hrp, data without checksum) when bech32 or bech32m validates. */
    private fun bech32Decode(token: String): Pair<String, IntArray>? {
        val s = token.lowercase()
        val separator = s.lastIndexOf('1')
        val hrp = s.substring(0, separator)
        val data = IntArray(s.length - separator - 1) { BECH32_CHARSET.indexOf(s[separator + 1 + it]) }
        val values = IntArray(hrp.length * 2 + 1 + data.size)
        hrp.forEachIndexed { i, c ->
            values[i] = c.code shr 5
            values[hrp.length + 1 + i] = c.code and 31
        }
        System.arraycopy(data, 0, values, hrp.length * 2 + 1, data.size)
        val check = bech32Polymod(values)
        if (check != 1 && check != BECH32M_CONST) return null
        return hrp to data.copyOfRange(0, data.size - 6)
    }

    private val SECRET_HRPS = setOf("nsec", "xprv", "suiprivkey", "age-secret-key-")
    private val PUBLIC_HRPS = setOf("npub", "nprofile", "age")
    private val IGNORED_HRPS = setOf("note", "nevent", "naddr", "nrelay") // public Nostr content IDs
    private val LIGHTNING_HRP = Regex("ln(?:bc|tb|tbs|bcrt|sb)(?:\\d+[munp]?)?")
    private val COSMOS_HRPS = setOf(
        "cosmos", "osmo", "juno", "terra", "kava", "secret", "inj", "celestia",
        "akash", "axelar", "evmos", "stars", "sei", "dydx", "noble", "stride",
        "kujira", "neutron", "persistence", "regen", "umee", "cro", "band",
        "iaa", "fetch", "xpla", "migaloo", "archway", "cheqd", "desmos", "dym",
        "saga", "mantra", "somm", "gravity", "bitsong", "comdex", "agoric",
        "canto", "nibi", "kyve", "thor", "maya", "bnb", "tbnb", "zeta", "elys",
    )

    private fun bech32Kind(hrp: String, data: IntArray): String? {
        if (hrp in setOf("bc", "tb", "bcrt")) return "crypto_btc"
        if (hrp in setOf("ltc", "tltc", "rltc")) return "crypto_ltc"
        if (hrp in setOf("addr", "addr_test", "stake", "stake_test")) return "crypto_ada"
        if (hrp in SECRET_HRPS || hrp.endsWith("_sk") || hrp.endsWith("_xsk")) return "crypto_private_key"
        if (hrp in PUBLIC_HRPS || hrp.endsWith("_vk") || hrp.endsWith("_xvk") || hrp.endsWith("pub")) {
            return "crypto_public_key"
        }
        if (hrp == "lnurl" || LIGHTNING_HRP.matches(hrp)) return "crypto_lightning"
        if (hrp in IGNORED_HRPS) return null
        val base = hrp.removeSuffix("valoper").removeSuffix("valcons")
        if (base in COSMOS_HRPS) return "crypto_cosmos"
        // Unknown prefix, valid checksum, >= 160 bits of data: some other chain's address.
        return if (data.size >= 32) "crypto_address" else null
    }

    private fun scanBech32(text: String, sink: Sink) {
        for (m in BECH32_TOKEN.findAll(text)) {
            val kind = failClosed("crypto_address") { bech32Decode(m.value)?.let { (hrp, data) -> bech32Kind(hrp, data) } }
            if (kind != null) sink.hit(m.range.first, m.range.last + 1, kind)
        }
    }

    // ── CashAddr (Bitcoin Cash) ──────────────────────────────────────────

    private val CASHADDR_TOKEN = Regex(
        "(?i)(?<![A-Za-z0-9])(?:(bitcoincash|bchtest|bchreg):)?" +
            "([qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41}(?:[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{19})?)" +
            "(?![A-Za-z0-9])",
    )
    private val CASHADDR_GEN = listOf(
        0x01L to 0x98F2BC8E61L, 0x02L to 0x79B76D99E2L, 0x04L to 0xF33E5FB3C4L,
        0x08L to 0xAE2EABE2A8L, 0x10L to 0x1E4F43E470L,
    )

    private fun cashAddrPolymod(values: IntArray): Long {
        var c = 1L
        for (d in values) {
            val top = c ushr 35
            c = ((c and 0x07FFFFFFFFL) shl 5) xor d.toLong()
            for ((bit, generator) in CASHADDR_GEN) if (top and bit != 0L) c = c xor generator
        }
        return c xor 1L
    }

    private fun isCashAddr(prefix: String?, payload: String): Boolean {
        if (payload != payload.lowercase() && payload != payload.uppercase()) return false // mixed case
        val data = payload.lowercase().map { BECH32_CHARSET.indexOf(it) }
        val prefixes = if (prefix != null) listOf(prefix.lowercase()) else listOf("bitcoincash", "bchtest")
        return prefixes.any { p ->
            val values = p.map { it.code and 0x1F } + 0 + data
            cashAddrPolymod(values.toIntArray()) == 0L
        }
    }

    private fun scanCashAddr(text: String, sink: Sink) {
        for (m in CASHADDR_TOKEN.findAll(text)) {
            val valid = try {
                isCashAddr(m.groups[1]?.value, m.groups[2]!!.value)
            } catch (_: Exception) {
                true
            }
            if (valid) sink.hit(m.range.first, m.range.last + 1, "crypto_bch")
        }
    }

    // ── Base32: Stellar StrKey and Algorand ──────────────────────────────

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val B32_TOKEN = Regex("(?<![A-Za-z0-9])[A-Z2-7]{56,69}(?![A-Za-z0-9])")

    /** RFC 4648 base32 without padding; trailing bits that do not fill a byte are dropped. */
    private fun b32decode(token: String): ByteArray? {
        val out = ByteArrayOutputStream()
        var buffer = 0L
        var bits = 0
        for (c in token) {
            val value = BASE32_ALPHABET.indexOf(c)
            if (value < 0) return null
            buffer = (buffer shl 5) or value.toLong()
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.write(((buffer shr bits) and 0xff).toInt())
            }
        }
        return out.toByteArray()
    }

    private fun isAlgorand(token: String): Boolean {
        val raw = b32decode(token) ?: return false
        if (raw.size != 36) return false
        val digest = try {
            MessageDigest.getInstance("SHA-512/256").digest(raw.copyOfRange(0, 32))
        } catch (_: java.security.NoSuchAlgorithmException) {
            return true // cannot verify: let the shape decide (over-redact, never leak)
        }
        return digest.copyOfRange(digest.size - 4, digest.size).contentEquals(raw.copyOfRange(32, 36))
    }

    /** CRC-16/XMODEM, which Python spells binascii.crc_hqx(data, 0). */
    private fun crc16Xmodem(data: ByteArray): Int {
        var crc = 0
        for (byte in data) {
            crc = crc xor ((byte.toInt() and 0xff) shl 8)
            repeat(8) { crc = if (crc and 0x8000 != 0) ((crc shl 1) xor 0x1021) and 0xffff else (crc shl 1) and 0xffff }
        }
        return crc
    }

    private fun base32Kind(token: String): String? {
        if (token.length == 58) return if (isAlgorand(token)) "crypto_algo" else null
        if (token.length != 56 && token.length != 69) return null
        val raw = b32decode(token) ?: return null
        val body = raw.copyOfRange(0, raw.size - 2)
        val crc = crc16Xmodem(body) // stored little-endian
        if ((raw[raw.size - 2].toInt() and 0xff) != (crc and 0xff) ||
            (raw[raw.size - 1].toInt() and 0xff) != (crc ushr 8)
        ) {
            return null
        }
        val versionByte = body[0].toInt() and 0xff
        if (versionByte and 7 != 0) return null
        return when (versionByte shr 3) {
            18 -> "crypto_private_key" // secret seed "S..."
            6, 12, 2 -> "crypto_xlm" // account "G...", muxed "M...", contract "C..."
            else -> null // pre-auth tx / hash / signed-payload signers: not personal data
        }
    }

    private fun scanBase32(text: String, sink: Sink) {
        for (m in B32_TOKEN.findAll(text)) {
            val kind = failClosed("crypto_address") { base32Kind(m.value) }
            if (kind != null) sink.hit(m.range.first, m.range.last + 1, kind)
        }
    }

    // ── EVM addresses ────────────────────────────────────────────────────

    private val EVM_ADDRESS = Regex("(?U)\\b0x[0-9a-fA-F]{40}\\b")
    private val EVM_PUBLIC_ADDRESSES = setOf(
        "0x0000000000000000000000000000000000000000", // zero address
        "0x000000000000000000000000000000000000dEaD", // burn address
        "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE", // "native ETH" sentinel
        "0xcA11bde05977b3631167028862bE2a173976CA11", // Multicall3
        "0x000000000022D473030F116dDEE9F6B43aC78BA3", // Permit2
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH9
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
        "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT
        "0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI
    ).mapTo(HashSet()) { it.lowercase() }

    private fun scanEvm(text: String, sink: Sink) {
        for (m in EVM_ADDRESS.findAll(text)) {
            if (m.value.lowercase() !in EVM_PUBLIC_ADDRESSES) sink.hit(m.range.first, m.range.last + 1, "crypto_eth")
        }
    }

    // ── Hex keys: secp256k1 / BLS public keys, private keys in context ───

    private val SECP256K1_P: BigInteger =
        BigInteger.ONE.shiftLeft(256) - BigInteger.ONE.shiftLeft(32) - BigInteger.valueOf(977)
    private val HEX_TOKEN = Regex("(?<![0-9A-Za-z])(0x)?([0-9a-fA-F]{64,130})(?![0-9A-Za-z])")
    private const val CONTEXT_WINDOW = 200
    private const val CHAIN_GAP = 100
    private val PRIVATE_KEY_CONTEXT: Pattern = Pattern.compile(
        "(?iU)priv(?:ate)?[\\s_\\-]*keys?|privkey|secret[\\s_\\-]*(?:keys?|exponent)|\\bsecret\\b" +
            "|sign(?:ing|er)[\\s_\\-]*keys?|(?:wallet|deployer)[\\s_\\-]*keys?|from_?key" +
            "|\\bpk\\b|\\bsk\\b|\\bseed\\b|mnemonic|keypair" +
            "|\\baccounts\\s*:\\s*\\[|\\b(?:accounts|wallet)\\.add\\s*\\(|\\bWallet\\s*\\(",
    )
    private val MOVE_CONTEXT: Pattern = Pattern.compile(
        "(?iU)\\b(?:aptos|sui|movement)\\b|\\bmove\\s+(?:address|module|package|object)\\b" +
            "|\\bobject\\s*id\\b|\\b0x[0-9a-f]{1,2}::",
    )

    /** Python's pattern.search(text, start, end): look-arounds may see outside the window. */
    private fun searchWindow(pattern: Pattern, text: String, start: Int, end: Int): Boolean =
        pattern.matcher(text).region(start, end).useTransparentBounds(true).useAnchoringBounds(false).find()

    private fun hexToBytes(digits: String): ByteArray {
        require(digits.length % 2 == 0)
        return ByteArray(digits.length / 2) { digits.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }

    /** Does this 33/65/64-byte hex value encode a point on secp256k1? */
    private fun onSecp256k1(digits: String): Boolean {
        var key = hexToBytes(digits)
        val p = SECP256K1_P
        if (key.size == 64) key = byteArrayOf(0x04) + key
        if (key.size == 65 && key[0] == 0x04.toByte()) {
            val x = BigInteger(1, key.copyOfRange(1, 33))
            val y = BigInteger(1, key.copyOfRange(33, 65))
            return x < p && y < p && (y * y - x * x * x - BigInteger.valueOf(7)).mod(p).signum() == 0
        }
        if (key.size == 33 && (key[0] == 0x02.toByte() || key[0] == 0x03.toByte())) {
            val x = BigInteger(1, key.copyOfRange(1, 33))
            if (x >= p) return false
            // A matching y exists iff x^3 + 7 is a square mod p (Euler's criterion).
            val rhs = (x.modPow(BigInteger.valueOf(3), p) + BigInteger.valueOf(7)).mod(p)
            return rhs.modPow((p - BigInteger.ONE).shiftRight(1), p) == BigInteger.ONE
        }
        return false
    }

    private fun hexKind(text: String, m: MatchResult, chained: Boolean): String? {
        val prefixed = m.groups[1] != null
        val digits = m.groups[2]!!.value
        val n = digits.length
        if ((n == 66 || n == 128 || n == 130) && onSecp256k1(digits)) return "crypto_public_key"
        // Ethereum validator (BLS12-381) public keys: compression flag set, infinity flag clear.
        if (n == 96 && prefixed && digits[0] in "89abAB") return "crypto_public_key"
        val windowStart = maxOf(0, m.range.first - CONTEXT_WINDOW)
        val windowEnd = m.range.first
        if ((n == 64 || n == 128) && (chained || searchWindow(PRIVATE_KEY_CONTEXT, text, windowStart, windowEnd))) {
            return "crypto_private_key"
        }
        if (n == 64 && prefixed && searchWindow(MOVE_CONTEXT, text, windowStart, windowEnd)) return "crypto_address"
        return null
    }

    private fun scanHex(text: String, sink: Sink) {
        var lastKeyEnd = -CHAIN_GAP - 1
        for (m in HEX_TOKEN.findAll(text)) {
            val chained = m.range.first - lastKeyEnd <= CHAIN_GAP
            val kind = try {
                hexKind(text, m, chained)
            } catch (_: Exception) {
                if (m.groups[2]!!.value.length in setOf(64, 128)) "crypto_private_key" else null
            }
            if (kind != null) {
                if (kind == "crypto_private_key") lastKeyEnd = m.range.last + 1
                sink.hit(m.range.first, m.range.last + 1, kind)
            }
        }
    }

    // ── Solana / NEAR keypair files ──────────────────────────────────────

    private val BYTE_ARRAY_64 = Regex("\\[\\s*(?:\\d{1,3}\\s*,\\s*){63}\\d{1,3}\\s*,?\\s*\\]")
    private val INTEGER = Regex("\\d+")

    private fun scanKeypairArrays(text: String, sink: Sink) {
        if ('[' !in text) return
        for (m in BYTE_ARRAY_64.findAll(text)) {
            val values = INTEGER.findAll(m.value).map { it.value.toInt() }.toList()
            if (values.any { it > 255 }) continue
            val isKey = try {
                isEd25519Keypair(ByteArray(values.size) { values[it].toByte() })
            } catch (_: Exception) {
                true
            }
            if (isKey) sink.hit(m.range.first, m.range.last + 1, "crypto_private_key")
        }
    }

    // ── Seed phrases: BIP-39 (10 languages), Monero, SLIP-39, old Electrum ──

    /** See wallets.py for how these thresholds were measured. */
    const val MIN_MNEMONIC_WORDS = 12
    const val MIN_DISTINCT_WORDS = 10

    private val WORDLIST_FILES = listOf(
        "bip39_english" to 2048,
        "bip39_chinese_simplified" to 2048,
        "bip39_chinese_traditional" to 2048,
        "bip39_czech" to 2048,
        "bip39_french" to 2048,
        "bip39_italian" to 2048,
        "bip39_japanese" to 2048,
        "bip39_korean" to 2048,
        "bip39_portuguese" to 2048,
        "bip39_spanish" to 2048,
        "electrum_old" to 1626,
        "monero_english" to 1626,
        "slip39" to 1024,
    )

    /**
     * NFKD word -> bitmask of the lists containing it. The files are the
     * Python package's own (build.gradle.kts copies them into the jar), so
     * there is one copy to keep correct, SHA-256-pinned by the Python tests.
     */
    internal val vocabulary: Map<String, Int> by lazy {
        val owners = HashMap<String, Int>(40_000)
        WORDLIST_FILES.forEachIndexed { bit, (stem, size) ->
            val words = WalletDetector::class.java.getResourceAsStream("wordlists/$stem.txt")
                ?.use { it.readBytes().toString(Charsets.UTF_8) }
                ?.split(WHITESPACE)?.filter { it.isNotEmpty() }
                ?: error("wordlists/$stem.txt is missing from the extension jar")
            check(words.size == size) { "wordlists/$stem.txt is damaged: ${words.size} words, not $size" }
            for (word in words) {
                val key = Normalizer.normalize(word, Normalizer.Form.NFKD)
                owners[key] = (owners[key] ?: 0) or (1 shl bit)
            }
        }
        owners
    }

    private val WHITESPACE = Regex("\\s+")
    // A word: letters, plus combining marks so decomposed input stays whole.
    private val WORD = Regex("[\\p{L}\\u0300-\\u036f\\u3099\\u309a]+")
    // What may separate two words of one phrase: whitespace and punctuation,
    // optionally carrying a one- or two-digit position number ("1. abandon").
    private val MNEMONIC_GAP = Regex("(?U)[^\\w]{1,16}|[^\\w]{1,16}\\d{1,2}[^\\w]{1,16}")
    // Between two Chinese ideographs only whitespace (and a list number) may.
    private val IDEOGRAPH_GAP = Regex("(?U)\\s{1,8}(?:\\d{1,2}[.)\\u3001:\\uff1a]\\s{0,4})?")

    private class Word(val start: Int, val end: Int, val key: String, val ideograph: Boolean)

    private fun isIdeograph(c: Char): Boolean =
        c in '㐀'..'䶿' || c in '一'..'鿿' || c in '豈'..'﫿'

    private fun lookupKey(token: String): String {
        val lower = token.lowercase()
        return if (lower.all { it.code < 128 }) lower else Normalizer.normalize(lower, Normalizer.Form.NFKD)
    }

    private fun joins(text: String, previous: Word, next: Word): Boolean {
        val length = next.start - previous.end
        val gap = text.subSequence(previous.end, next.start)
        return if (previous.ideograph && next.ideograph) {
            length <= 15 && IDEOGRAPH_GAP.matches(gap)
        } else {
            length <= 34 && MNEMONIC_GAP.matches(gap)
        }
    }

    /** How many leading words are a label such as `seed:` (itself a BIP-39 word). */
    private fun labelEnd(text: String, run: List<Word>): Int {
        for (i in 0 until minOf(3, run.size - 1)) {
            val gap = text.substring(run[i].end, run[i + 1].start)
            if (':' in gap && gap.none { it.isDigit() }) return i + 1
        }
        return 0
    }

    /** Report the windows of a run that look like a random seed phrase, merged. */
    private fun seedLike(run: List<Word>, sink: Sink) {
        if (run.size < MIN_MNEMONIC_WORDS) return
        var spanStart = -1
        var spanEnd = -1
        for (i in 0..run.size - MIN_MNEMONIC_WORDS) {
            val j = i + MIN_MNEMONIC_WORDS
            if (run.subList(i, j).mapTo(HashSet()) { it.key }.size < MIN_DISTINCT_WORDS) continue
            if (i > spanEnd) {
                if (spanStart >= 0) sink.hit(run[spanStart].start, run[spanEnd].end, "crypto_mnemonic")
                spanStart = i
            }
            spanEnd = j - 1
        }
        if (spanStart >= 0) sink.hit(run[spanStart].start, run[spanEnd].end, "crypto_mnemonic")
    }

    private fun judge(text: String, run: List<Word>, sink: Sink) {
        if (run.size < MIN_MNEMONIC_WORDS) return
        seedLike(run.subList(labelEnd(text, run), run.size), sink)
    }

    /**
     * Runs of words that all share at least one wordlist. When the next word
     * shares no list with the run, the run is judged and the new run keeps
     * the longest tail that does share a list with that word (a phrase may
     * open with words that sit on two lists). Same algorithm as wallets.py.
     */
    private fun scanMnemonics(text: String, sink: Sink) {
        val lists = try {
            vocabulary
        } catch (_: Exception) {
            return // a broken jar; the wordlist test fails the build long before this
        }
        val run = ArrayList<Word>()
        val masks = ArrayList<Int>()
        var shared = 0
        for (m in WORD.findAll(text)) {
            val key = lookupKey(m.value)
            val found = lists[key]
            if (found == null) {
                judge(text, run, sink)
                run.clear()
                masks.clear()
                shared = 0
                continue
            }
            val owners: Int = found
            val word = Word(m.range.first, m.range.last + 1, key, m.value.length == 1 && isIdeograph(m.value[0]))
            val joined = run.isNotEmpty() && joins(text, run.last(), word)
            if (joined && (shared and owners) != 0) {
                run += word
                masks += owners
                shared = shared and owners
                continue
            }
            judge(text, run, sink)
            var keep = run.size
            var carry = owners
            while (joined && keep > 0 && (carry and masks[keep - 1]) != 0) {
                carry = carry and masks[keep - 1]
                keep--
            }
            val tailWords = run.subList(keep, run.size).toList()
            val tailMasks = masks.subList(keep, masks.size).toList()
            run.clear()
            run.addAll(tailWords)
            run += word
            masks.clear()
            masks.addAll(tailMasks)
            masks += owners
            shared = carry
        }
        judge(text, run, sink)
    }

    // ── ENS names ────────────────────────────────────────────────────────

    private val ENS_HINT = Regex("(?iU)\\.eth(?![\\w\\-])")
    // wallets.py's `(?:label\.)*label\.eth` repeats a group (see the class
    // comment); the dotted run is matched as one character class instead and
    // its labels checked in code, which accepts exactly the same names.
    private val ENS = Regex("(?iU)(?<![\\w.\\-])[a-z0-9\\-.]+\\.eth(?![\\w\\-]|\\.[\\w(]|\\()")
    private val ENS_CODE_NAMES = listOf("web3.eth", "w3.eth", "self.eth", "this.eth", "ethers.eth")

    private fun scanEns(text: String, sink: Sink) {
        if (!ENS_HINT.containsMatchIn(text)) return
        for (m in ENS.findAll(text)) {
            val name = m.value.lowercase()
            val labels = name.removeSuffix(".eth").split('.')
            if (labels.any { it.isEmpty() } || labels.last().length < 3) continue
            if (name in ENS_CODE_NAMES || ENS_CODE_NAMES.any { name.endsWith(".$it") }) continue
            sink.hit(m.range.first, m.range.last + 1, "crypto_ens")
        }
    }
}
