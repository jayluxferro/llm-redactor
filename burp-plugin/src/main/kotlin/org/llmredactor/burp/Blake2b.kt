package org.llmredactor.burp

/**
 * Unkeyed BLAKE2b (RFC 7693), needed only for Polkadot/Substrate SS58
 * address checksums. The JDK ships no BLAKE2, and pulling in Bouncy Castle
 * for one hash would put a second crypto provider on Burp's class path.
 * Checked against the RFC's "abc" vector and against Python's hashlib in
 * Blake2bTest.
 */
internal object Blake2b {
    private val IV = longArrayOf(
        0x6a09e667f3bcc908uL.toLong(), 0xbb67ae8584caa73buL.toLong(),
        0x3c6ef372fe94f82buL.toLong(), 0xa54ff53a5f1d36f1uL.toLong(),
        0x510e527fade682d1uL.toLong(), 0x9b05688c2b3e6c1fuL.toLong(),
        0x1f83d9abfb41bd6buL.toLong(), 0x5be0cd19137e2179uL.toLong(),
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    )

    fun digest(input: ByteArray, outLen: Int = 64): ByteArray {
        require(outLen in 1..64)
        val h = IV.copyOf()
        h[0] = h[0] xor (0x01010000L or outLen.toLong())
        val blocks = maxOf(1, (input.size + 127) / 128)
        val block = ByteArray(128)
        val m = LongArray(16)
        val v = LongArray(16)
        var counter = 0L // inputs here are tiny; the high 64 bits of the counter stay 0
        for (b in 0 until blocks) {
            val offset = b * 128
            val length = minOf(128, input.size - offset)
            block.fill(0)
            if (length > 0) System.arraycopy(input, offset, block, 0, length)
            counter += length
            for (i in 0 until 16) m[i] = littleEndianLong(block, i * 8)
            for (i in 0 until 8) {
                v[i] = h[i]
                v[i + 8] = IV[i]
            }
            v[12] = v[12] xor counter
            if (b == blocks - 1) v[14] = v[14].inv()
            for (round in 0 until 12) {
                val s = SIGMA[round % 10]
                mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
                mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
                mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
                mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
                mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
                mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
                mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
                mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
            }
            for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
        }
        val out = ByteArray(outLen)
        for (i in 0 until outLen) out[i] = (h[i / 8] ushr (8 * (i % 8))).toByte()
        return out
    }

    private fun mix(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] = v[a] + v[b] + x
        v[d] = (v[d] xor v[a]).rotateRight(32)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(24)
        v[a] = v[a] + v[b] + y
        v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(63)
    }

    private fun littleEndianLong(bytes: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 7 downTo 0) value = (value shl 8) or (bytes[offset + i].toLong() and 0xff)
        return value
    }
}
