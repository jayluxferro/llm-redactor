"""Blockchain addresses, public keys, private keys and seed phrases.

Why this is its own module
--------------------------
Every detector in ``regex.py`` is one pattern, optionally followed by a
checksum.  Wallet formats do not fit that shape: the same base58 token could
be a Bitcoin address, a Tron address, an XRP seed, a Polkadot account or a
Solana public key, and the only reliable way to tell is to *decode* it.  So
each scanner below finds candidate tokens with a cheap regex, decodes each
once, and lets the decoded bytes pick the kind.

Precision comes from the formats' own integrity checks rather than context:

========================  ======================================  ==========
family                    check                                   random hit
========================  ======================================  ==========
Base58Check (BTC, LTC,    double SHA-256, 4 bytes                 2^-32
DOGE, TRX, Tezos, WIF,
xpub/xprv, BIP38, XRP)
bech32 / bech32m          BCH code over HRP + data                ~2^-30
CashAddr (Bitcoin Cash)   40-bit BCH code                         2^-40
SS58 (Polkadot, Kusama)   BLAKE2b-512, 2 bytes                    2^-16
Stellar StrKey            CRC-16/XMODEM + version byte            2^-16
Algorand                  SHA-512/256, 4 bytes                    2^-32
secp256k1 public key      the point must lie on the curve         ~0 when
                                                                  uncompressed
Solana/NEAR keypair       2nd half = public key of the 1st half   ~0
========================  ======================================  ==========

Where the difficulty lies: four families have no usable checksum and lean on
shape instead, so they are the places this module can still be fooled.

* Solana public keys are a bare 32-byte value.  We require a 32-44 char
  token that decodes to exactly 32 bytes and is mixed-case.  Random IDs of
  that exact shape get redacted too, which is usually harmless because such
  IDs are typically secrets themselves.
* Monero is checked structurally (block-base58 + network byte), not with its
  Keccak checksum.
* 64-hex private keys are indistinguishable from SHA-256 digests and tx
  hashes, so they need a "private key"-style keyword within
  ``_CONTEXT_WINDOW`` chars, or must sit in a list right after another key.
  A bare ``0x`` + 64-hex value with no such context is deliberately NOT
  redacted (it is far more often a tx hash than a key).
* Seed phrases are runs of BIP-39 English words; see ``MIN_MNEMONIC_WORDS``.

Known trade-off: strict checksums mean a mistyped address is *not* redacted.
Addresses are pasted far more often than typed, and without the checksum the
legacy-address shape alone matches ~2% of MD5 digests, so precision wins.
But a one-character typo is only a checksum search away from the real value.

Contract shared with ``regex.DETECT_VALIDATORS``: a bug in a classifier must
widen what gets redacted, never narrow it (see ``_fail_closed``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import re
from collections.abc import Callable, Iterable, Iterator
from functools import lru_cache
from importlib import resources

from .types import Span

_LOG = logging.getLogger(__name__)

#: Every kind this module can emit.  A test keeps these in ``types.CATEGORY_MAP``:
#: an unmapped kind is silently dropped by ``filter_by_categories``.
ADDRESS_KINDS: frozenset[str] = frozenset(
    {
        "crypto_btc",
        "crypto_eth",  # every EVM chain shares the 0x + 40-hex format
        "crypto_ltc",
        "crypto_doge",
        "crypto_bch",
        "crypto_trx",
        "crypto_xrp",
        "crypto_sol",
        "crypto_xmr",
        "crypto_ada",
        "crypto_dot",  # any SS58 account: Polkadot, Kusama, Substrate chains
        "crypto_cosmos",  # any Cosmos-SDK bech32 account / validator address
        "crypto_xlm",
        "crypto_algo",
        "crypto_xtz",
        "crypto_lightning",  # BOLT11 invoices and LNURLs
        "crypto_address",  # checksum-valid address of a chain not listed above
    }
)
PUBLIC_KEY_KINDS: frozenset[str] = frozenset({"crypto_xpub", "crypto_public_key"})
SECRET_KINDS: frozenset[str] = frozenset({"crypto_private_key", "crypto_xprv", "crypto_mnemonic"})
WALLET_KINDS: frozenset[str] = ADDRESS_KINDS | PUBLIC_KEY_KINDS | SECRET_KINDS

# A span is (start, end, kind); Span objects are built once, at the end.
_Hit = tuple[int, int, str]


def _fail_closed(classify: Callable[[str], str | None], token: str, fallback: str) -> str | None:
    """Run a classifier; if it raises, report ``fallback`` (i.e. redact anyway).

    Candidates are already restricted to the right alphabet by their regex, so
    an exception here means a bug, and a bug must not unredact a key.  The
    token itself is never logged.
    """
    try:
        return classify(token)
    except Exception as exc:  # pragma: no cover - defensive
        _LOG.warning(
            "wallet classifier %s failed (%s); redacting the candidate",
            classify.__name__,
            type(exc).__name__,
        )
        return fallback


# ── Base58 ────────────────────────────────────────────────────────────────

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Ripple permutes the same 58 symbols so that its account IDs start with "r".
_XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}
_XRP_INDEX = {c: i for i, c in enumerate(_XRP_ALPHABET)}

# A whole base58 token.  25 chars is the shortest Base58Check address; 120
# covers Bitcoin extended keys (111) and Cardano Byron addresses.  The
# look-arounds anchor on alphanumerics rather than \b so a token after "_" or
# ":" still counts, and a longer run (inside a base64 blob, say) never
# matches part-way through.
_B58_TOKEN = re.compile(r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{25,120}(?![A-Za-z0-9])")


def _b58decode(token: str, alphabet: str = _B58_ALPHABET) -> bytes:
    """Plain base58 to bytes; each leading zero-symbol is one leading 0x00."""
    index = _XRP_INDEX if alphabet is _XRP_ALPHABET else _B58_INDEX
    n = 0
    for ch in token:
        n = n * 58 + index[ch]
    pad = len(token) - len(token.lstrip(alphabet[0]))
    return b"\x00" * pad + n.to_bytes((n.bit_length() + 7) // 8, "big")


def _b58check(raw: bytes) -> bytes | None:
    """Verify and strip a Base58Check checksum (first 4 bytes of SHA-256^2)."""
    if len(raw) < 5:
        return None
    payload, check = raw[:-4], raw[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return payload if digest[:4] == check else None


# One-byte version prefixes of 20-byte-hash addresses (payload = 21 bytes).
_B58_ADDRESS_VERSIONS: dict[int, str] = {
    0x00: "crypto_btc",  # P2PKH "1..." (also Bitcoin Cash legacy, BSV)
    0x05: "crypto_btc",  # P2SH "3..." (also legacy Litecoin P2SH)
    0x6F: "crypto_btc",  # testnet P2PKH "m..." / "n..."
    0xC4: "crypto_btc",  # testnet P2SH "2..."
    0x30: "crypto_ltc",  # "L..."
    0x32: "crypto_ltc",  # "M..."
    0x1E: "crypto_doge",  # "D..."
    0x16: "crypto_doge",  # "9..." / "A..."
    0x41: "crypto_trx",  # Tron "T..."
}
# Tezos prefixes are 3-5 bytes long; it is simpler (and equivalent) to match
# the text they always encode to.
_TEZOS_SECRET = ("edsk", "spsk", "p2sk", "BLsk", "edesk", "spesk", "p2esk", "BLesk")
_TEZOS_PUBLIC = ("edpk", "sppk", "p2pk", "BLpk")
_TEZOS_ADDRESS = ("tz1", "tz2", "tz3", "tz4", "KT1", "sr1")


def _classify_base58check(token: str, payload: bytes) -> str | None:
    """Kind of a checksum-valid Base58Check token (Bitcoin alphabet)."""
    n = len(payload)
    if token.startswith(_TEZOS_SECRET):
        return "crypto_private_key"
    if token.startswith(_TEZOS_PUBLIC):
        return "crypto_public_key"
    if token.startswith(_TEZOS_ADDRESS) and n == 23:
        return "crypto_xtz"
    if n == 21:
        # An unknown version byte is still almost certainly some altcoin's
        # address: a random token passes the checksum once in 2^32.
        return _B58_ADDRESS_VERSIONS.get(payload[0], "crypto_address")
    if n in (22, 23):
        return "crypto_address"  # 2-3 byte version + 20-byte hash (Zcash t-addr, ...)
    if n == 33 or (n == 34 and payload[-1] == 0x01):
        return "crypto_private_key"  # WIF: version + 32-byte key (+ compressed flag)
    if n == 78:
        # BIP32 serialisation: the 33-byte key field starts at offset 45; a
        # private key is stored as 0x00 + 32 bytes, a public key as 02/03 + x.
        # Reading that byte is prefix-agnostic (xpub/ypub/zpub/tpub/Ltub/...).
        return "crypto_xprv" if payload[45] == 0x00 else "crypto_xpub"
    if n == 39 and token.startswith("6P"):
        return "crypto_private_key"  # BIP38 passphrase-encrypted key
    return None


def _classify_xrp(payload: bytes) -> str | None:
    """Kind of a checksum-valid Base58Check token in Ripple's alphabet."""
    n = len(payload)
    if n == 21 and payload[0] == 0x00:
        return "crypto_xrp"  # classic address "r..."
    if n == 31 and payload[:2] in (b"\x05\x44", b"\x04\x93"):
        return "crypto_xrp"  # X-address (account + destination tag)
    if (n == 17 and payload[0] == 0x21) or (n == 19 and payload[:3] == b"\x01\xe1\x4b"):
        return "crypto_private_key"  # family seed "s..." (secp256k1) / "sEd..." (ed25519)
    if n == 33:
        return "crypto_private_key"  # node / account private key: version + 32 bytes
    if n == 34:
        return "crypto_public_key"  # node / account public key: version + 33 bytes
    return None


# First characters an XRP-alphabet token can have: "r" accounts, "s" seeds,
# "X"/"T" X-addresses, "n"/"p"/"a" node and account keys.  Skipping the
# second decode for anything else keeps the common case to one decode.
_XRP_LEADS = frozenset("rsXTnpa")


def _is_ss58(raw: bytes) -> bool:
    """Polkadot-style account: prefix + 32/33-byte key + 2-byte BLAKE2b checksum."""
    if not raw or raw[0] >= 128:
        return False
    prefix_len = 1 if raw[0] < 64 else 2  # SS58 encodes prefixes >= 64 in 2 bytes
    if len(raw) - prefix_len not in (34, 35):
        return False
    body, check = raw[:-2], raw[-2:]
    return hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2] == check


# Public, well-known program and mint IDs.  They are infrastructure, not
# personal data, and they appear constantly in Solana code; redacting them
# only costs the model the ability to recognise them.
_SOLANA_PUBLIC_IDS = frozenset(
    {
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  # SPL Token-2022
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",  # Associated Token Account
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",  # Memo v2
        "So11111111111111111111111111111111111111112",  # wrapped SOL mint
        "ComputeBudget111111111111111111111111111111",  # Compute Budget
        "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",  # Metaplex Token Metadata
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # USDC mint
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",  # USDT mint
    }
)


_VOWELS = frozenset("aeiouAEU")  # base58 has no "I" or "O"


def _looks_like_identifier(token: str) -> bool:
    """camelCase names such as ``hipDeviceAttributeMaxTexture2DLayeredHeight``.

    They are 43-44 chars of base58-safe letters that decode to 32 bytes, i.e.
    exactly a Solana key's shape.  English is ~35-45% vowels with few digits;
    uniform base58 is ~16% vowels with ~7 digits in 44 chars.  Requiring both
    signals misclassifies about 1 random key in 5,000 (pinned by a test).
    """
    letters = [c for c in token if c.isalpha()]
    vowels = sum(c in _VOWELS for c in letters)
    digits = len(token) - len(letters)
    return digits <= 2 and vowels >= 0.30 * len(letters)


def _inside_base64(text: str, start: int, end: int) -> bool:
    """Is this token a fragment of a base64 blob (cert, data URI, k8s secret)?

    Inside a blob, base58-safe runs are cut by ``+`` and ``/`` and the blob
    may end in ``=`` padding; a pasted address is delimited by spaces,
    quotes or punctuation.  Accepted miss: an address *between* two slashes
    of a URL path (``/account/<addr>/tokens``).
    """
    before = text[start - 1] if start else ""
    after = text[end] if end < len(text) else ""
    return before == "+" or after in ("+", "=") or (before == "/" and after == "/")


def _is_solana_pubkey(token: str, raw: bytes) -> bool:
    # No checksum exists.  Mixed case is the cheap sanity check: a random
    # 43-44 char base58 string is virtually always mixed case, while hex
    # digests, single-case IDs and bech32 strings (some of which also decode
    # to 32 bytes) are not.  Token length bounds the decoded value, so the
    # 32-byte test also rejects every Base58Check address (21-25 bytes).
    return (
        len(raw) == 32
        and 32 <= len(token) <= 44
        and token not in _SOLANA_PUBLIC_IDS
        and any(c.isupper() for c in token)
        and any(c.islower() for c in token)
        and not _looks_like_identifier(token)
    )


def _is_ed25519_keypair(secret: bytes) -> bool:
    """True when ``secret`` is seed(32) || public(32): Solana, NEAR, tweetnacl.

    A 64-byte base58 value is also the shape of every Solana *transaction
    signature*, so the second half must be the public key of the first.
    """
    if len(secret) != 64:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:  # pragma: no cover - cryptography ships with presidio-anonymizer
        return True  # cannot verify: treat as a key (over-redact, never leak)
    public = Ed25519PrivateKey.from_private_bytes(secret[:32]).public_key()
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw) == secret[32:]


# Monero base58 works on 8-byte blocks -> 11 chars; a short final block of
# k bytes takes _XMR_BLOCK_CHARS[k] chars.
_XMR_BLOCK_CHARS = (0, 2, 3, 5, 6, 7, 9, 10, 11)
# Standard / integrated / subaddress network bytes for main, stage and test nets.
_XMR_NETWORK_BYTES = frozenset({18, 19, 42, 24, 25, 36, 53, 54, 63})


def _monero_decode(token: str) -> bytes | None:
    if len(token) % 11 not in _XMR_BLOCK_CHARS:
        return None
    out = bytearray()
    for i in range(0, len(token), 11):
        block = token[i : i + 11]
        size = 8 if len(block) == 11 else _XMR_BLOCK_CHARS.index(len(block))
        value = 0
        for ch in block:
            value = value * 58 + _B58_INDEX[ch]
        if value >> (8 * size):
            return None  # overflows its block: not Monero's encoding
        out += value.to_bytes(size, "big")
    return bytes(out)


def _is_monero(token: str) -> bool:
    # 95 chars = 69 bytes (net + spend + view + checksum); 106 = integrated.
    if len(token) not in (95, 106):
        return False
    raw = _monero_decode(token)
    return raw is not None and raw[0] in _XMR_NETWORK_BYTES


def _is_cardano_byron(token: str, raw: bytes) -> bool:
    # Byron addresses are base58 of CBOR [#6.24(bytes), crc32]: 82 d8 18 ...
    return token.startswith(("Ae2", "Ddz")) and raw[:3] == b"\x82\xd8\x18"


def _base58_kind(token: str) -> str | None:
    raw = _b58decode(token)
    payload = _b58check(raw)
    if payload is not None and (kind := _classify_base58check(token, payload)):
        return kind
    if token[0] in _XRP_LEADS:
        payload = _b58check(_b58decode(token, _XRP_ALPHABET))
        if payload is not None and (kind := _classify_xrp(payload)):
            return kind
    if _is_ss58(raw):
        return "crypto_dot"
    if _is_solana_pubkey(token, raw):
        return "crypto_sol"
    if len(raw) == 64 and _is_ed25519_keypair(raw):
        return "crypto_private_key"
    if _is_monero(token):
        return "crypto_xmr"
    if _is_cardano_byron(token, raw):
        return "crypto_ada"
    return None


def _scan_base58(text: str) -> Iterator[_Hit]:
    for m in _B58_TOKEN.finditer(text):
        kind = _fail_closed(_base58_kind, m.group(), "crypto_address")
        # Only the checksum-free Solana guess is vetoed inside base64 blobs;
        # every other kind passed an integrity check and stands on its own.
        if kind == "crypto_sol" and _inside_base64(text, m.start(), m.end()):
            continue
        if kind is not None:
            yield m.start(), m.end(), kind


# ── bech32 / bech32m (BIP-173 / BIP-350) ─────────────────────────────────

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_VALUES = {c: i for i, c in enumerate(_BECH32_CHARSET)}
_BECH32_CONSTS = frozenset({1, 0x2BC830A3})  # bech32, bech32m
# HRP + "1" + data, single-case.  The data charset has no "1", so the regex's
# backtracking lands on the LAST "1" as the separator, exactly as the spec
# says.  The data part is allowed past BIP-173's 90-char cap because Cardano
# addresses and Lightning invoices use longer bech32 strings.
_BECH32_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_\-])"
    r"(?:[a-z][a-z0-9_\-]{0,40}1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,1500}"
    r"|[A-Z][A-Z0-9_\-]{0,40}1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{6,1500})"
    r"(?![A-Za-z0-9])"
)
_BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _bech32_polymod(values: Iterable[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i, g in enumerate(_BECH32_GEN):
            if (top >> i) & 1:
                chk ^= g
    return chk


def _bech32_decode(token: str) -> tuple[str, list[int]] | None:
    """(hrp, data without checksum) when bech32 or bech32m validates."""
    s = token.lower()
    sep = s.rfind("1")
    hrp = s[:sep]
    data = [_BECH32_VALUES[c] for c in s[sep + 1 :]]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _bech32_polymod(expanded + data) not in _BECH32_CONSTS:
        return None
    return hrp, data[:-6]


_SECRET_HRPS = frozenset({"nsec", "xprv", "suiprivkey", "age-secret-key-"})
_PUBLIC_HRPS = frozenset({"npub", "nprofile", "age"})
_IGNORED_HRPS = frozenset({"note", "nevent", "naddr", "nrelay"})  # public Nostr content IDs
_LIGHTNING_HRP = re.compile(r"ln(?:bc|tb|tbs|bcrt|sb)(?:\d+[munp]?)?")
_COSMOS_HRPS = frozenset(
    {
        "cosmos", "osmo", "juno", "terra", "kava", "secret", "inj", "celestia",
        "akash", "axelar", "evmos", "stars", "sei", "dydx", "noble", "stride",
        "kujira", "neutron", "persistence", "regen", "umee", "cro", "band",
        "iaa", "fetch", "xpla", "migaloo", "archway", "cheqd", "desmos", "dym",
        "saga", "mantra", "somm", "gravity", "bitsong", "comdex", "agoric",
        "canto", "nibi", "kyve", "thor", "maya", "bnb", "tbnb", "zeta", "elys",
    }
)  # fmt: skip


def _bech32_kind(hrp: str, data: list[int]) -> str | None:
    if hrp in ("bc", "tb", "bcrt"):
        return "crypto_btc"
    if hrp in ("ltc", "tltc", "rltc"):
        return "crypto_ltc"
    if hrp in ("addr", "addr_test", "stake", "stake_test"):
        return "crypto_ada"
    # Cardano CIP-5 key prefixes end in _sk/_xsk (signing) and _vk/_xvk
    # (verification); Cosmos public keys end in "pub" (cosmospub, ...valoperpub).
    if hrp in _SECRET_HRPS or hrp.endswith(("_sk", "_xsk")):
        return "crypto_private_key"
    if hrp in _PUBLIC_HRPS or hrp.endswith(("_vk", "_xvk", "pub")):
        return "crypto_public_key"
    if hrp == "lnurl" or _LIGHTNING_HRP.fullmatch(hrp):
        return "crypto_lightning"
    if hrp in _IGNORED_HRPS:
        return None
    base = hrp.removesuffix("valoper").removesuffix("valcons")
    if base in _COSMOS_HRPS:
        return "crypto_cosmos"
    # Unknown prefix, valid checksum, >= 160 bits of data: some other chain's
    # address (Harmony one1..., MultiversX erd1..., Zcash zs1..., ...).
    return "crypto_address" if len(data) >= 32 else None


def _bech32_token_kind(token: str) -> str | None:
    decoded = _bech32_decode(token)
    return _bech32_kind(*decoded) if decoded is not None else None


def _scan_bech32(text: str) -> Iterator[_Hit]:
    for m in _BECH32_TOKEN.finditer(text):
        kind = _fail_closed(_bech32_token_kind, m.group(), "crypto_address")
        if kind is not None:
            yield m.start(), m.end(), kind


# ── CashAddr (Bitcoin Cash) ──────────────────────────────────────────────

_CASHADDR_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:(bitcoincash|bchtest|bchreg):)?"
    r"([qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41}(?:[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{19})?)"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_CASHADDR_GEN = (
    (0x01, 0x98F2BC8E61),
    (0x02, 0x79B76D99E2),
    (0x04, 0xF33E5FB3C4),
    (0x08, 0xAE2EABE2A8),
    (0x10, 0x1E4F43E470),
)


def _cashaddr_polymod(values: Iterable[int]) -> int:
    c = 1
    for d in values:
        top = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for bit, g in _CASHADDR_GEN:
            if top & bit:
                c ^= g
    return c ^ 1


def _is_cashaddr(prefix: str | None, payload: str) -> bool:
    if payload not in (payload.lower(), payload.upper()):
        return False  # mixed case is invalid in every bech32-family format
    data = [_BECH32_VALUES[c] for c in payload.lower()]
    # The prefix is part of the checksum even when it is left out of the text.
    for p in (prefix.lower(),) if prefix else ("bitcoincash", "bchtest"):
        if _cashaddr_polymod([ord(c) & 0x1F for c in p] + [0] + data) == 0:
            return True
    return False


def _scan_cashaddr(text: str) -> Iterator[_Hit]:
    for m in _CASHADDR_TOKEN.finditer(text):
        try:
            valid = _is_cashaddr(m.group(1), m.group(2))
        except Exception:  # pragma: no cover - defensive, see _fail_closed
            valid = True
        if valid:
            yield m.start(), m.end(), "crypto_bch"


# ── Base32: Stellar StrKey and Algorand ──────────────────────────────────

# Stellar accounts/seeds/contracts are 56 chars, muxed accounts 69, Algorand 58.
_B32_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Z2-7]{56,69}(?![A-Za-z0-9])")


def _b32decode(token: str) -> bytes | None:
    try:
        return base64.b32decode(token + "=" * (-len(token) % 8))
    except binascii.Error:
        return None


def _is_algorand(token: str) -> bool:
    raw = _b32decode(token)
    if raw is None or len(raw) != 36:
        return False
    try:
        digest = hashlib.new("sha512_256", raw[:32]).digest()
    except ValueError:  # pragma: no cover - OpenSSL built without SHA-512/256
        return True  # cannot verify: let the shape decide (over-redact, never leak)
    return digest[-4:] == raw[32:]


def _base32_kind(token: str) -> str | None:
    if len(token) == 58:
        return "crypto_algo" if _is_algorand(token) else None
    if len(token) not in (56, 69):
        return None
    raw = _b32decode(token)
    if raw is None:
        return None
    body, check = raw[:-2], raw[-2:]
    # crc_hqx with init 0 is CRC-16/XMODEM; StrKey stores it little-endian.
    if binascii.crc_hqx(body, 0).to_bytes(2, "little") != check or body[0] & 7:
        return None
    version = body[0] >> 3
    if version == 18:
        return "crypto_private_key"  # secret seed "S..."
    if version in (6, 12, 2):
        return "crypto_xlm"  # account "G...", muxed account "M...", contract "C..."
    return None  # pre-auth tx / hash / signed-payload signers: not personal data


def _scan_base32(text: str) -> Iterator[_Hit]:
    for m in _B32_TOKEN.finditer(text):
        kind = _fail_closed(_base32_kind, m.group(), "crypto_address")
        if kind is not None:
            yield m.start(), m.end(), kind


# ── EVM addresses ────────────────────────────────────────────────────────

_EVM_ADDRESS = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
# Sentinels and canonical mainnet infrastructure: never personal data, and
# common enough in Solidity/TS code that redacting them hurts answers.
_EVM_PUBLIC_ADDRESSES = frozenset(
    a.lower()
    for a in (
        "0x0000000000000000000000000000000000000000",  # zero address
        "0x000000000000000000000000000000000000dEaD",  # burn address
        "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",  # "native ETH" sentinel
        "0xcA11bde05977b3631167028862bE2a173976CA11",  # Multicall3
        "0x000000000022D473030F116dDEE9F6B43aC78BA3",  # Permit2
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH9
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
        "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
    )
)


def _scan_evm(text: str) -> Iterator[_Hit]:
    for m in _EVM_ADDRESS.finditer(text):
        if m.group().lower() not in _EVM_PUBLIC_ADDRESSES:
            yield m.start(), m.end(), "crypto_eth"


# ── Hex keys: secp256k1 / BLS public keys, private keys in context ───────

_SECP256K1_P = 2**256 - 2**32 - 977
_HEX_TOKEN = re.compile(r"(?<![0-9A-Za-z])(0x)?([0-9a-fA-F]{64,130})(?![0-9A-Za-z])")
# How far back a private-key keyword may sit, and how close the next key in a
# list must follow to inherit it (``PRIVATE_KEYS=0x..,0x..`` or a YAML list).
_CONTEXT_WINDOW = 200
_CHAIN_GAP = 100
_PRIVATE_KEY_CONTEXT = re.compile(
    r"(?i)priv(?:ate)?[\s_\-]*keys?|privkey|secret[\s_\-]*(?:keys?|exponent)|\bsecret\b"
    r"|sign(?:ing|er)[\s_\-]*keys?|(?:wallet|deployer)[\s_\-]*keys?|from_?key"
    r"|\bpk\b|\bsk\b|\bseed\b|mnemonic|keypair"
    # Hardhat `accounts: [...]`, Brownie `accounts.add(`, web3.js
    # `wallet.add(`, ethers `new Wallet(`: the usual ways keys land in code.
    r"|\baccounts\s*:\s*\[|\b(?:accounts|wallet)\.add\s*\(|\bWallet\s*\("
)


def _on_secp256k1(digits: str) -> bool:
    """Does this 33/65/64-byte hex value encode a point on secp256k1?"""
    key = bytes.fromhex(digits)
    p = _SECP256K1_P
    if len(key) == 64:
        key = b"\x04" + key  # uncompressed, written without its 04 prefix
    if len(key) == 65 and key[0] == 0x04:
        x, y = int.from_bytes(key[1:33], "big"), int.from_bytes(key[33:], "big")
        return x < p and y < p and (y * y - x * x * x - 7) % p == 0
    if len(key) == 33 and key[0] in (0x02, 0x03):
        x = int.from_bytes(key[1:], "big")
        if x >= p:
            return False
        # A matching y exists iff x^3 + 7 is a square mod p (Euler's criterion).
        return pow((pow(x, 3, p) + 7) % p, (p - 1) // 2, p) == 1
    return False


def _hex_kind(text: str, m: re.Match[str], chained: bool) -> str | None:
    prefixed, digits = m.group(1) is not None, m.group(2)
    n = len(digits)
    if n in (66, 128, 130) and _on_secp256k1(digits):
        return "crypto_public_key"
    # Ethereum validator (BLS12-381) public keys: 0x + 48 bytes with the
    # compression flag set and the infinity flag clear.
    if n == 96 and prefixed and digits[0] in "89abAB":
        return "crypto_public_key"
    # 32-byte keys / 64-byte BIP32 seeds look exactly like SHA-256 / SHA-512
    # digests; only context separates them.
    if n in (64, 128) and (
        chained or _PRIVATE_KEY_CONTEXT.search(text, max(0, m.start() - _CONTEXT_WINDOW), m.start())
    ):
        return "crypto_private_key"
    return None


def _scan_hex(text: str) -> Iterator[_Hit]:
    last_key_end = -_CHAIN_GAP - 1
    for m in _HEX_TOKEN.finditer(text):
        chained = m.start() - last_key_end <= _CHAIN_GAP
        try:
            kind = _hex_kind(text, m, chained)
        except Exception:  # pragma: no cover - defensive, see _fail_closed
            kind = "crypto_private_key" if len(m.group(2)) in (64, 128) else None
        if kind is not None:
            if kind == "crypto_private_key":
                last_key_end = m.end()
            yield m.start(), m.end(), kind


# ── Solana / NEAR keypair files ──────────────────────────────────────────

# `solana-keygen` writes the 64-byte secret as a JSON array of integers.
_BYTE_ARRAY_64 = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*,?\s*\]")
_INT = re.compile(r"\d+")


def _scan_keypair_arrays(text: str) -> Iterator[_Hit]:
    for m in _BYTE_ARRAY_64.finditer(text):
        values = [int(v) for v in _INT.findall(m.group())]
        if any(v > 255 for v in values):
            continue
        try:
            is_key = _is_ed25519_keypair(bytes(values))
        except Exception:  # pragma: no cover - defensive, see _fail_closed
            is_key = True
        if is_key:
            yield m.start(), m.end(), "crypto_private_key"


# ── BIP-39 seed phrases ──────────────────────────────────────────────────

#: Shortest run of consecutive BIP-39 words reported as a seed phrase.  Real
#: phrases are 12-24 words (Algorand: 25, from the same list).  Measured on
#: this repo's docs plus ~100 MB of library source: prose never chains more
#: than 9 list words (it is full of "a", "the", "of", which are not on the
#: list), but code does: ``(False,), (True,)`` tables, ``torch.float16``
#: maps and CSS property lists reach 18.  Those runs repeat a handful of
#: words, which is what ``MIN_DISTINCT_WORDS`` rejects.
MIN_MNEMONIC_WORDS = 12
#: Distinct words required in some window of ``MIN_MNEMONIC_WORDS``.  Twelve
#: random draws from 2048 words give >= 10 distinct words more than 99.9% of
#: the time; the code runs above have 2-6.  (The zero-entropy test vector
#: "abandon x11 about" is public and is deliberately not redacted.)
MIN_DISTINCT_WORDS = 10

# What may separate two words of one phrase: whitespace and punctuation
# (spaces, newlines, commas, JSON quotes, list bullets), optionally carrying
# a one- or two-digit position number ("1. abandon 2. ability").  The number
# needs punctuation on both sides, so "float16:" is not a list number.
# Underscores, letters and long gaps break the run, so snake_case never chains.
_GAP = r"(?:[^\w]{1,16}|[^\w]{1,16}\d{1,2}[^\w]{1,16})"
_MNEMONIC_GAP = re.compile(_GAP)
# Pre-filter in C: >= MIN_MNEMONIC_WORDS words of 3-8 letters (the BIP-39
# English length range) joined by legal gaps.  Prose is full of one- and
# two-letter words, so this rejects nearly all of it before any per-word
# Python work happens.
_WORD_RUN = re.compile(
    r"(?<![A-Za-z])(?:[A-Za-z]{3,8}%s){%d,}[A-Za-z]{3,8}(?![A-Za-z])"
    % (_GAP, MIN_MNEMONIC_WORDS - 1)
)
_WORD = re.compile(r"[A-Za-z]+")


@lru_cache(maxsize=1)
def bip39_words() -> frozenset[str]:
    """The official BIP-39 English wordlist (2048 words; SHA-256 pinned in tests)."""
    raw = resources.files("llm_redactor.detect").joinpath("bip39_english.txt")
    words = raw.read_text(encoding="ascii").split()
    if len(words) != 2048:
        raise RuntimeError(f"bip39_english.txt is damaged: {len(words)} words, expected 2048")
    return frozenset(words)


def _seed_like(run: list[re.Match[str]]) -> Iterator[_Hit]:
    """Yield the parts of one word run that look like a random seed phrase.

    Every window of ``MIN_MNEMONIC_WORDS`` with enough distinct words is
    marked, and overlapping marked windows are reported as one span, so a
    real 24-word phrase stays one placeholder even inside a longer run.
    """
    if len(run) < MIN_MNEMONIC_WORDS:
        return
    lowered = [m.group().lower() for m in run]
    span_start = span_end = -1
    for i in range(len(run) - MIN_MNEMONIC_WORDS + 1):
        j = i + MIN_MNEMONIC_WORDS
        if len(set(lowered[i:j])) < MIN_DISTINCT_WORDS:
            continue
        if i > span_end:  # disjoint from the window being grown
            if span_start >= 0:
                yield run[span_start].start(), run[span_end].end(), "crypto_mnemonic"
            span_start = i
        span_end = j - 1
    if span_start >= 0:
        yield run[span_start].start(), run[span_end].end(), "crypto_mnemonic"


def _without_label(text: str, run: list[re.Match[str]]) -> list[re.Match[str]]:
    """Drop a leading label such as ``seed:`` or ``"mnemonic":``.

    "seed" is itself a BIP-39 word, so ``seed: harbor swap ...`` chains the
    label into the run.  A colon (with no list number) after one of the first
    three words marks everything before it as a label: dropping a label can
    never leak a phrase word, while keeping it only hides the label.
    """
    for i in range(min(3, len(run) - 1)):
        gap = text[run[i].end() : run[i + 1].start()]
        if ":" in gap and not any(c.isdigit() for c in gap):
            return run[i + 1 :]
    return run


def _mnemonic_runs(text: str, start: int, end: int, words: frozenset[str]) -> Iterator[_Hit]:
    run: list[re.Match[str]] = []
    for m in _WORD.finditer(text, start, end):
        if m.group().lower() not in words:
            yield from _seed_like(_without_label(text, run))
            run = []
        elif run and not _MNEMONIC_GAP.fullmatch(text, run[-1].end(), m.start()):
            yield from _seed_like(_without_label(text, run))
            run = [m]
        else:
            run.append(m)
    yield from _seed_like(_without_label(text, run))


def _scan_mnemonics(text: str) -> Iterator[_Hit]:
    words = bip39_words()
    for candidate in _WORD_RUN.finditer(text):
        yield from _mnemonic_runs(text, candidate.start(), candidate.end(), words)


# ── Entry point ──────────────────────────────────────────────────────────

_SCANNERS: tuple[Callable[[str], Iterator[_Hit]], ...] = (
    _scan_mnemonics,
    _scan_keypair_arrays,
    _scan_hex,
    _scan_evm,
    _scan_bech32,
    _scan_cashaddr,
    _scan_base32,
    _scan_base58,
)


def detect_wallets(text: str) -> list[Span]:
    """Every blockchain address, public key, private key and seed phrase in ``text``.

    The scanners' candidate alphabets barely overlap (hex, bech32, base32 and
    base58 tokens are told apart by their decoded bytes), and the orchestrator
    merges any overlap with other detectors.
    """
    hits: list[_Hit] = []
    for scan in _SCANNERS:
        hits.extend(scan(text))
    return [
        Span(start=s, end=e, kind=k, confidence=1.0, text=text[s:e], source="regex")
        for s, e, k in hits
    ]
