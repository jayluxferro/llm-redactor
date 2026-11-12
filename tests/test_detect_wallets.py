"""Blockchain address / key / seed-phrase detection (detect/wallets.py).

Two kinds of evidence, on purpose:

* Published vectors (BIP-32/38/173/350, the Bitcoin wiki, Substrate's dev
  accounts, Hardhat's default account, the secp256k1 generator) check the
  decoders against values produced by somebody else's implementation.
* For formats without a convenient public vector, the encoders in this file
  are written independently of the module under test (straight from the
  specs), so a shared misunderstanding would have to be made twice.

The private keys below are all public test material: they control nothing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
from pathlib import Path

import pytest

from llm_redactor.detect import wallets
from llm_redactor.detect.ner import PRESIDIO_KIND_MAP
from llm_redactor.detect.orchestrator import detect_all
from llm_redactor.detect.regex import PATTERNS, detect_regex
from llm_redactor.detect.types import CATEGORY_MAP, filter_by_categories
from llm_redactor.detect.wallets import (
    ADDRESS_KINDS,
    MIN_MNEMONIC_WORDS,
    PUBLIC_KEY_KINDS,
    SECRET_KINDS,
    WALLET_KINDS,
    bip39_words,
    detect_wallets,
)
from llm_redactor.redact.placeholder import redact
from llm_redactor.redact.restore import restore

# ── independent encoders (from the specs, not from wallets.py) ───────────

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
XRP = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def b58encode(data: bytes, alphabet: str = B58) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return alphabet[0] * (len(data) - len(data.lstrip(b"\0"))) + out


def b58check(payload: bytes, alphabet: str = B58) -> str:
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + check, alphabet)


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32(hrp: str, data: bytes, const: int = 1) -> str:
    acc = bits = 0
    five: list[int] = []
    for byte in data:  # 8-bit -> 5-bit groups, zero-padded
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            five.append((acc >> bits) & 31)
    if bits:
        five.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _polymod(expanded + five + [0] * 6) ^ const
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32[d] for d in five + checksum)


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def strkey(version: int, payload: bytes) -> str:
    body = bytes([version << 3]) + payload
    return base64.b32encode(body + crc16_xmodem(body).to_bytes(2, "little")).decode().rstrip("=")


def kinds(text: str) -> list[tuple[str, str]]:
    return [(s.kind, s.text) for s in detect_wallets(text)]


def only(text: str, token: str) -> str:
    """Assert ``token`` is the single wallet hit in ``text``; return its kind."""
    hits = kinds(text)
    assert len(hits) == 1 and hits[0][1] == token, hits
    return hits[0][0]


# ── published vectors ────────────────────────────────────────────────────

PUBLISHED = {
    # Bitcoin wiki / BIP-173 / BIP-350
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2": "crypto_btc",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy": "crypto_btc",
    "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4": "crypto_btc",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7": "crypto_btc",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0": "crypto_btc",
    "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a": "crypto_bch",
    "LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL": "crypto_ltc",
    "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L": "crypto_doge",
    "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW": "crypto_trx",
    "0x52908400098527886E0F7030069857D2E4169EE7": "crypto_eth",  # EIP-55 vector
    "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh": "crypto_xrp",  # XRPL genesis account
    "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY": "crypto_dot",  # Substrate "Alice"
    "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV": "crypto_sol",
    "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A": (  # noqa: E501
        "crypto_xmr"  # Monero general fund
    ),
    "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x": (  # noqa: E501
        "crypto_ada"  # CIP-19 vector
    ),
    "Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi": "crypto_ada",  # Byron
    "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ": "crypto_xlm",
    "VCMJKWOY5P5P7SKMZFFOCEROPJCZOTIJMNIYNUCKH7LRO45JMJP6UYBIJA": "crypto_algo",
    "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb": "crypto_xtz",
    # BIP-32 test vector 1, master node
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8": (  # noqa: E501
        "crypto_xpub"
    ),
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi": (  # noqa: E501
        "crypto_xprv"
    ),
    # Bitcoin wiki WIF example, uncompressed and compressed
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ": "crypto_private_key",
    "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617": "crypto_private_key",
    # BIP-38 test vector 1 (passphrase "TestingOneTwoThree")
    "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg": "crypto_private_key",
    "snoPBrXtMeMyMHUVTgbuqAfg1SUTb": "crypto_private_key",  # XRPL "masterpassphrase" seed
    # secp256k1 generator G, compressed / uncompressed / uncompressed without 04
    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798": "crypto_public_key",
    "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8": "crypto_public_key",
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8": "crypto_public_key",
}


@pytest.mark.parametrize("token,kind", PUBLISHED.items(), ids=lambda v: v[:14])
def test_published_vectors(token: str, kind: str) -> None:
    assert only(f"send to {token}, thanks", token) == kind


@pytest.mark.parametrize(
    "token",
    [
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3",  # last char changed
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b",
        "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ",
        "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGA",
        # First char: Algorand's LAST char is mostly padding bits, so changing
        # it can leave the decoded account (and its checksum) untouched.
        "WCMJKWOY5P5P7SKMZFFOCEROPJCZOTIJMNIYNUCKH7LRO45JMJP6UYBIJA",
        "Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  # mixed case is invalid bech32
    ],
)
def test_corrupted_checksums_are_not_redacted(token: str) -> None:
    # Documented trade-off (module docstring): precision over typo tolerance.
    assert kinds(f"send to {token}") == []


# ── generated round trips ────────────────────────────────────────────────

rng = random.Random(1337)
H20, H32 = rng.randbytes(20), rng.randbytes(32)


@pytest.mark.parametrize(
    "token,lead,kind",
    [
        (b58check(b"\x30" + H20), "L", "crypto_ltc"),
        (b58check(b"\x1e" + H20), "D", "crypto_doge"),
        (b58check(b"\x41" + H20), "T", "crypto_trx"),
        (b58check(b"\x6f" + H20), "", "crypto_btc"),  # testnet m/n
        (b58check(b"\x4c" + H20), "X", "crypto_address"),  # Dash: unlisted version
        (b58check(b"\x1c\xb8" + H20), "t1", "crypto_address"),  # Zcash transparent
        (b58check(b"\x06\xa1\x9f" + H20), "tz1", "crypto_xtz"),
        (b58check(b"\x02\x5a\x79" + H20), "KT1", "crypto_xtz"),
        (b58check(b"\x0d\x0f\x25\xd9" + H32), "edpk", "crypto_public_key"),
        (b58check(b"\x0d\x0f\x3a\x07" + H32), "edsk", "crypto_private_key"),
        (b58check(b"\x2b\xf6\x4e\x07" + rng.randbytes(64)), "edsk", "crypto_private_key"),
        (b58check(b"\x01\x42\xc0" + rng.randbytes(36)), "6P", "crypto_private_key"),
        (b58check(b"\x80" + H32 + b"\x01"), "", "crypto_private_key"),  # WIF compressed
        (b58check(b"\xb0" + H32), "", "crypto_private_key"),  # Litecoin WIF
        (b58check(b"\x05\x44" + H20 + b"\x00" + bytes(8), XRP), "X", "crypto_xrp"),
        (b58check(b"\x01\xe1\x4b" + rng.randbytes(16), XRP), "sEd", "crypto_private_key"),
        (strkey(6, H32), "G", "crypto_xlm"),
        (strkey(12, H32 + bytes(8)), "M", "crypto_xlm"),
        (strkey(2, H32), "C", "crypto_xlm"),
        (strkey(18, H32), "S", "crypto_private_key"),
        (bech32("ltc", b"\x00" + H20), "ltc1", "crypto_ltc"),
        (bech32("cosmos", H20), "cosmos1", "crypto_cosmos"),
        (bech32("osmovaloper", H20), "osmovaloper1", "crypto_cosmos"),
        (bech32("cosmospub", rng.randbytes(38)), "cosmospub1", "crypto_public_key"),
        (bech32("stake", rng.randbytes(29)), "stake1", "crypto_ada"),
        (bech32("addr_xsk", rng.randbytes(96)), "addr_xsk1", "crypto_private_key"),
        (bech32("addr_vk", H32), "addr_vk1", "crypto_public_key"),
        (bech32("nsec", H32), "nsec1", "crypto_private_key"),
        (bech32("npub", H32), "npub1", "crypto_public_key"),
        (bech32("suiprivkey", b"\x00" + H32), "suiprivkey1", "crypto_private_key"),
        (bech32("age-secret-key-", H32).upper(), "AGE-SECRET-KEY-1", "crypto_private_key"),
        (bech32("lnbc2500u", rng.randbytes(180)), "lnbc2500u1", "crypto_lightning"),
        (bech32("lnurl", rng.randbytes(60)).upper(), "LNURL1", "crypto_lightning"),
        (bech32("one", H20), "one1", "crypto_address"),  # Harmony: unknown HRP
        (bech32("erd", H32, const=0x2BC830A3), "erd1", "crypto_address"),  # bech32m
    ],
    ids=lambda v: v if isinstance(v, str) and len(v) < 20 else None,
)
def test_generated_formats(token: str, lead: str, kind: str) -> None:
    assert token.startswith(lead), "encoder/prefix assumption is wrong"
    assert only(f"value: {token}\n", token) == kind


def test_public_nostr_content_ids_and_short_bech32_are_ignored() -> None:
    assert kinds(bech32("note", H32)) == []
    assert kinds(bech32("ab", b"\x01\x02\x03")) == []


def test_extended_keys_are_classified_by_key_byte_not_prefix() -> None:
    # A zpub/zprv-style version prefix is not in any list; byte 45 decides.
    head = b"\x04\xb2\x47\x46" + bytes(9) + H32
    assert only(b58check(head + b"\x02" + H32), b58check(head + b"\x02" + H32)) == "crypto_xpub"
    assert only(b58check(head + b"\x00" + H32), b58check(head + b"\x00" + H32)) == "crypto_xprv"


# ── keys whose format has no checksum ────────────────────────────────────

HARDHAT_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


@pytest.mark.parametrize(
    "text",
    [
        f"PRIVATE_KEY={HARDHAT_0}",
        f'{{"privateKey": "{HARDHAT_0}"}}',
        f"forge script Deploy --private-key {HARDHAT_0} --broadcast",
        f"my private key is {HARDHAT_0[2:]}",
        f"const wallet = new Wallet('{HARDHAT_0}')",
        f"account = Account.from_key('{HARDHAT_0}')",
        f"uint256 deployerPrivateKey = {HARDHAT_0};",
    ],
)
def test_hex_private_key_in_context(text: str) -> None:
    hits = kinds(text)
    assert [k for k, _ in hits] == ["crypto_private_key"], hits


def test_hex_private_keys_in_a_list_inherit_the_label() -> None:
    other = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    third = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
    hardhat = f"networks: {{ sepolia: {{ accounts: ['{HARDHAT_0}', '{other}'] }} }}"
    assert [k for k, _ in kinds(hardhat)] == ["crypto_private_key"] * 2
    yaml_list = f"private_keys:\n  - {HARDHAT_0}\n  - {other}\n  - {third}\n"
    assert [k for k, _ in kinds(yaml_list)] == ["crypto_private_key"] * 3


@pytest.mark.parametrize(
    "text",
    [
        # A bare 0x + 64-hex value is far more often a tx hash than a key.
        "tx 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060 mined",
        "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "MINTER_ROLE = 0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6",
        "commit 1f7a2d9e1c8b4e5f6a7b8c9d0e1f2a3b4c5d6e7f",
    ],
)
def test_hashes_without_key_context_are_not_redacted(text: str) -> None:
    assert kinds(text) == []


def test_secp256k1_points_must_be_on_the_curve() -> None:
    p = 2**256 - 2**32 - 977
    x = next(x for x in range(2, 100) if pow((x**3 + 7) % p, (p - 1) // 2, p) != 1)
    off_curve = "02" + x.to_bytes(32, "big").hex()
    assert kinds(off_curve) == []
    assert kinds("04" + rng.randbytes(64).hex()) == []


def test_eth_validator_bls_pubkey() -> None:
    key = "0xa" + rng.randbytes(48).hex()[1:]
    assert only(f"validator {key} exited", key) == "crypto_public_key"
    assert kinds("0x1" + rng.randbytes(48).hex()[1:]) == []  # compression flag unset


def _ed25519_keypair() -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PrivateKey.from_private_bytes(H32)
    return H32 + key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_solana_keypair_file_and_base58_secret() -> None:
    secret = _ed25519_keypair()
    keyfile = json.dumps(list(secret))  # what `solana-keygen new` writes
    assert only(f"id.json: {keyfile}", keyfile) == "crypto_private_key"
    exported = b58encode(secret)  # Phantom / NEAR "ed25519:<base58>" export
    assert only(f"ed25519:{exported}", exported) == "crypto_private_key"


def test_solana_signatures_are_not_mistaken_for_secret_keys() -> None:
    # Same 64-byte base58 shape as an exported secret key, but the halves are
    # unrelated, so this is a transaction signature: public, not redacted.
    assert kinds(b58encode(rng.randbytes(64))) == []
    assert kinds(json.dumps(list(rng.randbytes(64)))) == []


def test_solana_recall_on_random_keys() -> None:
    # The checksum-free heuristics may veto a real key; the module docstring
    # promises about 1 in 5,000.  Pin it well above that, deterministically.
    local = random.Random(2024)
    keys = [b58encode(local.randbytes(32)) for _ in range(5000)]
    found = sum(kinds(f" {k} ") == [("crypto_sol", k)] for k in keys)
    assert found >= 4990, found


@pytest.mark.parametrize(
    "text",
    [
        "hipDeviceAttributeMaxTexture2DLayeredHeight",  # camelCase identifiers
        "cudaFuncAttributeMaxDynamicSharedMemorySize",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # public program ID
        "0x0000000000000000000000000000000000000000",  # zero address
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC contract
    ],
)
def test_identifiers_and_public_infrastructure_pass_through(text: str) -> None:
    assert kinds(f"see {text}") == []


def test_base64_blobs_do_not_produce_solana_hits() -> None:
    blob = base64.b64encode(random.Random(7).randbytes(200_000)).decode()
    assert [k for k, _ in kinds(blob) if k == "crypto_sol"] == []


def test_solana_address_in_explorer_url() -> None:
    addr = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV"
    assert only(f"https://solscan.io/account/{addr}?cluster=devnet", addr) == "crypto_sol"


# ── seed phrases ─────────────────────────────────────────────────────────


WORDLISTS = Path(wallets.__file__).with_name("wordlists")


def bip39_mnemonic(entropy: bytes, language: str = "english") -> list[str]:
    """BIP-39 entropy -> words, checksum included (straight from the spec)."""
    wordlist = (WORDLISTS / f"bip39_{language}.txt").read_text(encoding="utf-8").split()
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(len(entropy) * 8)
    check = bin(hashlib.sha256(entropy).digest()[0])[2:].zfill(8)[: len(entropy) * 8 // 32]
    bits += check
    return [wordlist[int(bits[i : i + 11], 2)] for i in range(0, len(bits), 11)]


# Provenance of every bundled list, pinned so corruption or a hand edit fails
# loudly.  BIP-39: bitcoin/bips bip-0039/*.txt, byte for byte (these are the
# hashes published with BIP-39).  SLIP-39: satoshilabs/slips
# slip-0039/wordlist.txt, byte for byte.  electrum_old: the 1626-word list
# literal in spesmilo/electrum electrum/old_mnemonic.py; monero_english: the
# words of monero-project/monero src/mnemonics/english.h, one per line.
WORDLIST_SHA256 = {
    "bip39_chinese_simplified": "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726",
    "bip39_chinese_traditional": "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f",
    "bip39_czech": "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc",
    "bip39_english": "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
    "bip39_french": "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59",
    "bip39_italian": "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2",
    "bip39_japanese": "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd",
    "bip39_korean": "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60",
    "bip39_portuguese": "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f",
    "bip39_spanish": "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b",
    "electrum_old": "c8da327d316f8ee758b790068e618077ac271a89fd77ec1250c59ae40e7b599e",
    "monero_english": "eaa6bce7dd92f4d6dd74f224264e0ef4ad21095d68ec77616b26ceb599baf4f7",
    "slip39": "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3",
}


@pytest.mark.parametrize("stem,digest", WORDLIST_SHA256.items())
def test_bundled_wordlists_are_the_published_ones(stem: str, digest: str) -> None:
    assert hashlib.sha256((WORDLISTS / f"{stem}.txt").read_bytes()).hexdigest() == digest
    assert stem in wallets.wordlists()  # and the detector loads every one of them
    assert len(bip39_words()) == 2048


SEED12 = bip39_mnemonic(bytes.fromhex("9e885d952ad362caeb4efe34a8e91bd2"))
SEED24 = bip39_mnemonic(random.Random(99).randbytes(32))


@pytest.mark.parametrize(
    "layout",
    [
        " ".join,
        ", ".join,
        "\n".join,
        lambda ws: "\n".join(f"{i}. {w}" for i, w in enumerate(ws, 1)),
        lambda ws: "  ".join(f"{i}) {w.upper()}" for i, w in enumerate(ws, 1)),
        json.dumps,
    ],
    ids=["spaces", "commas", "lines", "numbered", "upper", "json"],
)
def test_seed_phrase_layouts(layout) -> None:
    body = layout(SEED12)
    hits = kinds(f"My recovery phrase:\n{body}\nDon't share it.")
    assert [k for k, _ in hits] == ["crypto_mnemonic"], hits
    text = hits[0][1].lower()
    assert SEED12[0] in text and SEED12[-1] in text and "recovery" not in text


def test_long_seed_phrase_is_one_span() -> None:
    phrase = " ".join(SEED24)
    # "seed" is itself a BIP-39 word; the label before the colon is trimmed.
    assert kinds(f"seed: {phrase}") == [("crypto_mnemonic", phrase)]
    assert kinds(json.dumps({"mnemonic": phrase})) == [("crypto_mnemonic", phrase)]


def test_short_runs_and_repetitive_code_are_not_seed_phrases() -> None:
    assert kinds(" ".join(SEED12[: MIN_MNEMONIC_WORDS - 1])) == []
    table = "[(False,), (False,), (True,)],\n" * 6  # 18 list words, 2 distinct
    assert kinds(table) == []
    css = "'border-image-repeat', 'border-image-slice', 'border-image-source', " * 2
    assert kinds(css) == []
    dtypes = "torch.float16: torch.float32, torch.float32: torch.float64, " * 3
    assert kinds(dtypes) == []


def test_prose_does_not_look_like_a_seed_phrase() -> None:
    readme = (Path(__file__).parents[1] / "README.md").read_text()
    assert [s for s in detect_wallets(readme) if s.kind == "crypto_mnemonic"] == []


def _detected_phrase(text: str) -> str:
    hits = kinds(text)
    assert [k for k, _ in hits] == ["crypto_mnemonic"], hits
    return hits[0][1]


@pytest.mark.parametrize(
    "language,sep",
    [
        ("spanish", " "),  # accented words typed composed (NFC); the list is NFKD
        ("french", " "),
        ("czech", " "),
        ("italian", " "),
        ("portuguese", " "),
        ("japanese", "\u3000"),  # wallets join Japanese words with ideographic spaces
        ("korean", " "),  # Hangul typed as composed syllables, list decomposed
        ("chinese_simplified", " "),
        ("chinese_traditional", " "),
    ],
)
def test_seed_phrases_in_other_bip39_languages(language: str, sep: str) -> None:
    import unicodedata

    words = bip39_mnemonic(random.Random(language).randbytes(16), language)
    phrase = sep.join(unicodedata.normalize("NFC", w) for w in words)
    assert _detected_phrase(f"backup:\n{phrase}\n") == phrase


def test_unspaced_chinese_prose_is_not_a_seed_phrase() -> None:
    # Chinese prose is made of exactly the characters on the Chinese lists;
    # only space-separated characters may chain.
    words = (WORDLISTS / "bip39_chinese_simplified.txt").read_text(encoding="utf-8").split()
    prose = "".join(random.Random(5).sample(words, 60))
    assert kinds(prose) == []


def test_monero_slip39_and_old_electrum_phrases() -> None:
    monero = (
        "sequence atlas unveil summon pebbles tuesday beer rudely snake rockets different "
        "fuselage woven tagged bested dented vegan hover rapid fawns obvious muppet randomly "
        "seasons randomly"
    )  # a widely published Monero example seed (checksum word last)
    assert _detected_phrase(f"monero seed: {monero}") == monero
    share = (
        "duckling enlarge academic academic agency result length solution fridge kidney "
        "coal piece deal husband erode duke ajar critical decision keyboard"
    )  # SLIP-39 test vector 1
    assert _detected_phrase(share) == share
    old = (WORDLISTS / "electrum_old.txt").read_text().split()
    electrum = " ".join(random.Random(12).sample(old, 12))
    assert _detected_phrase(f"electrum seed: {electrum}") == electrum


@pytest.mark.parametrize(
    "text,expected",
    [
        ("pay vitalik.eth or treasury.dao.eth", ["vitalik.eth", "treasury.dao.eth"]),
        ("balance = w3.eth.get_balance(addr)", []),  # web3.py attribute chain
        ("call web3.eth for the block", []),
        ("from foo.ethereum import x", []),
    ],
)
def test_ens_names(text: str, expected: list[str]) -> None:
    assert [t for k, t in kinds(text) if k == "crypto_ens"] == expected


def test_move_chain_addresses_need_a_chain_keyword() -> None:
    addr = "0x" + "a1" * 32
    assert only(f"aptos account fund-with-faucet --account {addr}", addr) == "crypto_address"
    assert only(f"sui client object {addr}", addr) == "crypto_address"
    assert kinds(f"digest {addr}") == []  # without context it may be any hash


# ── integration with the rest of detection ───────────────────────────────


def test_every_emitted_kind_is_in_the_taxonomy() -> None:
    # filter_by_categories silently drops kinds that CATEGORY_MAP lacks, so a
    # missing entry would detect a key and then forward it anyway.
    for kind in ADDRESS_KINDS | PUBLIC_KEY_KINDS:
        assert CATEGORY_MAP.get(kind) == "financial", kind
    for kind in SECRET_KINDS:
        assert CATEGORY_MAP.get(kind) == "private_key", kind
    every_kind = set(PATTERNS) | set(PRESIDIO_KIND_MAP.values()) | WALLET_KINDS
    assert every_kind - set(CATEGORY_MAP) == set()


PUBLISHED_ADDR = "0x52908400098527886E0F7030069857D2E4169EE7"


def test_secret_policy_keeps_keys_and_drops_addresses() -> None:
    # detect_all, not detect_regex: the overlap merge is part of the contract
    # (aws_secret_key also grabs the first 40 chars after "key ").
    spans = detect_all(f"private key {HARDHAT_0} sent from {PUBLISHED_ADDR}", use_ner=False)
    secret = {s.kind for s in filter_by_categories(spans, ["secret"])}
    pii = {s.kind for s in filter_by_categories(spans, ["pii"])}
    assert secret == {"crypto_private_key"} and pii == {"crypto_eth"}


def test_specific_label_wins_the_tie_with_generic_api_key() -> None:
    # PRIVATE_KEY=<hex> matches generic_api_key on the identical span too.
    spans = detect_all(f"PRIVATE_KEY={HARDHAT_0}", use_ner=False)
    assert [(s.kind, s.text) for s in spans] == [("crypto_private_key", HARDHAT_0)]


def test_redact_and_restore_round_trip() -> None:
    phrase = " ".join(SEED12)
    text = (
        f"Move funds from {PUBLISHED_ADDR} to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.\n"
        f"Seed: {phrase}\nkey: {HARDHAT_0}"
    )
    spans = detect_all(text, use_ner=False)
    result = redact(text, spans)
    for secret in (PUBLISHED_ADDR, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", phrase, HARDHAT_0):
        assert secret not in result.redacted_text
    assert "⟨CRYPTO_MNEMONIC_1⟩" in result.redacted_text
    assert restore(result.redacted_text, result.reverse_map) == text


def test_tendermint_armored_key_is_fully_covered() -> None:
    pem = (
        "-----BEGIN TENDERMINT PRIVATE KEY-----\nkdf: bcrypt\nsalt: 4F3A\ntype: secp256k1\n\n"
        "c2VjcmV0IGtleSBtYXRlcmlhbA==\n=n3AK\n-----END TENDERMINT PRIVATE KEY-----"
    )
    spans = [s for s in detect_regex(pem) if s.kind == "private_key_pem"]
    assert spans and spans[0].text == pem


async def test_proxy_pipeline_never_forwards_wallet_secrets() -> None:
    """End to end through Option B: what reaches the cloud, and what comes back."""
    from typing import Any
    from unittest.mock import patch

    from llm_redactor.config import Config
    from llm_redactor.pipeline.option_b import OptionBPipeline

    phrase = " ".join(SEED24)
    xprv = next(t for t, k in PUBLISHED.items() if k == "crypto_xprv")
    user = (
        f"Restore my wallet from: {phrase}\n"
        f"then sweep {xprv} to {PUBLISHED_ADDR} using PRIVATE_KEY={HARDHAT_0}"
    )
    sent: dict[str, Any] = {}

    async def fake_cloud(outgoing: dict[str, Any], *_: Any, **__: Any) -> dict[str, Any]:
        sent.update(outgoing)
        echoed = outgoing["messages"][0]["content"]  # a model that repeats the prompt
        return {"choices": [{"index": 0, "message": {"role": "assistant", "content": echoed}}]}

    cfg = Config()
    cfg.pipeline.opt_b_redact.strict = False
    with patch("llm_redactor.pipeline.option_b.forward_chat_completion", side_effect=fake_cloud):
        result = await OptionBPipeline(config=cfg, use_ner=False).run(
            {"model": "m", "messages": [{"role": "user", "content": user}]}
        )
    outgoing = sent["messages"][0]["content"]
    for secret in (phrase, xprv, PUBLISHED_ADDR, HARDHAT_0):
        assert secret not in outgoing, secret
    assert outgoing.count("⟨") == 4, outgoing
    assert result.leak_audit["original_span_text_survived"] == 0
    assert result.response["choices"][0]["message"]["content"] == user
