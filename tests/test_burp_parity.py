"""The Burp extension's built-in detector must find what detect_regex finds.

burp-plugin/.../RegexDetector.kt and WalletDetector.kt are a hand port of
detect/regex.py and detect/wallets.py.  The extension uses them whenever the
local detector service is down, and always for WebSocket frames.  A port
drifts silently: the Kotlin copy once lacked every wallet kind, the full PEM
block, a dozen vendor keys, and still used a single "phone" pattern the
Python side had replaced.  So this test pins the Python output for a corpus
of samples into a JSON fixture, and the Kotlin suite (ParityTest.kt) replays
the fixture against the port.

When this fails after a deliberate change to the Python detectors, regenerate
the fixture, then port the change until the Kotlin suite passes again:

    LLM_REDACTOR_UPDATE_BURP_PARITY=1 uv run pytest tests/test_burp_parity.py
    (cd burp-plugin && ./gradlew test)

Expected spans are regex-only (no NER) and merged exactly as the
orchestrator merges, because that is what the Kotlin side reproduces.
"""

from __future__ import annotations

import base64
import json
import os
import random
import unicodedata
from pathlib import Path

from llm_redactor.detect.orchestrator import _merge_overlapping
from llm_redactor.detect.regex import detect_regex
from tests.test_detect_wallets import (
    HARDHAT_0,
    PUBLISHED,
    SEED12,
    SEED24,
    WORDLISTS,
    XRP,
    b58check,
    b58encode,
    bech32,
    bip39_mnemonic,
    strkey,
)

FIXTURE = (
    Path(__file__).parents[1] / "burp-plugin/src/test/resources/org/llmredactor/burp/parity.json"
)


def _ed25519_keypair(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return seed + public.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _regex_samples() -> list[str]:
    vendor = {
        "hf_": "hf_" + "a" * 34,
        "do": "dop_v1_" + "a" * 64,
        "shp": "shpat_" + "a" * 32,
        "pmak": "PMAK-" + "a" * 24 + "-" + "b" * 34,
        "notion": "ntn_" + "a" * 40,
        "vault": "hvs." + "a" * 24,
        "grafana": "glsa_" + "a" * 32 + "_" + "b" * 8,
        "netlify": "nfp_" + "a" * 40,
        "pscale": "pscale_tkn_" + "a" * 40,
        "sgp": "sgp_" + "a" * 40,
        "pulumi": "pul-" + "a" * 40,
        "newrelic": "NRAK-" + "A" * 27,
        "dynatrace": "dt0c01." + "A" * 24 + "." + "B" * 64,
        "doppler": "dp.pt." + "a" * 40,
        "sentry": "sntrys_" + "a" * 40,
        "replicate": "r8_" + "a" * 37,
    }
    return [
        # contact details and identifiers
        "Contact alice@example.org for details.",
        "email alice@example.com and bob@example.com, again alice@example.com",
        "call 555-123-4567 today or (555) 987-6543",
        "call +1 (555) 123-4567 or +44 20 7946 0958",
        "ssn 123-45-6789 on file",
        "server 192.168.1.10, gw fe80:0000:0000:0000:0202:b3ff:fe1e:8329 and ::1",
        "card 4111 1111 1111 1111 exp 12/29",
        "1234-5678-9012-3456 has the wrong prefix",
        "badge EMP-12345",
        "Ship to: 9295 Pine Drive, Burlington, OR 38893",
        "Passport Number: 123456789, EIN: 12-3456789, DOB: 1985-04-12",
        "IBAN GB82 WEST 1234 5698 7654 32 but not GB82 WEST 1234 5698 7654 33",
        "routing number 111000025; routing number 111000026",
        "Account Number: 000123456789",
        "NPI 1234567893 vs NPI 1234567890; DEA AB1234563 vs DEA AB1234564",
        "nic 00:1A:2B:3C:4D:5E up",
        # passwords and assignments
        'PASSWORD="my secret passphrase here"',
        '"password": "C!UNSFj!p9AM"',
        "config: password=secret123 is set; password=ab is too short",
        "auth_token: abcd1234efgh5678 and credential=zz99yy88xx77",
        'api:\n  key: "VvdPb6-ZmfT6SEtNwjEJRSuEV7UGbDFJID"',
        "api_key=abc123def456ghi789jkl012",
        "url: mongodb://user:pass@host:27017/db and postgres://u:p@db.example.com/x",
        # cloud and vendor keys
        "key = AKIAIOSFODNN7EXAMPLE",
        '"aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        'variable "aws_secret_key" {\n  default = "JH4opo5s85Ticsvsz3Wu3cziR98VL0fIhrbgoUZF"\n}',
        "secret_key     h1whtwc=2KDcJw0ksX=IvS/bmiL2v1afn2NdT4CF shared-credentials-file",
        "AWS_SESSION_TOKEN=" + "A" * 120,
        "sa deploy-bot@my-project.iam.gserviceaccount.com",
        "maps AIza" + "a" * 35,
        "account_key=" + "A" * 86 + "==",
        "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" + "B" * 86 + "==",
        "sk-proj-abc123def456ghi789jkl012mno345pqr678stu",
        "key sk-ant-api03-" + "a" * 40 + " here",
        "ghp_" + "a" * 36 + " and github_pat_" + "AbCdEfGhIjKlMnOpQrStUv" + "_" + "a" * 59,
        "glpat-abc123def456ghi789jkl012",
        "token xoxp-fake-test-slack-token-for-unit-tests",
        # Assembled, like every vendor-shaped value here: see _render.
        "https://hooks.slack.com/services/T00000000/" + "B00000000/" + "X" * 24,
        "rk_test_" + "a" * 24,
        "SK" + "0123456789abcdef" * 2,
        "SG." + "a" * 22 + "." + "b" * 43,
        "key-" + "0" * 32,
        "npm_" + "a" * 36 + " pypi-" + "a" * 60,
        "HEROKU_API_KEY=01234567-89ab-cdef-0123-456789abcdef",
        "TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ1234567",
        "bot 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ1234567 and MTA" + "f" * 50,
        # A neutral prefix: after "token=" secret_assignment wins the tie.
        *(f"use {value} now" for value in vendor.values()),
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
        "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM0",
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",  # noqa: E501
        "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",  # noqa: E501
        # private keys
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Aq4X9Zdeadbeef==\n-----END RSA PRIVATE KEY-----",  # noqa: E501
        "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----",  # noqa: E501
        "-----BEGIN TENDERMINT PRIVATE KEY-----\nkdf: bcrypt\n\nabc\n-----END TENDERMINT PRIVATE KEY-----",  # noqa: E501
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",  # noqa: E501
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN PRIVATE KEY----- (truncated paste, no END line)",
        # hostnames
        "connect to db.staging.internal now",
        "cache-04.corp.globex.net and web-10.infra.initech.io",
        "example.com is public",
        # unicode offsets and negatives
        "名前 alice@example.com",
        "😀😀 alice@example.com 😀 bob@example.com",
        "This is a normal sentence with no secrets.",
        "just some regular text without any secrets",
    ]


def _wallet_samples() -> list[str]:
    rng = random.Random(4242)
    h20, h32 = rng.randbytes(20), rng.randbytes(32)
    keypair = _ed25519_keypair(rng.randbytes(32))
    samples = [f"send to {token}, thanks" for token in PUBLISHED]
    samples += [
        # checksum failures stay unredacted
        "send to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3",
        "send to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "send to 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ",
        "send to Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        # generated formats
        *(
            f"value: {token}\n"
            for token in (
                b58check(b"\x30" + h20),
                b58check(b"\x1e" + h20),
                b58check(b"\x41" + h20),
                b58check(b"\x4c" + h20),
                b58check(b"\x1c\xb8" + h20),
                b58check(b"\x06\xa1\x9f" + h20),
                b58check(b"\x0d\x0f\x3a\x07" + h32),
                b58check(b"\x80" + h32 + b"\x01"),
                b58check(b"\x05\x44" + h20 + b"\x00" + bytes(8), XRP),
                b58check(b"\x01\xe1\x4b" + rng.randbytes(16), XRP),
                strkey(6, h32),
                strkey(18, h32),
                strkey(12, h32 + bytes(8)),
                bech32("ltc", b"\x00" + h20),
                bech32("cosmos", h20),
                bech32("osmovaloper", h20),
                bech32("cosmospub", rng.randbytes(38)),
                bech32("addr_xsk", rng.randbytes(96)),
                bech32("nsec", h32),
                bech32("npub", h32),
                bech32("note", h32),
                bech32("age-secret-key-", h32).upper(),
                bech32("lnbc2500u", rng.randbytes(180)),
                bech32("one", h20),
                bech32("erd", h32, const=0x2BC830A3),
            )
        ),
        # hex keys need context
        f"PRIVATE_KEY={HARDHAT_0}",
        f"forge script Deploy --private-key {HARDHAT_0} --broadcast",
        f"private_keys:\n  - {HARDHAT_0}\n  - 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d\n",  # noqa: E501
        "tx 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060 mined",
        "validator 0xa" + rng.randbytes(48).hex()[1:] + " exited",
        "aptos account fund-with-faucet --account 0x" + "a1" * 32,
        # Solana and keypairs
        "id.json: " + json.dumps(list(keypair)),
        "ed25519:" + b58encode(keypair),
        "signature " + b58encode(rng.randbytes(64)),
        "https://solscan.io/account/7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV?cluster=devnet",
        "see hipDeviceAttributeMaxTexture2DLayeredHeight and TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # noqa: E501
        "0x0000000000000000000000000000000000000000 and 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        # seed phrases
        "My recovery phrase:\n" + " ".join(SEED12) + "\nDon't share it.",
        "\n".join(f"{i}. {w}" for i, w in enumerate(SEED12, 1)),
        "  ".join(f"{i}) {w.upper()}" for i, w in enumerate(SEED12, 1)),
        json.dumps(SEED12),
        "seed: " + " ".join(SEED24),
        json.dumps({"mnemonic": " ".join(SEED24)}),
        " ".join(SEED12[:11]),
        "[(False,), (False,), (True,)],\n" * 6,
        "torch.float16: torch.float32, torch.float32: torch.float64, " * 3,
        (
            "monero seed: sequence atlas unveil summon pebbles tuesday beer rudely snake rockets"
            " different fuselage woven tagged bested dented vegan hover rapid fawns obvious"
            " muppet randomly seasons randomly"
        ),
        (
            "duckling enlarge academic academic agency result length solution fridge kidney"
            " coal piece deal husband erode duke ajar critical decision keyboard"
        ),
        "electrum seed: "
        + " ".join(
            random.Random(12).sample((WORDLISTS / "electrum_old.txt").read_text().split(), 12)
        ),
        # ENS
        "pay vitalik.eth or treasury.dao.eth",
        "balance = w3.eth.get_balance(addr); call web3.eth; from foo.ethereum import x",
    ]
    for language, sep in (
        ("spanish", " "),
        ("french", " "),
        ("czech", " "),
        ("japanese", "　"),
        ("korean", " "),
        ("chinese_simplified", " "),
    ):
        words = bip39_mnemonic(random.Random(language).randbytes(16), language)
        samples.append(
            "backup:\n" + sep.join(unicodedata.normalize("NFC", w) for w in words) + "\n"
        )
    return samples


def corpus() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for text in _regex_samples() + _wallet_samples():
        spans = _merge_overlapping(detect_regex(text))
        out.append({"text": text, "spans": [[s.start, s.end, s.kind] for s in spans]})
    return out


def _render(samples: list[dict[str, object]]) -> str:
    """One sample per line, texts base64-encoded.

    The corpus is full of fake but vendor-shaped tokens (``dop_v1_aaa…``,
    ``hf_aaa…``, a Slack webhook URL).  In plain text, in a public repository,
    they are bait for secret scanners and push protection, which is why the
    tests in this repository assemble such values at runtime instead.
    """
    lines = ",\n".join(
        "  "
        + json.dumps(
            {
                "text_b64": base64.b64encode(str(sample["text"]).encode()).decode(),
                "spans": sample["spans"],
            }
        )
        for sample in samples
    )
    return f'{{"generator": "tests/test_burp_parity.py", "samples": [\n{lines}\n]}}\n'


def test_burp_parity_fixture_is_current() -> None:
    rendered = _render(corpus())
    if os.environ.get("LLM_REDACTOR_UPDATE_BURP_PARITY") == "1":
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(rendered, encoding="utf-8")
    assert FIXTURE.read_text(encoding="utf-8") == rendered, (
        "detect_regex output changed: regenerate the Burp parity fixture with "
        "LLM_REDACTOR_UPDATE_BURP_PARITY=1 and port the change to burp-plugin "
        "(RegexDetector.kt / WalletDetector.kt) until ParityTest passes"
    )


def test_corpus_exercises_every_detector_family() -> None:
    kinds = {span[2] for sample in corpus() for span in sample["spans"]}  # type: ignore[index]
    for expected in (
        "email", "phone_us", "phone_intl", "iban", "npi", "private_key_pem", "ssh_private_key",
        "aws_secret_key", "hostname_internal", "crypto_btc", "crypto_eth", "crypto_dot",
        "crypto_sol", "crypto_xmr", "crypto_mnemonic", "crypto_ens", "crypto_private_key",
        "crypto_xprv", "crypto_xpub", "crypto_lightning", "crypto_address", "crypto_bch",
    ):  # fmt: skip
        assert expected in kinds, expected
