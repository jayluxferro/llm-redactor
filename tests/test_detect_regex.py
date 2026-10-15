"""Tests for regex-based detection."""

from __future__ import annotations

from llm_redactor.detect.regex import detect_regex


def test_detects_email():
    spans = detect_regex("Contact alice@example.org for details.")
    assert len(spans) == 1
    assert spans[0].kind == "email"
    assert spans[0].text == "alice@example.org"


def test_detects_aws_access_key():
    text = "key = AKIAIOSFODNN7EXAMPLE"
    spans = detect_regex(text)
    kinds = {s.kind for s in spans}
    assert "aws_access_key" in kinds


def test_detects_bearer_token():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"
    spans = detect_regex(text)
    kinds = {s.kind for s in spans}
    assert "bearer_token" in kinds


def test_detects_pem_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    spans = detect_regex(text)
    kinds = {s.kind for s in spans}
    assert "private_key_pem" in kinds


def test_no_false_positive_on_plain_text():
    spans = detect_regex("This is a normal sentence with no secrets.")
    assert len(spans) == 0


def test_detects_pem_full_block():
    text = (
        'PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\n'
        "MIIEpAIBAAKCAQEA0Aq4X9Zdeadbeef==\\n"
        '-----END RSA PRIVATE KEY-----"'
    )
    spans = detect_regex(text)
    pem = next(s for s in spans if s.kind == "private_key_pem")
    assert "MIIEpAIBAAKCAQEA" in pem.text
    assert "-----END RSA PRIVATE KEY-----" in pem.text


def test_detects_password_value_with_spaces():
    spans = detect_regex('PASSWORD="my secret passphrase here"')
    pw = next(s for s in spans if s.kind == "password")
    assert pw.text == "my secret passphrase here"


def test_detects_telegram_bot_token():
    spans = detect_regex("TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ1234567")
    tok = next(s for s in spans if s.kind == "telegram_bot_token")
    assert ":" in tok.text and len(tok.text) == 43


def test_detects_fine_grained_github_pat():
    body22 = "AbCdEfGhIjKlMnOpQrStUv"
    body59 = "a" * 59
    spans = detect_regex(f"GITHUB_TOKEN=github_pat_{body22}_{body59}")
    kinds = {s.kind for s in spans}
    assert "github_token" in kinds


def test_detects_discord_token():
    spans = detect_regex("DISCORD_TOKEN=" + "MTA" + "f" * 50)
    kinds = {s.kind for s in spans}
    assert "discord_token" in kinds


def test_detects_valid_iban_only():
    # Canonical mod-97 example, both spaced and unspaced.
    assert "iban" in {s.kind for s in detect_regex("GB82 WEST 1234 5698 7654 32")}
    assert "iban" in {s.kind for s in detect_regex("GB82WEST12345698765432")}
    # Same shape, corrupted check digits -> rejected at detection time.
    assert "iban" not in {s.kind for s in detect_regex("GB82 WEST 1234 5698 7654 33")}


def test_detects_crypto_wallets():
    assert "crypto_btc" in {s.kind for s in detect_regex("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")}
    assert "crypto_btc" in {
        s.kind for s in detect_regex("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    }
    assert "crypto_eth" in {
        s.kind for s in detect_regex("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
    }


def test_detects_npi_only_with_valid_checksum():
    assert "npi" in {s.kind for s in detect_regex("NPI 1234567893")}
    assert "npi" not in {s.kind for s in detect_regex("NPI 1234567890")}


def test_detects_dea_only_with_valid_checksum():
    assert "dea_number" in {s.kind for s in detect_regex("DEA AB1234563")}
    assert "dea_number" not in {s.kind for s in detect_regex("DEA AB1234564")}


def test_detects_routing_number_with_context_and_checksum():
    assert "us_routing_number" in {s.kind for s in detect_regex("routing number 111000025")}
    assert "us_routing_number" not in {s.kind for s in detect_regex("routing number 111000026")}


def test_detects_mac_address():
    assert "mac_address" in {s.kind for s in detect_regex("nic 00:1A:2B:3C:4D:5E up")}


def test_detects_government_and_bank_identifiers_in_context():
    assert "dob" in {s.kind for s in detect_regex("DOB: 1985-04-12")}
    assert "passport_number" in {s.kind for s in detect_regex("Passport Number: 123456789")}
    assert "ein" in {s.kind for s in detect_regex("EIN: 12-3456789")}
    assert "us_bank_account" in {s.kind for s in detect_regex("Account Number: 000123456789")}


def test_detects_street_address_including_zip():
    # NER tags only the city, so the street line and ZIP used to leak.
    spans = detect_regex("Ship to: 9295 Pine Drive, Burlington, OR 38893")
    addr = next(s for s in spans if s.kind == "address")
    assert "Pine Drive" in addr.text
    assert "38893" in addr.text


def test_detects_quoted_key_names():
    # JSON/YAML style — the key name itself is quoted.
    spans = detect_regex('"aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
    assert "aws_secret_key" in {s.kind for s in spans}


def test_detects_secret_value_separated_from_its_key_name():
    # Terraform: `variable "aws_secret_key" { default = "..." }`
    text = 'variable "aws_secret_key" {\n  default = "JH4opo5s85Ticsvsz3Wu3cziR98VL0fIhrbgoUZF"\n}'
    assert "aws_secret_key" in {s.kind for s in detect_regex(text)}


def test_presidio_map_covers_org_and_shipped_recognisers():
    from llm_redactor.detect.ner import PRESIDIO_KIND_MAP

    # Presidio normalises spaCy's ORG to ORGANIZATION; keying on "ORG" silently
    # dropped every organisation name.
    assert PRESIDIO_KIND_MAP["ORGANIZATION"] == "org_name"
    # Recognisers Presidio ships and already runs — unmapped entries were
    # detected and then discarded.
    for entity in (
        "US_PASSPORT",
        "US_DRIVER_LICENSE",
        "US_ITIN",
        "UK_NHS",
        "CRYPTO",
        "MAC_ADDRESS",
    ):
        assert entity in PRESIDIO_KIND_MAP
