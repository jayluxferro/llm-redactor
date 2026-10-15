"""Pure checksum/shape validators shared by detection and rule validation.

Both :func:`llm_redactor.detect.regex.detect_regex` (detection-time filtering
of checksummed kinds) and :mod:`llm_redactor.detect.rules_validator` (the
deterministic ``rules`` validation backend) need the same arithmetic, so it
lives here exactly once — two copies of a checksum would eventually disagree,
and the weaker copy wins.

Dependency-free by design: importing a detector from here would invert the
layering (both callers import *this* module, never the reverse).
"""

from __future__ import annotations


def digits_only(text: str) -> str:
    """Strip every non-digit (spaces, dashes, dots, parentheses)."""
    return "".join(c for c in text if c.isdigit())


def luhn(digits: str) -> bool:
    """Luhn checksum (ISO/IEC 7812-1)."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        # Double every second digit counting from the rightmost.
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def credit_card(text: str) -> bool:
    d = digits_only(text)
    return 13 <= len(d) <= 19 and luhn(d)


def iban(text: str) -> bool:
    """ISO 13616 mod-97 check: move the leading country+check digits to the
    end, map letters to 10-35, and require the whole number ≡ 1 (mod 97)."""
    s = text.replace(" ", "").replace("-", "").upper()
    if len(s) < 15 or len(s) > 34 or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    value = 0
    for ch in s[4:] + s[:4]:
        if ch.isdigit():
            value = value * 10 + int(ch)
        elif "A" <= ch <= "Z":
            value = value * 100 + (ord(ch) - ord("A") + 10)
        else:
            return False
        # Keep the running modulus small — same result as one big mod at the end.
        value %= 97
    return value % 97 == 1


def npi(text: str) -> bool:
    """US National Provider Identifier.

    10 digits whose trailing check digit is Luhn over the 15-digit string
    ``80840`` + NPI (ISO 7812 issuer prefix 80840 marks US healthcare).
    """
    d = digits_only(text)
    return len(d) == 10 and luhn("80840" + d)


# Registrant-type letters that may begin a DEA number.  I, O, Y and Z are
# never issued, so excluding them removes a slice of false positives for free.
_DEA_FIRST_LETTERS = frozenset("ABCDEFGHJKLMNPRSTUX")


def dea_number(text: str) -> bool:
    """DEA registration number: 2 letters + 7 digits, mod-10 check digit.

    Check digit = last digit of (sum of odd-positioned digits) +
    2 x (sum of even-positioned digits) over the 7-digit tail.
    """
    s = text.strip().upper()
    if len(s) != 9 or not s[:2].isalpha() or not s[2:].isdigit():
        return False
    if s[0] not in _DEA_FIRST_LETTERS:
        return False
    d = s[2:]
    odd = int(d[0]) + int(d[2]) + int(d[4])
    even = int(d[1]) + int(d[3]) + int(d[5])
    return (odd + 2 * even) % 10 == int(d[6])


def _aba_prefix_ok(prefix: str) -> bool:
    """ABA routing prefixes actually assigned to institutions."""
    n = int(prefix)
    return n <= 12 or 21 <= n <= 32 or 61 <= n <= 72 or n == 80


def us_routing_number(text: str) -> bool:
    """US ABA routing transit number: 9 digits, 3-7-1 weighted checksum."""
    d = digits_only(text)
    if len(d) != 9 or not _aba_prefix_ok(d[:2]):
        return False
    checksum = (
        3 * (int(d[0]) + int(d[3]) + int(d[6]))
        + 7 * (int(d[1]) + int(d[4]) + int(d[7]))
        + (int(d[2]) + int(d[5]) + int(d[8]))
    )
    return checksum % 10 == 0
