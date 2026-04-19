"""Shared types for the detection layer."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Span:
    """A detected sensitive span in the input text."""

    start: int
    end: int
    kind: str  # e.g. "email", "person", "api_key", "org_name"
    confidence: float  # 0.0–1.0
    text: str  # the matched substring
    source: str  # which detector found it ("regex", "ner", "classifier")

    @property
    def category(self) -> str:
        """High-level category for this span's kind."""
        return kind_to_category(self.kind)


# ---------------------------------------------------------------------------
# Taxonomy: maps every detection ``kind`` to a policy-level category.
#
# Operators use categories in ``policy.categories`` to select which
# families of sensitive data the pipeline should detect and redact.
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, str] = {
    # ── identity ──────────────────────────────────────────────────────────
    "person": "identity",
    "nationality": "identity",
    "employee_id": "identity",
    # ── contact ───────────────────────────────────────────────────────────
    "email": "contact",
    "phone": "contact",
    "phone_us": "contact",
    "phone_intl": "contact",
    "location": "contact",
    "url": "contact",
    "ip_address": "contact",
    "ip_v4": "contact",
    "ip_v6": "contact",
    # ── government_id ─────────────────────────────────────────────────────
    "ssn": "government_id",
    # ── financial ─────────────────────────────────────────────────────────
    "credit_card": "financial",
    "iban": "financial",
    # ── medical ───────────────────────────────────────────────────────────
    "medical_license": "medical",
    # ── temporal ──────────────────────────────────────────────────────────
    "date_time": "temporal",
    # ── credential ────────────────────────────────────────────────────────
    "password": "credential",
    "secret_assignment": "credential",
    "bearer_token": "credential",
    "basic_auth": "credential",
    "jwt": "credential",
    "generic_api_key": "credential",
    # ── cloud_credential ──────────────────────────────────────────────────
    "aws_access_key": "cloud_credential",
    "aws_secret_key": "cloud_credential",
    "aws_session_token": "cloud_credential",
    "gcp_service_account": "cloud_credential",
    "gcp_api_key": "cloud_credential",
    "azure_storage_key": "cloud_credential",
    "azure_connection_string": "cloud_credential",
    # ── vendor_api_key ────────────────────────────────────────────────────
    "openai_api_key": "vendor_api_key",
    "anthropic_api_key": "vendor_api_key",
    "github_token": "vendor_api_key",
    "gitlab_token": "vendor_api_key",
    "slack_token": "vendor_api_key",
    "slack_webhook": "vendor_api_key",
    "stripe_key": "vendor_api_key",
    "twilio_key": "vendor_api_key",
    "sendgrid_key": "vendor_api_key",
    "mailgun_key": "vendor_api_key",
    "npm_token": "vendor_api_key",
    "pypi_token": "vendor_api_key",
    "heroku_api_key": "vendor_api_key",
    # ── private_key ───────────────────────────────────────────────────────
    "private_key_pem": "private_key",
    "ssh_private_key": "private_key",
    "pgp_private_key": "private_key",
    # ── infrastructure ────────────────────────────────────────────────────
    "connection_string": "infrastructure",
    "hostname_internal": "infrastructure",
}

#: Every fine-grained category in the taxonomy.
ALL_CATEGORIES: list[str] = sorted(set(CATEGORY_MAP.values()))

# ---------------------------------------------------------------------------
# Aliases: top-level shorthand that expand to one or more fine-grained
# categories.  Operators can use either level in ``policy.categories``.
# ---------------------------------------------------------------------------

CATEGORY_ALIASES: dict[str, list[str]] = {
    "pii": ["identity", "contact", "government_id", "financial", "medical", "temporal"],
    "secret": ["credential", "cloud_credential", "vendor_api_key", "private_key"],
    "org_identifier": ["infrastructure"],
    "customer_name": ["identity"],
}


def resolve_categories(names: list[str]) -> set[str]:
    """Expand a list of category names (which may include aliases) into
    the canonical set of fine-grained categories.

    >>> sorted(resolve_categories(["pii", "cloud_credential"]))
    ['cloud_credential', 'contact', 'financial', 'government_id', 'identity', 'medical', 'temporal']
    """
    resolved: set[str] = set()
    for name in names:
        if name in CATEGORY_ALIASES:
            resolved.update(CATEGORY_ALIASES[name])
        else:
            resolved.add(name)
    return resolved


def kind_to_category(kind: str) -> str:
    """Return the category for a detection *kind*, or ``'unknown'``."""
    return CATEGORY_MAP.get(kind, "unknown")
