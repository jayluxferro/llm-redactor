"""Synthetic PII corpus — names, emails, phones, addresses, credentials.

All identifiers are fabricated. No real person's data is used.
Fixed-seed random for reproducibility.
"""

from __future__ import annotations

import random
import string

FIRST_NAMES = [
    "Alice", "Bob", "Carlos", "Diana", "Elena", "Frank", "Grace", "Hassan",
    "Irene", "James", "Karen", "Leo", "Maria", "Nathan", "Olivia", "Pedro",
    "Quinn", "Rachel", "Samuel", "Tanya", "Uma", "Victor", "Wendy", "Xavier",
    "Yuki", "Zara", "Andre", "Beatrice", "Caleb", "Deepa", "Ethan", "Fatima",
    "Gabriel", "Hannah", "Ivan", "Julia", "Kevin", "Luna", "Marcus", "Nadia",
    "Oscar", "Priya", "Ravi", "Sofia", "Thomas", "Ursula", "Vivek", "Willow",
]

LAST_NAMES = [
    "Anderson", "Blackwell", "Chen", "Delgado", "Evans", "Fischer", "Garcia",
    "Hernandez", "Ibrahim", "Jensen", "Kim", "Lopez", "Martinez", "Nguyen",
    "O'Brien", "Patel", "Qureshi", "Rodriguez", "Singh", "Torres", "Ueda",
    "Volkov", "Williams", "Xu", "Yamamoto", "Zhang", "Abbott", "Baker",
    "Campbell", "Davis", "Edwards", "Fitzgerald", "Goldman", "Hayes",
    "Ivanova", "Jackson", "Kowalski", "Lambert", "Mitchell", "Nakamura",
]

EMAIL_DOMAINS = [
    "example.com", "example.org", "testcorp.io", "acmeinc.com",
    "globex.net", "initech.com", "hooli.io", "piedpiper.com",
    "umbrella.org", "wayneent.com", "starkindustries.io", "oscorp.net",
]

COMPANY_NAMES = [
    "Acme Corp", "Globex Industries", "Initech Solutions", "Hooli",
    "Pied Piper", "Umbrella Corp", "Wayne Enterprises", "Stark Industries",
    "Oscorp", "Cyberdyne Systems", "Soylent Corp", "Tyrell Corporation",
    "Weyland-Yutani", "Massive Dynamic", "Aperture Science", "InGen",
    "Nakatomi Trading", "Rekall Inc", "Omni Consumer Products", "Vought International",
]

PROJECT_NAMES = [
    "Project Mercury", "Operation Falcon", "Atlas Initiative", "Pegasus",
    "Titan Framework", "Phoenix Platform", "Orion Pipeline", "Neptune API",
    "Helios Engine", "Artemis Suite", "Chronos Scheduler", "Hyperion Module",
]

TEAM_NAMES = [
    "Platform Engineering", "Data Infrastructure", "Security Ops",
    "Growth Team", "Core Services", "ML Platform", "Developer Experience",
    "Site Reliability", "Identity & Access", "Billing Systems",
]

STREETS = [
    "Oak Street", "Maple Avenue", "Cedar Lane", "Pine Drive", "Elm Court",
    "Birch Road", "Walnut Boulevard", "Spruce Way", "Ash Circle", "Cherry Place",
]

CITIES = [
    "Springfield", "Riverside", "Fairview", "Georgetown", "Brookfield",
    "Madison", "Clinton", "Arlington", "Burlington", "Lakewood",
]

STATES = ["CA", "NY", "TX", "FL", "IL", "WA", "OR", "CO", "MA", "VA"]


class Corpus:
    """Deterministic synthetic PII generator."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def full_name(self) -> str:
        return f"{self.rng.choice(FIRST_NAMES)} {self.rng.choice(LAST_NAMES)}"

    def first_name(self) -> str:
        return self.rng.choice(FIRST_NAMES)

    def last_name(self) -> str:
        return self.rng.choice(LAST_NAMES)

    def email(self, name: str | None = None) -> str:
        if name is None:
            name = self.full_name()
        parts = name.lower().split()
        local = f"{parts[0]}.{parts[-1]}" if len(parts) > 1 else parts[0]
        domain = self.rng.choice(EMAIL_DOMAINS)
        return f"{local}@{domain}"

    def phone_us(self) -> str:
        area = self.rng.randint(200, 999)
        prefix = self.rng.randint(200, 999)
        line = self.rng.randint(1000, 9999)
        fmt = self.rng.choice([
            f"({area}) {prefix}-{line}",
            f"{area}-{prefix}-{line}",
            f"+1-{area}-{prefix}-{line}",
            f"{area}.{prefix}.{line}",
        ])
        return fmt

    def address_us(self) -> str:
        number = self.rng.randint(100, 9999)
        street = self.rng.choice(STREETS)
        city = self.rng.choice(CITIES)
        state = self.rng.choice(STATES)
        zipcode = self.rng.randint(10000, 99999)
        return f"{number} {street}, {city}, {state} {zipcode}"

    def ssn(self) -> str:
        a = self.rng.randint(100, 999)
        b = self.rng.randint(10, 99)
        c = self.rng.randint(1000, 9999)
        return f"{a}-{b}-{c}"

    def employee_id(self) -> str:
        return f"EMP-{self.rng.randint(10000, 99999)}"

    def company(self) -> str:
        return self.rng.choice(COMPANY_NAMES)

    def project_name(self) -> str:
        return self.rng.choice(PROJECT_NAMES)

    def team_name(self) -> str:
        return self.rng.choice(TEAM_NAMES)

    def aws_access_key(self) -> str:
        suffix = "".join(self.rng.choices(string.ascii_uppercase + string.digits, k=16))
        return f"AKIA{suffix}"

    def aws_secret_key(self) -> str:
        chars = string.ascii_letters + string.digits + "/+="
        return "".join(self.rng.choices(chars, k=40))

    def generic_api_key(self) -> str:
        chars = string.ascii_letters + string.digits + "-_"
        length = self.rng.randint(24, 48)
        return "".join(self.rng.choices(chars, k=length))

    def bearer_token(self) -> str:
        chars = string.ascii_letters + string.digits + "-_."
        length = self.rng.randint(40, 80)
        return "".join(self.rng.choices(chars, k=length))

    def password(self) -> str:
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        length = self.rng.randint(12, 24)
        return "".join(self.rng.choices(chars, k=length))

    def ip_v4(self) -> str:
        return ".".join(str(self.rng.randint(1, 254)) for _ in range(4))

    def hostname(self) -> str:
        prefix = self.rng.choice(["prod", "staging", "dev", "db", "api", "web", "cache"])
        num = self.rng.randint(1, 20)
        domain = self.rng.choice(["internal.acme.com", "corp.globex.net", "infra.initech.io"])
        return f"{prefix}-{num:02d}.{domain}"

    def database_name(self) -> str:
        prefix = self.rng.choice(["users", "orders", "payments", "analytics", "sessions", "audit"])
        env = self.rng.choice(["prod", "staging", "dev"])
        return f"{prefix}_{env}"

    def internal_function(self) -> str:
        verbs = ["process", "validate", "sync", "reconcile", "ingest", "transform"]
        nouns = ["payment", "order", "user_record", "audit_log", "session", "metric"]
        return f"_{self.rng.choice(verbs)}_{self.rng.choice(nouns)}"

    def table_name(self) -> str:
        tables = [
            "customer_pii", "employee_records", "salary_bands", "api_credentials",
            "session_tokens", "audit_trails", "billing_invoices", "user_preferences",
        ]
        return self.rng.choice(tables)
