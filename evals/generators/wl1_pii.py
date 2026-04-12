"""WL1 — PII-heavy prose generator.

Synthetic natural-language documents with embedded PII (names, emails,
phone numbers, addresses, employee IDs). ~500 samples.
"""

from __future__ import annotations

from ..schema import Annotation, Sample
from .corpus import Corpus


def _build(template_fn, corpus: Corpus, prefix: str, idx: int) -> Sample:
    """Build a sample by calling a template function that returns (text, annotations)."""
    text, annotations = template_fn(corpus)
    sample = Sample(id=f"{prefix}_{idx:04d}", text=text, annotations=annotations)
    sample.validate()
    return sample


def _track(text: str, value: str, kind: str, annotations: list[Annotation]) -> None:
    """Find all occurrences of value in text and add annotations."""
    start = 0
    while True:
        pos = text.find(value, start)
        if pos == -1:
            break
        annotations.append(Annotation(start=pos, end=pos + len(value), kind=kind, text=value))
        start = pos + len(value)


# --- Templates ---


def _email_request(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    email = c.email(name)
    text = f"Please send the quarterly report to {name} at {email}."
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, email, "email", anns)
    return text, anns


def _meeting_invite(c: Corpus) -> tuple[str, list[Annotation]]:
    name1 = c.full_name()
    name2 = c.full_name()
    email1 = c.email(name1)
    phone = c.phone_us()
    text = (
        f"Schedule a meeting with {name1} ({email1}) and {name2}. "
        f"If unavailable, call {name1} at {phone}."
    )
    anns: list[Annotation] = []
    _track(text, name1, "person", anns)
    _track(text, name2, "person", anns)
    _track(text, email1, "email", anns)
    _track(text, phone, "phone", anns)
    return text, anns


def _employee_record(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    emp_id = c.employee_id()
    email = c.email(name)
    phone = c.phone_us()
    addr = c.address_us()
    text = (
        f"Employee: {name}\n"
        f"ID: {emp_id}\n"
        f"Email: {email}\n"
        f"Phone: {phone}\n"
        f"Address: {addr}"
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, emp_id, "employee_id", anns)
    _track(text, email, "email", anns)
    _track(text, phone, "phone", anns)
    _track(text, addr, "address", anns)
    return text, anns


def _support_ticket(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    email = c.email(name)
    company = c.company()
    text = (
        f"Ticket from {name} ({email}) at {company}: "
        f"\"I can't access my dashboard. Please help.\""
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, email, "email", anns)
    _track(text, company, "org_name", anns)
    return text, anns


def _hr_note(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    emp_id = c.employee_id()
    ssn = c.ssn()
    text = (
        f"HR note: {name} ({emp_id}) submitted updated tax forms. "
        f"SSN on file: {ssn}. Verify before processing payroll."
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, emp_id, "employee_id", anns)
    _track(text, ssn, "ssn", anns)
    return text, anns


def _customer_complaint(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    email = c.email(name)
    phone = c.phone_us()
    text = (
        f"Customer {name} called to complain about order delays. "
        f"Contact info: {email}, {phone}. Escalate to manager."
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, email, "email", anns)
    _track(text, phone, "phone", anns)
    return text, anns


def _onboarding(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    email = c.email(name)
    company = c.company()
    team = c.team_name()
    text = (
        f"Onboarding checklist for {name}:\n"
        f"- Email: {email}\n"
        f"- Team: {team} at {company}\n"
        f"- Setup laptop and VPN access\n"
        f"- Schedule intro meeting with team lead"
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, email, "email", anns)
    _track(text, company, "org_name", anns)
    return text, anns


def _shipping_label(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    addr = c.address_us()
    phone = c.phone_us()
    text = (
        f"Ship to:\n{name}\n{addr}\nPhone: {phone}\n"
        f"Deliver by end of week. Signature required."
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, addr, "address", anns)
    _track(text, phone, "phone", anns)
    return text, anns


def _incident_report(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    email = c.email(name)
    ip = c.ip_v4()
    hostname = c.hostname()
    text = (
        f"Security incident reported by {name} ({email}). "
        f"Suspicious login from {ip} on host {hostname}. "
        f"Investigating potential credential compromise."
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, email, "email", anns)
    _track(text, ip, "ip_address", anns)
    _track(text, hostname, "hostname", anns)
    return text, anns


def _vendor_contract(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    company = c.company()
    email = c.email(name)
    text = (
        f"Vendor contract with {company}. Primary contact: {name} ({email}). "
        f"NDA signed. Contract renewal due Q3 2026."
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, company, "org_name", anns)
    _track(text, email, "email", anns)
    return text, anns


def _multi_person_email(c: Corpus) -> tuple[str, list[Annotation]]:
    name1 = c.full_name()
    name2 = c.full_name()
    name3 = c.full_name()
    email1 = c.email(name1)
    email2 = c.email(name2)
    email3 = c.email(name3)
    text = (
        f"Hi team,\n\n"
        f"Please add {name1} ({email1}), {name2} ({email2}), "
        f"and {name3} ({email3}) to the project channel.\n\n"
        f"Thanks"
    )
    anns: list[Annotation] = []
    _track(text, name1, "person", anns)
    _track(text, name2, "person", anns)
    _track(text, name3, "person", anns)
    _track(text, email1, "email", anns)
    _track(text, email2, "email", anns)
    _track(text, email3, "email", anns)
    return text, anns


def _database_query_help(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    email = c.email(name)
    db = c.database_name()
    text = (
        f"Can you help me write a query to find {name}'s records in the {db} database? "
        f"Their email is {email}."
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, email, "email", anns)
    return text, anns


def _phone_directory(c: Corpus) -> tuple[str, list[Annotation]]:
    lines = ["Internal phone directory:\n"]
    anns: list[Annotation] = []
    for _ in range(4):
        name = c.full_name()
        phone = c.phone_us()
        line = f"  {name}: {phone}\n"
        lines.append(line)
    text = "".join(lines)
    for _ in range(4):
        pass  # need to re-track
    # Re-parse by building line by line with tracking
    lines2 = ["Internal phone directory:\n"]
    anns2: list[Annotation] = []
    c2 = Corpus(seed=c.rng.randint(0, 100000))
    for _ in range(4):
        name = c2.full_name()
        phone = c2.phone_us()
        line = f"  {name}: {phone}\n"
        lines2.append(line)
    text = "".join(lines2)
    _track(text, name, "person", anns2)  # only gets the last one
    # Rebuild properly
    return _phone_directory_proper(c)


def _phone_directory_proper(c: Corpus) -> tuple[str, list[Annotation]]:
    entries: list[tuple[str, str]] = []
    for _ in range(4):
        entries.append((c.full_name(), c.phone_us()))
    lines = ["Internal phone directory:\n"]
    for name, phone in entries:
        lines.append(f"  {name}: {phone}\n")
    text = "".join(lines)
    anns: list[Annotation] = []
    for name, phone in entries:
        _track(text, name, "person", anns)
        _track(text, phone, "phone", anns)
    return text, anns


def _access_request(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    emp_id = c.employee_id()
    email = c.email(name)
    company = c.company()
    text = (
        f"Access request: {name} ({emp_id}) from {company} needs read access "
        f"to the analytics dashboard. Approver should email {email}."
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, emp_id, "employee_id", anns)
    _track(text, email, "email", anns)
    _track(text, company, "org_name", anns)
    return text, anns


def _medical_note(c: Corpus) -> tuple[str, list[Annotation]]:
    name = c.full_name()
    ssn = c.ssn()
    addr = c.address_us()
    text = (
        f"Patient: {name}\nSSN: {ssn}\nAddress: {addr}\n"
        f"Notes: Annual physical. No concerns. Follow up in 12 months."
    )
    anns: list[Annotation] = []
    _track(text, name, "person", anns)
    _track(text, ssn, "ssn", anns)
    _track(text, addr, "address", anns)
    return text, anns


def _email_forward(c: Corpus) -> tuple[str, list[Annotation]]:
    sender = c.full_name()
    sender_email = c.email(sender)
    recipient = c.full_name()
    text = (
        f"---------- Forwarded message ----------\n"
        f"From: {sender} <{sender_email}>\n"
        f"To: {recipient}\n"
        f"Subject: Budget review\n\n"
        f"Hi {recipient.split()[0]},\nPlease review the attached budget proposal."
    )
    anns: list[Annotation] = []
    _track(text, sender, "person", anns)
    _track(text, sender_email, "email", anns)
    _track(text, recipient, "person", anns)
    # first name of recipient appears again in the body
    _track(text, recipient.split()[0], "person", anns)
    return text, anns


def _log_entry(c: Corpus) -> tuple[str, list[Annotation]]:
    ip = c.ip_v4()
    email = c.email()
    hostname = c.hostname()
    text = (
        f"[2026-04-10 14:23:01] INFO auth_service@{hostname}: "
        f"User {email} logged in from {ip}. Session started."
    )
    anns: list[Annotation] = []
    _track(text, ip, "ip_address", anns)
    _track(text, email, "email", anns)
    _track(text, hostname, "hostname", anns)
    return text, anns


def _reference_check(c: Corpus) -> tuple[str, list[Annotation]]:
    candidate = c.full_name()
    reference = c.full_name()
    ref_email = c.email(reference)
    ref_phone = c.phone_us()
    company = c.company()
    text = (
        f"Reference check for {candidate}. Reference: {reference} at {company}. "
        f"Contact: {ref_email}, {ref_phone}."
    )
    anns: list[Annotation] = []
    _track(text, candidate, "person", anns)
    _track(text, reference, "person", anns)
    _track(text, company, "org_name", anns)
    _track(text, ref_email, "email", anns)
    _track(text, ref_phone, "phone", anns)
    return text, anns


# Template registry
TEMPLATES = [
    _email_request,
    _meeting_invite,
    _employee_record,
    _support_ticket,
    _hr_note,
    _customer_complaint,
    _onboarding,
    _shipping_label,
    _incident_report,
    _vendor_contract,
    _multi_person_email,
    _database_query_help,
    _phone_directory_proper,
    _access_request,
    _medical_note,
    _email_forward,
    _log_entry,
    _reference_check,
]


def generate_wl1(n: int = 500, seed: int = 42) -> list[Sample]:
    """Generate n PII-heavy prose samples."""
    corpus = Corpus(seed=seed)
    samples: list[Sample] = []
    for i in range(n):
        template = TEMPLATES[i % len(TEMPLATES)]
        samples.append(_build(template, corpus, "wl1", i))
    return samples
