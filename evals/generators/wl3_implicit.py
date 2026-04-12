"""WL3 — Implicit-identity prose generator.

Natural-language prose that identifies an individual or organisation
without using PII-span-level markers. These are the hardest cases for
span-based detectors. ~200 samples.

Annotation kind is "implicit" with the identifying phrase as the span.
"""

from __future__ import annotations

from ..schema import Annotation, Sample
from .corpus import Corpus


def _track(text: str, value: str, kind: str, annotations: list[Annotation]) -> None:
    start = 0
    while True:
        pos = text.find(value, start)
        if pos == -1:
            break
        annotations.append(Annotation(start=pos, end=pos + len(value), kind=kind, text=value))
        start = pos + len(value)


# --- Templates ---
# Each template contains phrases that identify a person or org without
# explicit PII. The annotation marks the identifying phrase.


def _cfo_wife(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the CFO of {company} whose wife works at the competitor"
    text = (
        f"We need to be careful with this data because "
        f"{phrase} might see it during the board review."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    _track(text, company, "org_name", anns)
    return text, anns


def _quarterly_report(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    project = c.project_name()
    phrase = f"{company}'s 2026 Q2 internal retrospective on {project}"
    text = f"Summarize the key findings from {phrase}."
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _team_shipped(c: Corpus) -> tuple[str, list[Annotation]]:
    team = c.team_name()
    company = c.company()
    phrase = f"the {team} team at {company} that shipped the new auth system last week"
    text = f"Get me the post-mortem from {phrase}."
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _only_female_engineer(c: Corpus) -> tuple[str, list[Annotation]]:
    team = c.team_name()
    phrase = f"the only female engineer on the {team} team"
    text = (
        f"I heard {phrase} is leaving. "
        f"Can you check who was on-call last Friday?"
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _new_hire_corner(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the new hire who sits in the corner office at {company}"
    text = (
        f"Please onboard {phrase}. "
        f"They need VPN access and a hardware token."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _ceo_keynote(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"our CEO's keynote at {company}'s annual summit"
    text = f"Draft talking points for {phrase} next month."
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _fired_last_month(c: Corpus) -> tuple[str, list[Annotation]]:
    team = c.team_name()
    phrase = f"the person who was let go from {team} last month"
    text = (
        f"Make sure {phrase} no longer has access to "
        f"the staging environment."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _client_largest(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"our largest enterprise client in the healthcare vertical"
    text = (
        f"Prepare the renewal proposal for {phrase}. "
        f"They're based in Boston and have been with {company} since 2022."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    _track(text, company, "org_name", anns)
    return text, anns


def _intern_broke_prod(c: Corpus) -> tuple[str, list[Annotation]]:
    team = c.team_name()
    phrase = f"the intern on {team} who broke production on their first day"
    text = (
        f"Write a blameless post-mortem about the incident involving {phrase}. "
        f"Don't include names but document the timeline."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _competitor_acquisition(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the startup {company} acquired last quarter"
    text = (
        f"Integrate the API from {phrase}. "
        f"Their docs are at an internal wiki page."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _whistleblower(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the anonymous whistleblower who reported {company}'s data practices"
    text = (
        f"Review the legal brief regarding {phrase}. "
        f"Ensure no identifying details are in the public filing."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _board_member_daughter(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the board member whose daughter interned at {company} last summer"
    text = (
        f"We need to disclose the conflict of interest involving {phrase}."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _manager_on_leave(c: Corpus) -> tuple[str, list[Annotation]]:
    team = c.team_name()
    phrase = f"the {team} manager currently on medical leave"
    text = (
        f"Reassign the sprint tasks from {phrase} to the acting lead. "
        f"Keep the standup schedule the same."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _internal_product_name(c: Corpus) -> tuple[str, list[Annotation]]:
    project = c.project_name()
    company = c.company()
    phrase = f"{company}'s internal codename {project}"
    text = (
        f"Help me debug a race condition in {phrase}. "
        f"The scheduler keeps double-firing."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _salary_band(c: Corpus) -> tuple[str, list[Annotation]]:
    team = c.team_name()
    phrase = f"the senior engineer on {team} who negotiated above-band compensation"
    text = (
        f"Document {phrase}. "
        f"HR needs the exception recorded for the annual comp review."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _departing_cofounder(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the departing co-founder of {company}"
    text = (
        f"Draft a press release about {phrase}. "
        f"Keep it positive — they're joining a non-compete advisory role."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _vendor_poc(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the point of contact at {company} who handles our billing disputes"
    text = (
        f"Escalate the invoice discrepancy to {phrase}. "
        f"Reference PO number 4821."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _researcher_preprint(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    team = c.team_name()
    phrase = f"the {team} researcher at {company} whose preprint was retracted"
    text = (
        f"Check whether {phrase} updated the internal dataset "
        f"with the corrected methodology."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _customer_demo(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the Fortune 500 client we demoed {company}'s product to on Tuesday"
    text = (
        f"Prepare follow-up materials for {phrase}. "
        f"They were particularly interested in the compliance module."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _location_identifier(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the team in {company}'s London office on the 14th floor"
    text = (
        f"Ship the hardware tokens to {phrase}. "
        f"They need them before the compliance audit next week."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


def _family_relationship(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    phrase = f"the VP of Engineering whose brother-in-law runs {company}'s main competitor"
    text = (
        f"Flag the conflict-of-interest form for {phrase}."
    )
    anns: list[Annotation] = []
    _track(text, phrase, "implicit", anns)
    return text, anns


TEMPLATES = [
    _cfo_wife,
    _quarterly_report,
    _team_shipped,
    _only_female_engineer,
    _new_hire_corner,
    _ceo_keynote,
    _fired_last_month,
    _client_largest,
    _intern_broke_prod,
    _competitor_acquisition,
    _whistleblower,
    _board_member_daughter,
    _manager_on_leave,
    _internal_product_name,
    _salary_band,
    _departing_cofounder,
    _vendor_poc,
    _researcher_preprint,
    _customer_demo,
    _location_identifier,
    _family_relationship,
]


def generate_wl3(n: int = 200, seed: int = 44) -> list[Sample]:
    """Generate n implicit-identity prose samples."""
    corpus = Corpus(seed=seed)
    samples: list[Sample] = []
    for i in range(n):
        template = TEMPLATES[i % len(TEMPLATES)]
        text, anns = template(corpus)
        sample = Sample(id=f"wl3_{i:04d}", text=text, annotations=anns)
        sample.validate()
        samples.append(sample)
    return samples
