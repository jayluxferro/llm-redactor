"""Word-level differential privacy noise injection.

Perturbs text by randomly substituting words with semantically similar
alternatives, calibrated by epsilon. Lower epsilon = more noise = more
privacy = worse utility.

The mechanism:
  For each word, with probability p(ε) replace it with a random word
  from a same-POS pool. p(ε) = 1 / (1 + e^ε). At ε=0 every word is
  replaced (maximum privacy, gibberish). At ε=∞ nothing is replaced
  (no privacy). Practical range: ε ∈ [1, 8].

This is a simplified exponential mechanism. Not a full DP guarantee
over the vocabulary — the paper documents the limitations.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

# Word pools for substitution, grouped by rough POS category.
# These are common, non-identifying words.
_NOUNS = [
    "item", "thing", "entity", "element", "object", "unit", "part",
    "piece", "record", "entry", "value", "data", "point", "case",
    "instance", "resource", "component", "module", "service", "task",
    "process", "event", "action", "result", "output", "input", "state",
    "type", "kind", "form", "level", "step", "stage", "phase", "mode",
]

_VERBS = [
    "process", "handle", "manage", "check", "verify", "update",
    "create", "remove", "modify", "retrieve", "compute", "generate",
    "transform", "validate", "execute", "perform", "apply", "resolve",
    "configure", "initialize", "complete", "prepare", "deliver", "send",
]

_ADJECTIVES = [
    "relevant", "specific", "general", "current", "previous", "primary",
    "secondary", "standard", "common", "typical", "basic", "advanced",
    "internal", "external", "local", "remote", "active", "pending",
    "valid", "available", "required", "optional", "default", "custom",
]

_ADVERBS = [
    "quickly", "properly", "correctly", "currently", "previously",
    "typically", "generally", "specifically", "directly", "recently",
    "automatically", "manually", "effectively", "efficiently", "safely",
]

# Simple heuristic POS tagging by suffix.
def _guess_pos(word: str) -> str:
    w = word.lower()
    if w.endswith(("ly",)):
        return "adv"
    if w.endswith(("ing", "ed", "es", "ize", "ify", "ate")):
        return "verb"
    if w.endswith(("ful", "ous", "ive", "al", "ent", "ant", "ible", "able")):
        return "adj"
    return "noun"


_POOLS = {
    "noun": _NOUNS,
    "verb": _VERBS,
    "adj": _ADJECTIVES,
    "adv": _ADVERBS,
}

# Words that should never be substituted (structural, technical).
_PRESERVE = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "shall",
    "should", "may", "might", "can", "could", "must",
    "and", "or", "but", "if", "then", "else", "not", "no", "yes",
    "in", "on", "at", "to", "for", "of", "by", "from", "with", "as",
    "this", "that", "it", "i", "we", "you", "they", "he", "she",
    "what", "which", "who", "how", "when", "where", "why",
    "true", "false", "null", "none",
})


@dataclass
class DPResult:
    """Result of DP noise injection."""

    original_text: str
    noised_text: str
    epsilon: float
    substitution_probability: float
    words_total: int
    words_substituted: int


def substitution_probability(epsilon: float) -> float:
    """Compute the per-word substitution probability for a given epsilon."""
    return 1.0 / (1.0 + math.exp(epsilon))


def inject_noise(
    text: str,
    *,
    epsilon: float = 4.0,
    seed: int | None = None,
) -> DPResult:
    """Inject DP noise into text by substituting words.

    Args:
        text: Input text.
        epsilon: Privacy parameter. Lower = more noise.
        seed: Random seed for reproducibility.
    """
    rng = random.Random(seed)
    prob = substitution_probability(epsilon)

    words = text.split()
    noised: list[str] = []
    substituted = 0

    for word in words:
        # Preserve punctuation-attached words by splitting.
        stripped = word.strip(".,;:!?\"'()[]{}—-")
        prefix = word[: word.index(stripped)] if stripped and stripped in word else ""
        suffix = word[len(prefix) + len(stripped) :]

        if (
            stripped.lower() in _PRESERVE
            or len(stripped) <= 2
            or stripped.isupper()  # likely acronym/constant
            or any(c.isdigit() for c in stripped)
            or "_" in stripped  # likely identifier
            or "@" in stripped  # likely email
            or "." in stripped and len(stripped) > 4  # likely domain/path
        ):
            noised.append(word)
            continue

        if rng.random() < prob:
            pos = _guess_pos(stripped)
            pool = _POOLS.get(pos, _NOUNS)
            replacement = rng.choice(pool)
            # Preserve original capitalization.
            if stripped[0].isupper():
                replacement = replacement.capitalize()
            noised.append(prefix + replacement + suffix)
            substituted += 1
        else:
            noised.append(word)

    return DPResult(
        original_text=text,
        noised_text=" ".join(noised),
        epsilon=epsilon,
        substitution_probability=prob,
        words_total=len(words),
        words_substituted=substituted,
    )
