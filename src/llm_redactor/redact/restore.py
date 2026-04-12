"""Response-path restoration: substitute placeholders back to originals."""

from __future__ import annotations


def restore(text: str, reverse_map: dict[str, str]) -> str:
    """Replace placeholders in the response with their original values.

    Only exact matches are substituted. If the cloud model paraphrased
    a placeholder (e.g. dropped the brackets), we leave it alone — that
    is the safe behaviour.
    """
    result = text
    for placeholder, original in reverse_map.items():
        result = result.replace(placeholder, original)
    return result
