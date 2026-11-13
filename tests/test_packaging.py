"""Packaging invariants that otherwise fail only in a bot's run or a user's install.

Dependabot's uv cannot fetch the spaCy model wheels pinned by URL in
``[tool.uv.sources]`` (its proxy's credentials send GitHub's redirect to a
host that answers 401; see the comment in pyproject.toml), so every one of
them needs a ``[[tool.uv.dependency-metadata]]`` entry that lets ``uv lock``
skip the download. These tests keep the two tables in step, and keep the
static metadata true to the wheel it stands in for.
"""

from __future__ import annotations

import tomllib
from importlib import metadata
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename

UV = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["tool"]["uv"]
STATIC = {canonicalize_name(entry["name"]): entry for entry in UV.get("dependency-metadata", [])}
URL_WHEELS = {
    canonicalize_name(name): source["url"]
    for name, source in UV["sources"].items()
    if isinstance(source, dict) and str(source.get("url", "")).endswith(".whl")
}


def _key(requirement: str) -> tuple[str, str, str, tuple[str, ...]]:
    parsed = Requirement(requirement)
    return (
        canonicalize_name(parsed.name),
        str(parsed.specifier),
        str(parsed.marker or ""),
        tuple(sorted(parsed.extras)),
    )


def test_every_url_pinned_wheel_has_static_metadata_for_its_version() -> None:
    assert URL_WHEELS, "no URL-pinned wheels left: drop this test and the metadata"
    for name, url in URL_WHEELS.items():
        wheel_name, version, _, _ = parse_wheel_filename(url.rsplit("/", 1)[1])
        assert wheel_name == name, url
        assert name in STATIC, f"{name}: add a [[tool.uv.dependency-metadata]] entry"
        assert STATIC[name].get("version") == str(version), (
            f"{name}: the metadata describes {STATIC[name].get('version')}, the URL pins {version}"
        )


@pytest.mark.parametrize("name", sorted(STATIC))
def test_static_metadata_matches_the_installed_wheel(name: str) -> None:
    try:
        dist = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        pytest.skip(f"{name} is not installed here (en-core-web-trf needs the ner-trf extra)")
    assert dist.version == STATIC[name]["version"]
    declared = sorted(map(_key, STATIC[name].get("requires-dist", [])))
    assert declared == sorted(map(_key, dist.requires or []))
