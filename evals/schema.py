"""Shared types for workload samples and annotations."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Annotation:
    """A ground-truth sensitive span in a sample."""

    start: int
    end: int
    kind: str  # e.g. "email", "person", "api_key", "org_name", "implicit"
    text: str


@dataclass(slots=True)
class Sample:
    """A single workload sample with ground-truth annotations."""

    id: str
    text: str
    annotations: list[Annotation]

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Sample:
        return cls(
            id=d["id"],
            text=d["text"],
            annotations=[Annotation(**a) for a in d["annotations"]],
        )

    def validate(self) -> None:
        """Check that all annotations point to the correct text."""
        for ann in self.annotations:
            actual = self.text[ann.start : ann.end]
            if actual != ann.text:
                raise ValueError(
                    f"Sample {self.id}: annotation {ann.kind} at "
                    f"[{ann.start}:{ann.end}] expected {ann.text!r}, "
                    f"got {actual!r}"
                )


def write_workload(samples: list[Sample], path: Path) -> None:
    """Write samples to a JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for sample in samples:
            sample.validate()
            f.write(json.dumps(sample.to_dict()) + "\n")


def read_workload(path: Path) -> list[Sample]:
    """Read samples from a JSONL file."""
    samples = []
    with open(path) as f:
        for line in f:
            if line.strip():
                samples.append(Sample.from_dict(json.loads(line)))
    return samples
