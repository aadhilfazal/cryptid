"""Small, explicit types shared by the search engine and CLI."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Transform:
    name: str
    data: bytes
    detail: str = ""
    family: str = "encoding"
    cost: float = 0.2


@dataclass(frozen=True)
class Step:
    name: str
    detail: str
    before: int
    after: int
    preview: str


@dataclass(frozen=True)
class Assessment:
    score: float
    kind: str
    evidence: str


@dataclass
class Candidate:
    data: bytes
    steps: tuple[Step, ...]
    assessment: Assessment
    cost: float = 0.0

    @property
    def rank(self) -> float:
        return self.assessment.score - min(0.055, self.cost * 0.003)


@dataclass
class Result:
    candidates: list[Candidate]
    status: str
    visited: int
    elapsed: float
    reason: str
    limits: list[str] = field(default_factory=list)

    @property
    def best(self) -> Candidate:
        return self.candidates[0]

