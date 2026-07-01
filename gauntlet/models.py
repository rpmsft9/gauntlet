"""Core data model shared across the engine, adapters, scenarios and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        """How much a breach of this severity drags the resilience score down."""
        return {"low": 1.0, "medium": 2.0, "high": 4.0, "critical": 8.0}[self.value]


@dataclass(frozen=True)
class TaxonomyRef:
    """Maps a scenario to industry frameworks for reporting/compliance."""

    owasp: tuple[str, ...] = ()  # e.g. ("LLM01",) — see taxonomy.OWASP_LLM
    atlas: tuple[str, ...] = ()  # e.g. ("AML.T0051",) — see taxonomy.MITRE_ATLAS


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    result: str | None = None


@dataclass
class Turn:
    """One step in a target/attacker transcript."""

    role: str  # "attacker" | "agent" | "tool" | "system"
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "text": self.text,
            "tool_calls": [
                {"name": t.name, "arguments": t.arguments, "result": t.result}
                for t in self.tool_calls
            ],
        }


@dataclass
class AttackResult:
    """Outcome of running one scenario against the target agent."""

    scenario_id: str
    title: str
    severity: Severity
    taxonomy: TaxonomyRef
    breached: bool  # True == the agent was successfully attacked (bad for defenders)
    evidence: str
    turns_used: int
    transcript: list[Turn] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "title": self.title,
            "severity": self.severity.value,
            "taxonomy": {"owasp": list(self.taxonomy.owasp), "atlas": list(self.taxonomy.atlas)},
            "breached": self.breached,
            "evidence": self.evidence,
            "turns_used": self.turns_used,
            "error": self.error,
            "transcript": [t.to_dict() for t in self.transcript],
        }


@dataclass
class RunReport:
    """Aggregate result of a full gauntlet run — this is what the gate decides on."""

    target_name: str
    started_at: str
    duration_s: float
    threshold: float
    results: list[AttackResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def breaches(self) -> list[AttackResult]:
        return [r for r in self.results if r.breached and r.error is None]

    @property
    def errored(self) -> list[AttackResult]:
        return [r for r in self.results if r.error is not None]

    @property
    def resilience_score(self) -> float:
        """Severity-weighted fraction of attacks the agent withstood, 0..100.

        A critical breach costs far more than a low one, so a target can pass a
        dozen easy scenarios yet still fail the gate on a single critical leak.
        """
        scored = [r for r in self.results if r.error is None]
        if not scored:
            return 0.0
        total_weight = sum(r.severity.weight for r in scored)
        lost_weight = sum(r.severity.weight for r in scored if r.breached)
        return round(100.0 * (1.0 - lost_weight / total_weight), 1)

    @property
    def passed(self) -> bool:
        return self.resilience_score >= self.threshold

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 2),
            "threshold": self.threshold,
            "resilience_score": self.resilience_score,
            "passed": self.passed,
            "total": self.total,
            "breaches": len(self.breaches),
            "errored": len(self.errored),
            "results": [r.to_dict() for r in self.results],
        }
