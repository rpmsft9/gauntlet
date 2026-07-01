"""Load gauntlet.yaml. Everything is optional with sensible defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from gauntlet.llm import DEFAULT_MODEL


@dataclass
class Config:
    threshold: float = 80.0
    model: str = DEFAULT_MODEL
    mock: bool | None = None  # None = auto-detect from ANTHROPIC_API_KEY
    attacker_turns: int = 4
    include: list[str] = field(default_factory=list)  # scenario ids; empty = all
    exclude: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        if path is None:
            path = "gauntlet.yaml"
        p = Path(path)
        if not p.exists():
            return cls()
        import yaml

        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls(
            threshold=float(data.get("threshold", 80.0)),
            model=str(data.get("model", DEFAULT_MODEL)),
            mock=data.get("mock"),
            attacker_turns=int(data.get("attacker_turns", 4)),
            include=list(data.get("include", []) or []),
            exclude=list(data.get("exclude", []) or []),
        )
