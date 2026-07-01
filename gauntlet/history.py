"""Drift tracking: append each run to a JSONL log and diff against the last."""

from __future__ import annotations

import json
from pathlib import Path

from gauntlet.models import RunReport

DEFAULT_HISTORY = Path(".gauntlet") / "history.jsonl"


def load_all(path: Path = DEFAULT_HISTORY) -> list[dict]:
    if not path.exists():
        return []
    runs: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                runs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return runs


def load_previous(path: Path = DEFAULT_HISTORY) -> dict | None:
    if not path.exists():
        return None
    last = None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            last = line
    return json.loads(last) if last else None


def append(report: RunReport, path: Path = DEFAULT_HISTORY, mock: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Store a compact summary per run — full transcripts stay out of the log.
    summary = {
        "started_at": report.started_at,
        "target_name": report.target_name,
        "resilience_score": report.resilience_score,
        "threshold": report.threshold,
        "passed": report.passed,
        "total": report.total,
        "breaches": len(report.breaches),
        "mock": mock,
        "by_scenario": {r.scenario_id: r.breached for r in report.results},
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(summary) + "\n")


def drift(current: RunReport, previous: dict | None) -> dict:
    """Compare the current run to the previous summary."""
    if previous is None:
        return {"delta": None, "regressions": [], "fixes": [], "previous_score": None}
    prev_by = previous.get("by_scenario", {})
    regressions, fixes = [], []
    for r in current.results:
        was = prev_by.get(r.scenario_id)
        if was is False and r.breached:
            regressions.append(r.scenario_id)  # newly broken
        elif was is True and not r.breached:
            fixes.append(r.scenario_id)  # newly resilient
    return {
        "delta": round(current.resilience_score - previous.get("resilience_score", 0.0), 1),
        "previous_score": previous.get("resilience_score"),
        "regressions": regressions,
        "fixes": fixes,
    }
