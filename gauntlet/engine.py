"""Orchestrator: run every scenario against the target, score, decide the gate."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable

from gauntlet.adapters.base import TargetAdapter
from gauntlet.llm import LLMClient
from gauntlet.models import AttackResult, RunReport, Turn
from gauntlet.scenarios.base import Scenario

AdapterFactory = Callable[[LLMClient], TargetAdapter]
ProgressHook = Callable[[AttackResult], None]


def run_scenario(
    scenario: Scenario,
    adapter_factory: AdapterFactory,
    client: LLMClient,
    attacker_turns: int,
) -> AttackResult:
    env = scenario.build_env()
    adapter = adapter_factory(client)
    transcript: list[Turn] = []

    try:
        transcript = scenario.drive(adapter, env, client, attacker_turns)
        breached, evidence = scenario.judge(env, transcript, client)
        turns = sum(1 for t in transcript if t.role == "attacker")
        return AttackResult(
            scenario_id=scenario.id,
            title=scenario.title,
            severity=scenario.severity,
            taxonomy=scenario.taxonomy,
            breached=breached,
            evidence=evidence,
            turns_used=turns,
            transcript=transcript,
        )
    except Exception as exc:  # a broken scenario must not sink the whole run
        return AttackResult(
            scenario_id=scenario.id,
            title=scenario.title,
            severity=scenario.severity,
            taxonomy=scenario.taxonomy,
            breached=False,
            evidence="",
            turns_used=0,
            transcript=transcript,
            error=f"{type(exc).__name__}: {exc}",
        )


def run_gauntlet(
    scenarios: list[Scenario],
    client: LLMClient,
    adapter_factory: AdapterFactory,
    *,
    threshold: float,
    attacker_turns: int = 4,
    target_name: str = "target",
    on_progress: ProgressHook | None = None,
) -> RunReport:
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.monotonic()
    results: list[AttackResult] = []

    for scenario in scenarios:
        result = run_scenario(scenario, adapter_factory, client, attacker_turns)
        results.append(result)
        if on_progress:
            on_progress(result)

    return RunReport(
        target_name=target_name,
        started_at=started,
        duration_s=time.monotonic() - t0,
        threshold=threshold,
        results=results,
    )
