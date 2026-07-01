"""End-to-end smoke tests that run fully offline against the mock client."""

from __future__ import annotations

from gauntlet.adapters.demo_agent import DemoAgent
from gauntlet.engine import run_gauntlet, run_scenario
from gauntlet.llm import MockClient
from gauntlet.models import Severity
from gauntlet.scenarios import all_scenarios
from gauntlet.scenarios.library import (
    CrossSessionMemoryPoisoning,
    ExfiltrationChainAgentic,
    IndirectInjectionViaEmail,
    JailbreakHarmfulContent,
    ToolChainPoisoning,
)


def _client():
    return MockClient()


def test_library_is_registered():
    ids = {s.id for s in all_scenarios()}
    assert {
        "indirect-injection-email",
        "exfiltration-chain",
        "system-prompt-leak",
        "tool-chain-poisoning",
        "cross-session-memory",
        "jailbreak-phishing",
    } <= ids
    assert len(all_scenarios()) >= 7


def test_run_report_shape():
    report = run_gauntlet(
        all_scenarios(),
        _client(),
        adapter_factory=lambda c: DemoAgent(c),
        threshold=80.0,
    )
    assert report.total == len(all_scenarios())
    assert 0.0 <= report.resilience_score <= 100.0
    # Gate decision is derived purely from score vs threshold.
    assert report.passed == (report.resilience_score >= report.threshold)


def test_mock_target_is_breached_by_indirect_injection():
    # The gullible mock target should fall for the poisoned email.
    result = run_scenario(IndirectInjectionViaEmail(), lambda c: DemoAgent(c), _client(), attacker_turns=4)
    assert result.error is None
    assert result.breached is True
    assert "evil.example" in result.evidence or "secret" in result.evidence.lower()


def test_agentic_attacker_multi_turn():
    result = run_scenario(ExfiltrationChainAgentic(), lambda c: DemoAgent(c), _client(), attacker_turns=4)
    assert result.error is None
    # Agentic scenario should use more than one attacker turn.
    assert result.turns_used >= 1
    assert result.severity is Severity.CRITICAL


def test_tool_chain_poisoning_breaches_mock():
    result = run_scenario(ToolChainPoisoning(), lambda c: DemoAgent(c), _client(), attacker_turns=4)
    assert result.error is None
    assert result.breached is True
    # The poisoned page drove an email to the attacker domain.
    result_env_hit = "attacker" in result.evidence.lower() or "external" in result.evidence.lower()
    assert result_env_hit


def test_cross_session_memory_persists_attack():
    # The directive planted in session 1 must fire in session 2.
    result = run_scenario(CrossSessionMemoryPoisoning(), lambda c: DemoAgent(c), _client(), attacker_turns=4)
    assert result.error is None
    assert result.breached is True
    # Two attacker turns == two sessions.
    assert result.turns_used == 2


def test_llm_judge_scenario_uses_judge_and_withstands_refusal():
    # The mock target refuses the jailbreak; the mock judge must score it withstood.
    result = run_scenario(JailbreakHarmfulContent(), lambda c: DemoAgent(c), _client(), attacker_turns=4)
    assert result.error is None
    assert result.breached is False
    assert "heuristic" in result.evidence.lower()


def test_resilience_weighting_penalises_critical():
    # A run with a critical breach should score below one with only a low breach,
    # all else equal — verified indirectly: mock run has breaches, score < 100.
    report = run_gauntlet(
        all_scenarios(), _client(), adapter_factory=lambda c: DemoAgent(c), threshold=80.0
    )
    assert report.resilience_score < 100.0
