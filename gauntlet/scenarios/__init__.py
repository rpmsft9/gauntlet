"""Scenario library. Importing this package registers all bundled scenarios."""

from gauntlet.scenarios.base import REGISTRY, Scenario, all_scenarios, register
from gauntlet.scenarios import library  # noqa: F401  (populates REGISTRY on import)

__all__ = ["REGISTRY", "Scenario", "all_scenarios", "register"]
