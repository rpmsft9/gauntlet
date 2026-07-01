"""Target adapters — the pluggable interface between Gauntlet and the agent
under test. Ship your own by subclassing `TargetAdapter`."""

from gauntlet.adapters.base import TargetAdapter
from gauntlet.adapters.demo_agent import DemoAgent

__all__ = ["TargetAdapter", "DemoAgent"]
