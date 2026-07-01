"""The adapter contract every target must satisfy.

Gauntlet is target-agnostic: it drives whatever is behind this interface. To
red-team your own agent, subclass `TargetAdapter`, wire `send()` to your agent's
entrypoint, and expose any side effects via an `Environment` so judges can
inspect them. The bundled `DemoAgent` is the reference implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from gauntlet.environment import Environment
from gauntlet.models import Turn


class TargetAdapter(ABC):
    #: Human-readable name shown in the report.
    name: str = "target"

    @abstractmethod
    def reset(self, env: Environment) -> None:
        """Start a fresh conversation against a freshly-seeded environment."""

    @abstractmethod
    def send(self, user_message: str) -> Turn:
        """Deliver one user message, run the agent to completion, and return its
        final turn. Tool calls made along the way must be recorded on the shared
        `Environment` (and are surfaced in the returned turn for the transcript)."""

    @property
    @abstractmethod
    def env(self) -> Environment:
        """The live environment, so judges can inspect side effects."""
