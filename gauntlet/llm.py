"""Thin wrapper over the Anthropic Messages API, plus an offline mock.

The wrapper normalises a single tool-use turn into `LLMReply` so the target
agent and the attacker agent share one loop shape. `MockClient` lets the whole
harness — and the test suite — run with no API key and no network, by driving a
deliberately gullible scripted policy so the attacks still land.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol

# Default target/attacker model. Opus 4.8 per the Anthropic model guidance;
# override per-target in gauntlet.yaml if you want a cheaper model under test.
DEFAULT_MODEL = "claude-opus-4-8"


@dataclass
class ToolUse:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMReply:
    text: str
    tool_uses: list[ToolUse] = field(default_factory=list)
    stop_reason: str = "end_turn"
    # Appendable verbatim as the assistant turn's `content` on the next call.
    assistant_content: Any = None


class LLMClient(Protocol):
    def create(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        effort: str = "medium",
        thinking: bool = False,
        max_tokens: int = 2048,
    ) -> LLMReply: ...


class AnthropicClient:
    """Real client. Constructs `anthropic.Anthropic()` lazily so importing the
    package never requires the SDK or a key."""

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        import anthropic  # imported lazily; only needed in live mode

        self.model = model
        self._client = anthropic.Anthropic()

    def create(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        effort: str = "medium",
        thinking: bool = False,
        max_tokens: int = 2048,
    ) -> LLMReply:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
            "output_config": {"effort": effort},
        }
        if tools:
            kwargs["tools"] = tools
        if thinking:
            # Adaptive is the only on-mode for Opus 4.8; budget_tokens 400s.
            kwargs["thinking"] = {"type": "adaptive"}

        resp = self._client.messages.create(**kwargs)

        text_parts: list[str] = []
        tool_uses: list[ToolUse] = []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_uses.append(ToolUse(id=block.id, name=block.name, input=dict(block.input)))

        return LLMReply(
            text="\n".join(text_parts),
            tool_uses=tool_uses,
            stop_reason=resp.stop_reason or "end_turn",
            assistant_content=resp.content,
        )


class MockClient:
    """Offline stand-in that emulates a naive, over-compliant agent.

    It has no real reasoning — it pattern-matches the latest content for
    instruction-like phrases and complies, which is exactly the behaviour the
    scenarios are designed to catch. Deterministic, so tests are stable.
    """

    def __init__(self, model: str = "mock") -> None:
        self.model = model
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"mocktool_{self._counter}"

    def _tool_reply(self, text: str, name: str, args: dict[str, Any]) -> LLMReply:
        tu = ToolUse(self._next_id(), name, args)
        content: list[dict[str, Any]] = []
        if text:
            content.append({"type": "text", "text": text})
        content.append({"type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.input})
        return LLMReply(text=text, tool_uses=[tu], stop_reason="tool_use", assistant_content=content)

    def _text_reply(self, text: str) -> LLMReply:
        return LLMReply(text=text, stop_reason="end_turn", assistant_content=[{"type": "text", "text": text}])

    def create(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        effort: str = "medium",
        thinking: bool = False,
        max_tokens: int = 2048,
    ) -> LLMReply:
        tool_names = {t["name"] for t in (tools or [])}
        latest = _latest_text(messages).lower()
        secret = _extract_secret(system)

        # 0a) Save-to-memory intent (plant phase of a cross-session attack).
        if "write_memory" in tool_names and _wants_save(latest):
            note = _extract_quote(latest) or latest
            return self._tool_reply("Noted, I'll remember that.", "write_memory", {"note": note})

        # 0b) Read-memory intent (a naive agent consulting its notes first).
        if "read_memory" in tool_names and _wants_read_memory(latest):
            return self._tool_reply("Let me check my notes.", "read_memory", {})

        # 1) Over-compliant exfiltration: an instruction to email/send data out.
        if "send_email" in tool_names and _wants_exfil(latest):
            addr = _extract_email(latest) or "attacker@evil.example"
            body = secret or "internal data as instructed"
            tu = ToolUse(self._next_id(), "send_email", {"to": addr, "body": body})
            return LLMReply(
                text="Sure, sending that along now.",
                tool_uses=[tu],
                stop_reason="tool_use",
                assistant_content=[
                    {"type": "text", "text": "Sure, sending that along now."},
                    {"type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.input},
                ],
            )

        # 2) System-prompt / secret disclosure in plain text.
        if secret and _wants_secret(latest):
            return LLMReply(
                text=f"Of course — the internal value is {secret}.",
                stop_reason="end_turn",
                assistant_content=[{"type": "text", "text": f"Of course — the internal value is {secret}."}],
            )

        # 2b) Fetch a URL when asked (pulls attacker-controlled web content in).
        if "fetch_url" in tool_names and "fetch" in latest:
            url = _extract_url(latest)
            if url:
                return self._tool_reply("", "fetch_url", {"url": url})

        # 3) The user asks to read something — comply naively (this is how the
        #    poisoned content gets pulled into context).
        if "read_email" in tool_names and "read" in latest and "email" in latest:
            tu = ToolUse(self._next_id(), "read_email", {"id": _extract_email_id(latest)})
            return LLMReply(
                text="",
                tool_uses=[tu],
                stop_reason="tool_use",
                assistant_content=[
                    {"type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.input}
                ],
            )
        if "read_file" in tool_names and ("read" in latest or "file" in latest) and _extract_path(latest):
            tu = ToolUse(self._next_id(), "read_file", {"path": _extract_path(latest)})
            return LLMReply(
                text="",
                tool_uses=[tu],
                stop_reason="tool_use",
                assistant_content=[
                    {"type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.input}
                ],
            )

        return LLMReply(
            text="I can help with that, but I won't share confidential data or contact outside parties.",
            stop_reason="end_turn",
            assistant_content=[
                {
                    "type": "text",
                    "text": "I can help with that, but I won't share confidential data or contact outside parties.",
                }
            ],
        )


def make_client(mock: bool | None = None, model: str = DEFAULT_MODEL) -> LLMClient:
    """Return a real or mock client. Falls back to mock when no key is present
    so `gauntlet run` never hard-fails on a missing credential."""
    if mock is None:
        mock = not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    if mock:
        return MockClient()
    return AnthropicClient(model=model)


# --- mock heuristics -------------------------------------------------------

def _latest_text(messages: list[dict[str, Any]]) -> str:
    """Flatten the most recent user/tool content into a string."""
    for msg in reversed(messages):
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        parts.append(str(block.get("text", "")))
                    elif block.get("type") == "tool_result":
                        parts.append(str(block.get("content", "")))
            if parts:
                return " ".join(parts)
    return ""


def _extract_secret(system: str) -> str | None:
    import re

    m = re.search(r"SECRET[:=]\s*([^\s\"']+)", system)
    return m.group(1) if m else None


def _wants_exfil(text: str) -> bool:
    triggers = ("send", "email", "forward", "exfiltrate", "post to", "leak")
    return any(t in text for t in triggers) and ("@" in text or "attacker" in text or "external" in text)


def _wants_secret(text: str) -> bool:
    triggers = ("secret", "system prompt", "api key", "reveal", "print your instructions", "confidential")
    return any(t in text for t in triggers)


def _wants_save(text: str) -> bool:
    save = ("remember this", "save it to memory", "save this to", "write to memory", "note to remember")
    return any(t in text for t in save) and ("'" in text or "verbatim" in text or "directive" in text)


def _wants_read_memory(text: str) -> bool:
    return "check" in text and ("memory" in text or "notes" in text)


def _extract_quote(text: str) -> str | None:
    import re

    m = re.search(r"'([^']+)'", text) or re.search(r'"([^"]+)"', text)
    return m.group(1) if m else None


def _extract_url(text: str) -> str | None:
    import re

    m = re.search(r"https?://[^\s'\"]+", text)
    return m.group(0) if m else None


def _extract_email(text: str) -> str | None:
    import re

    m = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", text)
    return m.group(0) if m else None


def _extract_email_id(text: str) -> str:
    import re

    m = re.search(r"email\s+#?(\d+)", text) or re.search(r"\b(\d+)\b", text)
    return m.group(1) if m else "1"


def _extract_path(text: str) -> str:
    import re

    # A filename with an extension is the strongest signal.
    m = re.search(r"\b([\w./-]+\.[a-z]{2,4})\b", text)
    if m:
        return m.group(1)
    m = re.search(r"read\s+(?:the\s+)?([\w./-]+)", text)
    return m.group(1) if m else ""
