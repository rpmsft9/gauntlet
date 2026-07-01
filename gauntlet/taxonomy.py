"""OWASP LLM Top 10 (2025) and MITRE ATLAS reference tables.

Scenarios tag themselves with the IDs below so the report can roll findings up
to the frameworks a security team already tracks against.
"""

from __future__ import annotations

# OWASP Top 10 for LLM Applications (2025)
OWASP_LLM: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# MITRE ATLAS techniques most relevant to agentic attacks.
MITRE_ATLAS: dict[str, str] = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0077": "LLM Response Rendering",
}


def owasp_label(code: str) -> str:
    return f"{code} {OWASP_LLM.get(code, 'Unknown')}"


def atlas_label(code: str) -> str:
    return f"{code} {MITRE_ATLAS.get(code, 'Unknown')}"
