from __future__ import annotations

import ast
from pathlib import Path

import pytest


def test_defense_adapter_does_not_embed_benchmark_generator_literals() -> None:
    try:
        from zero_trust_agent_benchmark.generator import literal_tokens
    except Exception:
        pytest.skip("zero-trust-agent-benchmark literal token API is optional in local unit runs")
    allowed_interface_terms = {
        "agent",
        "args",
        "attestation",
        "content",
        "deny",
        "egress",
        "identity",
        "profile",
        "scopes",
        "tool",
        "valid",
    }
    tokens = {t.lower() for t in literal_tokens() if len(t) >= 8} - allowed_interface_terms
    source = Path("src/ephemeral_agent_secret_leasing/defense.py").read_text(encoding="utf-8")
    constants = {
        node.value.lower()
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    offenders = sorted(token for token in tokens if token in constants)
    assert offenders == []
