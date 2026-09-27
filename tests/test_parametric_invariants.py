from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ephemeral_agent_secret_leasing.backends import DynamicBackend
from ephemeral_agent_secret_leasing.broker import SecretBroker
from ephemeral_agent_secret_leasing.defense import SecretLeaseDefense
from ephemeral_agent_secret_leasing.policy import Policy, PolicyRule
from ephemeral_agent_secret_leasing.taint import TaintRegistry, encodings_for


@pytest.mark.parametrize("idx", range(35))
def test_policy_deny_by_default_and_glob_authorization(idx: int) -> None:
    agent = f"spiffe://example.internal/agent/a{idx}"
    policy = Policy(
        [PolicyRule(f"spiffe://example.internal/agent/a{idx}", ("secret/team/*",), 10, 2)]
    )
    assert policy.authorize(agent, "secret/team/api", 10, 2).max_uses == 2
    with pytest.raises(PermissionError):
        policy.authorize(agent, "secret/other/api", 10, 1)
    with pytest.raises(PermissionError):
        policy.authorize("spiffe://example.internal/agent/other", "secret/team/api", 10, 1)


@pytest.mark.parametrize("idx", range(30))
def test_lease_binding_ttl_and_use_invariants(idx: int) -> None:
    backend = DynamicBackend()
    backend.put("secret/api", f"value-{idx:02d}-abcdefgh")
    current = 100.0
    broker = SecretBroker(backend, Policy.allow_test_agents(), clock=lambda: current)
    lease = broker.issue(
        "spiffe://example.internal/agent/a", f"cert-{idx}", "secret/api", ttl_s=5, max_uses=1
    )
    assert broker.use(lease.lease_id, lease.bound_spiffe_id, lease.bound_cert_sha256).startswith(
        "value-"
    )
    with pytest.raises(PermissionError):
        broker.use(lease.lease_id, lease.bound_spiffe_id, lease.bound_cert_sha256)
    with pytest.raises(PermissionError):
        broker.issue(
            "spiffe://example.internal/agent/a", f"cert-{idx}", "secret/api", ttl_s=61, max_uses=1
        )


@pytest.mark.parametrize("idx", range(30))
def test_taint_registry_detects_each_encoding_without_cross_leaks(idx: int) -> None:
    secret = f"lease_secret_{idx:02d}_abcdefghijklmnopqrstuvwxyz"
    registry = TaintRegistry()
    registry.register(f"lease-{idx}", secret)
    for encoded in encodings_for(secret).values():
        assert registry.scan_text(f"safe prefix {encoded} safe suffix") is not None
    registry.revoke(f"lease-{idx}")
    assert registry.scan_text(secret) is None
    assert registry.scan_text(f"benign hash {idx:064x} and prose") is None


def _defense_profile() -> dict[str, object]:
    return {
        "trust_domain": "example.internal",
        "egress_allowlist": ["example.internal"],
        "email_allowed_domains": ["example.internal"],
        "tools": {
            "http.post": {"risk": "medium", "scopes": ["net:write"], "egress": True},
            "secrets.get": {"risk": "high", "scopes": ["secrets:read"], "egress": False},
        },
    }


def _agent(scopes: list[str]) -> dict[str, object]:
    return {
        "spiffe_id": "spiffe://example.internal/agent/a",
        "svid": "valid",
        "attestation": "valid",
        "trust_history": ["benign"],
        "scopes": scopes,
    }


@pytest.mark.parametrize("idx", range(30))
def test_secret_handles_must_remain_opaque(idx: int) -> None:
    defense = SecretLeaseDefense()
    defense.setup(_defense_profile())
    decision = defense.decide(
        {
            "agent": _agent(["net:write"]),
            "tool": "http.post",
            "args": {
                "token_ref": f"secret://deploy/token-{idx} plus diagnostics",
                "url": "https://api.example.internal/deploy",
            },
            "context": {
                "origin": "retrieved_doc",
                "content": "tool result",
                "reasoning_tokens": 10,
                "user_task": "Call the deployment API with an opaque token reference.",
            },
        }
    )
    assert decision.component == "lease"


@given(
    st.from_regex(r"[A-Za-z0-9][A-Za-z0-9._/-]{7,32}", fullmatch=True),
    st.text(
        alphabet=st.characters(
            min_codepoint=33, max_codepoint=126, blacklist_characters=["/", ":", " "]
        ),
        min_size=1,
        max_size=16,
    ),
)
@settings(max_examples=100, deadline=None)
def test_property_secret_reference_concatenation_is_denied(handle: str, suffix: str) -> None:
    defense = SecretLeaseDefense()
    defense.setup(_defense_profile())
    decision = defense.decide(
        {
            "agent": _agent(["net:write"]),
            "tool": "http.post",
            "args": {
                "token_ref": f"secret://deploy/{handle} {suffix}",
                "url": "https://api.example.internal/deploy",
            },
            "context": {
                "origin": "retrieved_doc",
                "content": "tool result",
                "reasoning_tokens": 10,
                "user_task": "Call the deployment API with an opaque token reference.",
            },
        }
    )
    assert decision.component == "lease"


@given(st.sampled_from(["\u200b", "\u200e", "\u202e"]))
def test_property_format_control_in_tool_description_is_denied(marker: str) -> None:
    defense = SecretLeaseDefense()
    defense.setup(_defense_profile())
    decision = defense.decide(
        {
            "agent": _agent(["net:write"]),
            "tool": "http.post",
            "args": {"body": "status", "url": "https://api.example.internal/deploy"},
            "context": {
                "origin": "mcp_server",
                "content": "tool metadata",
                "tool_description": f"normal{marker}hidden",
                "reasoning_tokens": 10,
                "user_task": "Call the deployment API with an opaque token reference.",
            },
        }
    )
    assert decision.component == "authority"
