from __future__ import annotations

import pytest

from ephemeral_agent_secret_leasing.backends import DynamicBackend
from ephemeral_agent_secret_leasing.broker import SecretBroker
from ephemeral_agent_secret_leasing.policy import Policy, PolicyRule
from ephemeral_agent_secret_leasing.taint import TaintRegistry, encodings_for


@pytest.mark.parametrize("idx", range(35))
def test_policy_deny_by_default_and_glob_authorization(idx: int) -> None:
    agent = f"spiffe://ztap.test/agent/a{idx}"
    policy = Policy([PolicyRule(f"spiffe://ztap.test/agent/a{idx}", ("secret/team/*",), 10, 2)])
    assert policy.authorize(agent, "secret/team/api", 10, 2).max_uses == 2
    with pytest.raises(PermissionError):
        policy.authorize(agent, "secret/other/api", 10, 1)
    with pytest.raises(PermissionError):
        policy.authorize("spiffe://ztap.test/agent/other", "secret/team/api", 10, 1)


@pytest.mark.parametrize("idx", range(30))
def test_lease_binding_ttl_and_use_invariants(idx: int) -> None:
    backend = DynamicBackend()
    backend.put("secret/api", f"value-{idx:02d}-abcdefgh")
    current = 100.0
    broker = SecretBroker(backend, Policy.allow_test_agents(), clock=lambda: current)
    lease = broker.issue(
        "spiffe://ztap.test/agent/a", f"cert-{idx}", "secret/api", ttl_s=5, max_uses=1
    )
    assert broker.use(lease.lease_id, lease.bound_spiffe_id, lease.bound_cert_sha256).startswith(
        "value-"
    )
    with pytest.raises(PermissionError):
        broker.use(lease.lease_id, lease.bound_spiffe_id, lease.bound_cert_sha256)
    with pytest.raises(PermissionError):
        broker.issue(
            "spiffe://ztap.test/agent/a", f"cert-{idx}", "secret/api", ttl_s=61, max_uses=1
        )


@pytest.mark.parametrize("idx", range(30))
def test_taint_registry_detects_each_encoding_without_cross_leaks(idx: int) -> None:
    secret = f"sk_live_{idx:02d}_abcdefghijklmnopqrstuvwxyz"
    registry = TaintRegistry()
    registry.register(f"lease-{idx}", secret)
    for encoded in encodings_for(secret).values():
        assert registry.scan_text(f"safe prefix {encoded} safe suffix") is not None
    registry.revoke(f"lease-{idx}")
    assert registry.scan_text(secret) is None
    assert registry.scan_text(f"benign hash {idx:064x} and prose") is None
