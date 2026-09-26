from __future__ import annotations

from starlette.testclient import TestClient

from ephemeral_agent_secret_leasing.backends import DynamicBackend
from ephemeral_agent_secret_leasing.broker import SecretBroker, create_app
from ephemeral_agent_secret_leasing.defense import SecretLeaseDefense
from ephemeral_agent_secret_leasing.policy import Policy


def _profile() -> dict[str, object]:
    return {
        "trust_domain": "ztap.test",
        "egress_allowlist": ["ztap.test"],
        "email_allowed_domains": ["ztap.test"],
        "tools": {
            "http.post": {"risk": "medium", "scopes": ["net:write"], "egress": True},
            "db.admin": {"risk": "critical", "scopes": ["db:admin"], "egress": False},
        },
    }


def _req(args: dict[str, object], *, tool: str = "http.post") -> dict[str, object]:
    return {
        "trace_id": "t1",
        "step": 0,
        "agent": {
            "spiffe_id": "spiffe://ztap.test/agent/a",
            "svid": "valid",
            "attestation": "valid",
            "trust_history": ["benign"],
            "scopes": ["net:write"],
        },
        "tool": tool,
        "args": args,
        "context": {"origin": "user", "content": "ok", "reasoning_tokens": 10},
        "history": [],
    }


def test_defense_blocks_taint_external_bad_identity_and_scope() -> None:
    d = SecretLeaseDefense()
    d.setup(_profile())
    d.on_trace_start({"trace_id": "t1", "issued_secrets": ["sk_live_abcdefgh12345678"]})
    assert (
        d.decide(
            {**_req({"body": "sk_live_abcdefgh12345678", "url": "https://api.ztap.test/x"})}
        ).component
        == "taint"
    )
    external = SecretLeaseDefense()
    external.setup(_profile())
    assert (
        external.decide(_req({"url": "https://collector.example.net/x", "body": "hello"})).component
        == "egress"
    )
    ok = SecretLeaseDefense()
    ok.setup(_profile())
    assert ok.decide(_req({"url": "https://api.ztap.test/x", "body": "hello"})).decision == "allow"
    bad = _req({"url": "https://api.ztap.test/x"})
    assert isinstance(bad["agent"], dict)
    bad["agent"]["attestation"] = "missing"  # type: ignore[index]
    identity = SecretLeaseDefense()
    identity.setup(_profile())
    assert identity.decide(bad).component == "identity"
    scoped = SecretLeaseDefense()
    scoped.setup(_profile())
    assert scoped.decide(_req({"resource": "prod"}, tool="db.admin")).component == "policy"


def test_starlette_lease_api() -> None:
    backend = DynamicBackend()
    backend.put("secret/api", "api-value-123456")
    client = TestClient(create_app(SecretBroker(backend, Policy.allow_test_agents())))
    issue = client.post(
        "/v1/leases",
        json={
            "spiffe_id": "spiffe://ztap.test/agent/a",
            "cert_sha256": "abc",
            "path": "secret/api",
            "ttl_s": 10,
            "max_uses": 1,
        },
    )
    assert issue.status_code == 200
    lease_id = issue.json()["lease"]["lease_id"]
    used = client.post(
        "/v1/leases/use",
        json={
            "spiffe_id": "spiffe://ztap.test/agent/a",
            "cert_sha256": "abc",
            "lease_id": lease_id,
        },
    )
    assert used.json()["value"] == "api-value-123456"
