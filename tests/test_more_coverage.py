from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ephemeral_agent_secret_leasing.audit import AuditLog
from ephemeral_agent_secret_leasing.backends import (
    DynamicBackend,
    EncryptedStoreBackend,
    VaultBackend,
    load_or_create_kek,
)
from ephemeral_agent_secret_leasing.broker import SecretBroker, create_app
from ephemeral_agent_secret_leasing.ca import TestCA, spiffe_id_from_cert
from ephemeral_agent_secret_leasing.cli import main
from ephemeral_agent_secret_leasing.defense import SecretLeaseDefense
from ephemeral_agent_secret_leasing.policy import Policy


def test_cli_wilson_and_audit_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["wilson", "1", "2"]) == 0
    assert "point" in capsys.readouterr().out
    key = Ed25519PrivateKey.generate()
    log = AuditLog(tmp_path / "audit.jsonl", key)
    log.append({"action": "issue"})
    pub = tmp_path / "pub.pem"
    pub.write_bytes(log.public_key_pem())
    assert main(["verify-audit", str(tmp_path / "audit.jsonl"), str(pub)]) == 0


def test_policy_yaml_and_denials(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yml"
    policy_file.write_text(
        (
            "rules:\n"
            "- spiffe: spiffe://example.internal/agent/*\n"
            "  paths: ['secret/team/*']\n"
            "  max_ttl_s: 5\n"
            "  max_uses: 1\n"
        ),
        encoding="utf-8",
    )
    policy = Policy.from_yaml(policy_file)
    assert policy.authorize("spiffe://example.internal/agent/a", "secret/team/x", 5, 1)
    with pytest.raises(PermissionError):
        policy.authorize("spiffe://example.internal/agent/a", "secret/team/x", 6, 1)
    with pytest.raises(PermissionError):
        policy.authorize("spiffe://example.internal/agent/a", "secret/team/x", 5, 2)
    bad = tmp_path / "bad.yml"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        Policy.from_yaml(bad)


def test_api_renew_revoke_error_paths() -> None:
    from starlette.testclient import TestClient

    backend = DynamicBackend()
    backend.put("secret/api", "api-value-123456")
    client = TestClient(create_app(SecretBroker(backend, Policy.allow_test_agents())))
    denied = client.post(
        "/v1/leases",
        json={"spiffe_id": "spiffe://example.internal/agent/a", "cert_sha256": "c", "path": "bad"},
    )
    assert denied.status_code == 403
    issue = client.post(
        "/v1/leases",
        json={
            "spiffe_id": "spiffe://example.internal/agent/a",
            "cert_sha256": "c",
            "path": "secret/api",
        },
    )
    lease_id = issue.json()["lease"]["lease_id"]
    assert (
        client.post(
            "/v1/leases/renew",
            json={
                "spiffe_id": "spiffe://example.internal/agent/a",
                "cert_sha256": "c",
                "lease_id": lease_id,
                "ttl_s": 5,
            },
        ).status_code
        == 200
    )
    assert client.post("/v1/leases/revoke", json={"lease_id": lease_id}).json()["revoked"] is True
    assert (
        client.post(
            "/v1/leases/use",
            json={
                "spiffe_id": "spiffe://example.internal/agent/a",
                "cert_sha256": "c",
                "lease_id": lease_id,
            },
        ).status_code
        == 403
    )


def test_ca_invalid_and_missing_san() -> None:
    with pytest.raises(ValueError):
        TestCA().issue_svid("not-spiffe")
    with pytest.raises(ValueError):
        spiffe_id_from_cert(TestCA().cert_pem)


def test_defense_setup_schema_and_trace_hook() -> None:
    d = SecretLeaseDefense()
    d.setup(
        {
            "trust_domain": "example.internal",
            "egress_allowlist": ["example.org"],
            "email_allowed_domains": ["example.org"],
            "tools": {"http.post": {"scopes": ["net:write"], "egress": True}},
        }
    )
    d.on_trace_start({"trace_id": "t", "issued_secrets": ["secret1234567890"]})
    assert d.decide({"agent": {}, "args": {}}).decision == "deny"
    req = {
        "agent": {
            "svid": "valid",
            "attestation": "valid",
            "spiffe_id": "spiffe://example.internal/agent/a",
            "scopes": ["net:write"],
        },
        "args": {"url": "https://svc.example.org/x", "body": "ok"},
        "context": {"origin": "user"},
        "tool": "http.post",
    }
    assert d.decide(req).decision == "allow"
    bad_req = dict(req)
    bad_req["args"] = "oops"
    assert d.decide(bad_req).component == "schema"


def test_vault_backend_with_fake_hvac(monkeypatch: pytest.MonkeyPatch) -> None:
    stored: dict[str, str] = {}

    class FakeKV2:
        def create_or_update_secret(
            self, mount_point: str, path: str, secret: dict[str, str]
        ) -> None:
            stored[path] = secret["value"]

        def read_secret_version(
            self, mount_point: str, path: str
        ) -> dict[str, dict[str, dict[str, str]]]:
            return {"data": {"data": {"value": stored[path]}}}

    class FakeClient:
        def __init__(self, url: str, token: str) -> None:
            self.secrets = types.SimpleNamespace(kv=types.SimpleNamespace(v2=FakeKV2()))

    monkeypatch.setitem(sys.modules, "hvac", types.SimpleNamespace(Client=FakeClient))
    backend = VaultBackend("http://vault", "root")
    backend.put("p", "v")
    assert backend.get("p") == "v"


def test_existing_kek_and_missing_store_path(tmp_path: Path) -> None:
    kek_path = tmp_path / "kek"
    first = load_or_create_kek(kek_path)
    assert load_or_create_kek(kek_path) == first
    store = EncryptedStoreBackend(tmp_path / "store.json", first)
    with pytest.raises(KeyError):
        store.get("missing")
