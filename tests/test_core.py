from __future__ import annotations

import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ephemeral_agent_secret_leasing.audit import AuditLog, verify_audit_log
from ephemeral_agent_secret_leasing.backends import (
    DynamicBackend,
    EncryptedStoreBackend,
    load_or_create_kek,
)
from ephemeral_agent_secret_leasing.broker import SecretBroker
from ephemeral_agent_secret_leasing.ca import TestCA, cert_sha256, spiffe_id_from_cert
from ephemeral_agent_secret_leasing.policy import Policy


def test_ca_issues_spiffe_svid() -> None:
    bundle = TestCA().issue_svid("spiffe://example.internal/agent/a", ttl_s=60)
    assert spiffe_id_from_cert(bundle.cert_pem) == "spiffe://example.internal/agent/a"
    assert cert_sha256(bundle.cert_pem) == bundle.cert_sha256


def test_encrypted_store_roundtrip(tmp_path: Path) -> None:
    store = EncryptedStoreBackend(tmp_path / "store.json", load_or_create_kek(tmp_path / "kek.bin"))
    store.put("secret/api", "super-secret")
    assert store.get("secret/api") == "super-secret" and "super-secret" not in (
        tmp_path / "store.json"
    ).read_text(encoding="utf-8")


def test_broker_lease_lifecycle() -> None:
    backend = DynamicBackend()
    backend.put("secret/api", "value-12345678")
    now = 1000.0
    broker = SecretBroker(backend, Policy.allow_test_agents(), clock=lambda: now)
    lease = broker.issue(
        "spiffe://example.internal/agent/a", "abc", "secret/api", ttl_s=10, max_uses=2
    )
    assert broker.use(lease.lease_id, lease.bound_spiffe_id, "abc") == "value-12345678"
    broker.renew(lease.lease_id, lease.bound_spiffe_id, "abc", 20)
    assert lease.expires_at_s == 1020.0
    with pytest.raises(PermissionError):
        broker.use(lease.lease_id, lease.bound_spiffe_id, "wrong")
    assert broker.revoke_by_identity(lease.bound_spiffe_id) == 1
    with pytest.raises(PermissionError):
        broker.use(lease.lease_id, lease.bound_spiffe_id, "abc")


def test_rotation_overlap_and_reaper() -> None:
    backend = DynamicBackend()
    backend.put("secret/api", "old-secret-value")
    current = 1.0
    broker = SecretBroker(backend, Policy.allow_test_agents(), clock=lambda: current)
    old = broker.issue(
        "spiffe://example.internal/agent/a", "abc", "secret/api", ttl_s=10, max_uses=3
    )
    broker.rotate("secret/api", "new-secret-value", grace_s=5)
    new = broker.issue(
        "spiffe://example.internal/agent/a", "abc", "secret/api", ttl_s=10, max_uses=3
    )
    assert {old.value, new.value} == {"old-secret-value", "new-secret-value"}
    assert broker.valid_versions("secret/api") <= 2
    broker.clock = lambda: time.time() + 1000
    assert broker.reap_expired() >= 1


def test_audit_log_detects_tampering(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    log = AuditLog(tmp_path / "audit.jsonl", key)
    log.append({"action": "issue"})
    log.append({"action": "revoke"})
    assert verify_audit_log(tmp_path / "audit.jsonl", key.public_key()).ok
    (tmp_path / "audit.jsonl").write_text(
        (tmp_path / "audit.jsonl").read_text(encoding="utf-8").replace("revoke", "renew", 1),
        encoding="utf-8",
    )
    assert not verify_audit_log(tmp_path / "audit.jsonl", key.public_key()).ok
