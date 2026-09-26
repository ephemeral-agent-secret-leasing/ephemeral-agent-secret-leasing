from __future__ import annotations

import os

import pytest

from ephemeral_agent_secret_leasing.backends import VaultBackend

pytestmark = pytest.mark.integration


def test_vault_backend_roundtrip() -> None:
    if os.getenv("ZTAP_INTEGRATION") != "1":
        pytest.skip("set ZTAP_INTEGRATION=1 and run hashicorp/vault:1.21 dev server")
    backend = VaultBackend(
        os.getenv("VAULT_ADDR", "http://127.0.0.1:18420"), os.getenv("VAULT_TOKEN", "root")
    )
    backend.put("ephemeral-agent-secret-leasing-ci", "vault-value-123")
    assert backend.get("ephemeral-agent-secret-leasing-ci") == "vault-value-123"
