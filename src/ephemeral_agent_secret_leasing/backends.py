"""Secret storage and generation backends."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretBackend(Protocol):
    def get(self, path: str) -> str: ...
    def put(self, path: str, value: str) -> None: ...


def load_or_create_kek(path: Path) -> bytes:
    if path.exists():
        return base64.b64decode(path.read_text(encoding="utf-8"))
    key = AESGCM.generate_key(bit_length=256)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(key).decode(), encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return key


class EncryptedStoreBackend:
    def __init__(self, store_path: Path, kek: bytes) -> None:
        self.store_path = store_path
        self.kek = kek
        store_path.parent.mkdir(parents=True, exist_ok=True)
        if not store_path.exists():
            store_path.write_text("{}\n", encoding="utf-8")

    def _read(self) -> dict[str, dict[str, str]]:
        raw = json.loads(self.store_path.read_text(encoding="utf-8"))
        return {str(k): dict(v) for k, v in raw.items()}

    def _write(self, data: dict[str, dict[str, str]]) -> None:
        self.store_path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def put(self, path: str, value: str) -> None:
        dek = AESGCM.generate_key(bit_length=256)
        vn = secrets.token_bytes(12)
        dn = secrets.token_bytes(12)
        data = self._read()
        data[path] = {
            "value_nonce": base64.b64encode(vn).decode(),
            "dek_nonce": base64.b64encode(dn).decode(),
            "ciphertext": base64.b64encode(
                AESGCM(dek).encrypt(vn, value.encode(), path.encode())
            ).decode(),
            "wrapped_dek": base64.b64encode(
                AESGCM(self.kek).encrypt(dn, dek, path.encode())
            ).decode(),
        }
        self._write(data)

    def get(self, path: str) -> str:
        item = self._read()[path]
        dek = AESGCM(self.kek).decrypt(
            base64.b64decode(item["dek_nonce"]),
            base64.b64decode(item["wrapped_dek"]),
            path.encode(),
        )
        return (
            AESGCM(dek)
            .decrypt(
                base64.b64decode(item["value_nonce"]),
                base64.b64decode(item["ciphertext"]),
                path.encode(),
            )
            .decode()
        )


class DynamicBackend:
    def __init__(self) -> None:
        self._static: dict[str, str] = {}

    def put(self, path: str, value: str) -> None:
        self._static[path] = value

    def get(self, path: str) -> str:
        return self._static.get(
            path, ("db" if "db" in path else "tok") + "_" + secrets.token_urlsafe(24)
        )


class VaultBackend:
    def __init__(self, url: str, token: str, mount: str = "secret") -> None:
        import hvac

        self.client: Any = hvac.Client(url=url, token=token)
        self.mount = mount

    def put(self, path: str, value: str) -> None:
        self.client.secrets.kv.v2.create_or_update_secret(
            mount_point=self.mount, path=path, secret={"value": value}
        )

    def get(self, path: str) -> str:
        return str(
            self.client.secrets.kv.v2.read_secret_version(mount_point=self.mount, path=path)[
                "data"
            ]["data"]["value"]
        )
