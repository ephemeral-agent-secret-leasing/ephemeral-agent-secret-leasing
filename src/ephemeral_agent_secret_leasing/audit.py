"""Signed JSONL audit log."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    records: int
    error: str | None = None


class AuditLog:
    def __init__(self, path: Path, signing_key: Ed25519PrivateKey | None = None) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.signing_key = signing_key or Ed25519PrivateKey.generate()
        self.public_key = self.signing_key.public_key()
        if not path.exists():
            path.write_text("", encoding="utf-8")

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        prev = self._last_hash()
        index = sum(
            1 for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()
        )
        record: dict[str, Any] = {
            "index": index,
            "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "prev_hash": prev,
            "event": event,
        }
        record["signature"] = base64.b64encode(self.signing_key.sign(_canonical(record))).decode()
        record["hash"] = hashlib.sha256(_canonical(record)).hexdigest()
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        return record

    def public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def _last_hash(self) -> str:
        prev = "0" * 64
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                prev = str(json.loads(line)["hash"])
        return prev


def verify_audit_log(path: Path, public_key: Ed25519PublicKey) -> VerifyResult:
    prev = "0" * 64
    count = 0
    try:
        for expected, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            rec = json.loads(line)
            sig = base64.b64decode(rec.pop("signature"))
            stored = str(rec.pop("hash"))
            if rec.get("index") != expected or rec.get("prev_hash") != prev:
                return VerifyResult(False, count, "hash chain mismatch")
            public_key.verify(sig, _canonical(rec))
            rec["signature"] = base64.b64encode(sig).decode()
            if hashlib.sha256(_canonical(rec)).hexdigest() != stored:
                return VerifyResult(False, count, "record hash mismatch")
            prev = stored
            count += 1
    except (InvalidSignature, json.JSONDecodeError, KeyError, ValueError) as exc:
        return VerifyResult(False, count, exc.__class__.__name__)
    return VerifyResult(True, count)


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
