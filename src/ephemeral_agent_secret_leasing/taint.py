"""Taint registry and egress scanner."""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse


@dataclass(frozen=True, slots=True)
class TaintMatch:
    lease_id: str
    encoding: str
    token: str


@dataclass(frozen=True, slots=True)
class RegisteredSecret:
    lease_id: str
    value: str
    encodings: dict[str, str]


def encodings_for(value: str) -> dict[str, str]:
    raw = value.encode()
    percent_all = "".join(f"%{byte:02X}" for byte in raw)
    return {
        "raw": value,
        "base64": base64.b64encode(raw).decode(),
        "base64url": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "hex": binascii.hexlify(raw).decode(),
        "percent": quote(value, safe=""),
        "percent_all": percent_all,
        "reversed": value[::-1],
        "rot13": codecs.encode(value, "rot_13"),
        "json": json.dumps(value)[1:-1],
    }


def _compact(text: str) -> str:
    return "".join(re.findall(r"[A-Za-z0-9_\-]+", text))


def _ngrams(text: str, n: int) -> set[str]:
    return {text[i : i + n] for i in range(max(1, len(text) - n + 1))} if text else set()


class TaintRegistry:
    def __init__(self, min_ngram: int = 8) -> None:
        self.min_ngram = min_ngram
        self._secrets: dict[str, RegisteredSecret] = {}
        self._ngrams: dict[str, set[str]] = {}
        self.revoked: set[str] = set()

    def register(self, lease_id: str, value: str) -> None:
        secret = RegisteredSecret(lease_id, value, encodings_for(value))
        self._secrets[lease_id] = secret
        for token in {value, *secret.encodings.values()}:
            for gram in _ngrams(_compact(token).lower(), self.min_ngram):
                self._ngrams.setdefault(gram, set()).add(lease_id)

    def revoke(self, lease_id: str) -> None:
        self.revoked.add(lease_id)

    def scan_text(self, text: str) -> TaintMatch | None:
        lowered = text.lower()
        compact = _compact(text).lower()
        candidates: set[str] = set()
        for gram in _ngrams(compact, self.min_ngram):
            candidates.update(self._ngrams.get(gram, set()))
        for lease_id in sorted(candidates or set(self._secrets)):
            if lease_id in self.revoked:
                continue
            sec = self._secrets[lease_id]
            for name, token in sec.encodings.items():
                if token and token.lower() in lowered:
                    return TaintMatch(lease_id, name, token)
            if _compact(sec.value).lower() in compact:
                return TaintMatch(lease_id, "split", sec.value)
        return None

    def scan_request(
        self, args: dict[str, Any], headers: dict[str, str] | None = None
    ) -> TaintMatch | None:
        blob = json.dumps(args, sort_keys=True, ensure_ascii=False) + (
            json.dumps(headers, sort_keys=True) if headers else ""
        )
        for k in ("url", "uri"):
            v = args.get(k)
            if isinstance(v, str):
                blob += "\n" + (urlparse(v).hostname or "").replace(".", "")
        return self.scan_text(blob)
