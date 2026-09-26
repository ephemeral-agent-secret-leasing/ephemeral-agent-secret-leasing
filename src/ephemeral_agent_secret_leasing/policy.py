"""Deny-by-default lease policy."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class PolicyRule:
    spiffe_glob: str
    paths: tuple[str, ...]
    max_ttl_s: int
    max_uses: int

    def allows(self, spiffe_id: str, path: str) -> bool:
        return fnmatch.fnmatchcase(spiffe_id, self.spiffe_glob) and any(
            fnmatch.fnmatchcase(path, p) for p in self.paths
        )


class Policy:
    def __init__(self, rules: list[PolicyRule]) -> None:
        self.rules = rules

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        return cls(
            [
                PolicyRule(
                    str(r["spiffe"]),
                    tuple(map(str, r.get("paths", []))),
                    int(r.get("max_ttl_s", 60)),
                    int(r.get("max_uses", 1)),
                )
                for r in data.get("rules", [])
            ]
        )

    @classmethod
    def from_yaml(cls, path: Path) -> Policy:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        data = {} if loaded is None else loaded
        if not isinstance(data, dict):
            raise ValueError("policy YAML must be a mapping")
        return cls.from_dict(data)

    @classmethod
    def allow_test_agents(cls) -> Policy:
        return cls([PolicyRule("spiffe://ztap.test/agent/*", ("secret/*", "dynamic/*"), 60, 3)])

    def authorize(self, spiffe_id: str, path: str, ttl_s: int, max_uses: int) -> PolicyRule:
        for rule in self.rules:
            if rule.allows(spiffe_id, path):
                if ttl_s > rule.max_ttl_s:
                    raise PermissionError("requested ttl exceeds policy")
                if max_uses > rule.max_uses:
                    raise PermissionError("requested max_uses exceeds policy")
                return rule
        raise PermissionError("no policy rule allows this identity/path")
