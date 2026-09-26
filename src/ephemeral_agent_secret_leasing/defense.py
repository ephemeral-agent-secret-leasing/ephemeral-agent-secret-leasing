"""Zero Trust Agent Benchmark defense adapter."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from .taint import TaintRegistry

try:
    from zero_trust_agent_benchmark import Decision
except Exception:  # pragma: no cover

    class Decision:  # type: ignore[no-redef]
        def __init__(
            self, decision: str, reason: str = "", component: str = "ephemeral_agent_secret_leasing"
        ) -> None:
            self.decision = decision
            self.reason = reason
            self.component = component

        def as_dict(self) -> dict[str, str]:
            return {"decision": self.decision, "reason": self.reason, "component": self.component}


class SecretLeaseDefense:
    """Defense adapter using only operator profile, identity posture, and taint scanning."""

    def __init__(self) -> None:
        self.registry = TaintRegistry()
        self.trust_domain = "ztap.test"
        self.tools: dict[str, dict[str, Any]] = {}
        self.egress_allowlist = {self.trust_domain}
        self.email_allowed_domains = {self.trust_domain}

    def setup(self, profile: dict[str, Any]) -> None:
        if not isinstance(profile, dict):
            return
        self.trust_domain = str(profile.get("trust_domain", self.trust_domain))
        self.tools = _dict_of_dicts(profile.get("tools", {}))
        self.egress_allowlist = _string_set(profile.get("egress_allowlist", [self.trust_domain]))
        self.email_allowed_domains = _string_set(
            profile.get("email_allowed_domains", [self.trust_domain])
        )

    def reset(self) -> None:
        self.registry = TaintRegistry()

    def on_trace_start(self, meta: dict[str, Any]) -> None:
        for i, value in enumerate(meta.get("issued_secrets", [])):
            self.registry.register(f"issued-{i}", str(value))

    def decide(self, request: dict[str, Any]) -> Decision:
        agent = request.get("agent", {})
        if not isinstance(agent, dict) or not self._identity_ok(agent):
            return Decision("deny", "invalid identity posture", "identity")
        tool = str(request.get("tool", ""))
        tool_meta = self.tools.get(tool, {}) if self.tools else {}
        if self.tools and not tool_meta:
            return Decision("deny", "unknown tool", "policy")
        if not set(tool_meta.get("scopes", [])).issubset(set(agent.get("scopes", []))):
            return Decision("deny", "missing scope", "policy")
        args = request.get("args", {})
        if not isinstance(args, dict):
            return Decision("deny", "bad args", "schema")
        match = self.registry.scan_request(args)
        if match is not None:
            return Decision("deny", f"taint match {match.encoding}", "taint")
        if bool(tool_meta.get("egress", True)) and self._external_egress(args):
            return Decision("deny", "non-allowlisted egress", "egress")
        return Decision("allow", "ok", "ephemeral_agent_secret_leasing")

    def _identity_ok(self, agent: dict[str, Any]) -> bool:
        spiffe_id = str(agent.get("spiffe_id", ""))
        return (
            agent.get("svid") == "valid"
            and agent.get("attestation") == "valid"
            and spiffe_id.startswith(f"spiffe://{self.trust_domain}/")
        )

    def _external_egress(self, args: dict[str, Any]) -> bool:
        for value in _walk(args):
            if not isinstance(value, str):
                continue
            for host in _hosts_from_text(value):
                if not _host_allowed(host, self.egress_allowlist):
                    return True
            for domain in _mail_domains(value):
                if domain not in self.email_allowed_domains:
                    return True
        return False


def _dict_of_dicts(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    return {str(k): dict(v) for k, v in value.items() if isinstance(v, dict)}


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        return set()
    return {str(item).lower().rstrip(".") for item in value}


def _walk(obj: Any) -> list[Any]:
    if isinstance(obj, dict):
        out: list[Any] = []
        for value in obj.values():
            out.extend(_walk(value))
        return out
    if isinstance(obj, list):
        out = []
        for value in obj:
            out.extend(_walk(value))
        return out
    return [obj]


def _hosts_from_text(value: str) -> set[str]:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return set()
    host = parsed.hostname
    return {host.lower().rstrip(".")} if host else set()


def _mail_domains(value: str) -> set[str]:
    if "://" in value or "@" not in value:
        return set()
    domains = set()
    for piece in value.replace(",", " ").split():
        if "@" in piece:
            domains.add(piece.rsplit("@", 1)[-1].strip("<>()[]{};:,.").lower())
    return {domain for domain in domains if domain}


def _host_allowed(host: str, allowlist: set[str]) -> bool:
    return any(host == suffix or host.endswith("." + suffix) for suffix in allowlist)


defense = SecretLeaseDefense()
