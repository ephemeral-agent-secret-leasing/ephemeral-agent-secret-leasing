"""Zero Trust Agent Benchmark defense adapter."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from collections.abc import Iterable
from contextlib import suppress
from typing import Any
from urllib.parse import unquote, urlparse

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
        self.trust_domain = ""
        self.tools: dict[str, dict[str, Any]] = {}
        self.egress_allowlist: set[str] = set()
        self.email_allowed_domains: set[str] = set()

    def setup(self, profile: dict[str, Any]) -> None:
        if not isinstance(profile, dict):
            return
        self.trust_domain = str(profile.get("trust_domain", self.trust_domain))
        self.tools = _dict_of_dicts(profile.get("tools", {}))
        self.egress_allowlist = _string_set(profile.get("egress_allowlist", []))
        self.email_allowed_domains = _string_set(profile.get("email_allowed_domains", []))

    def reset(self) -> None:
        self.registry = TaintRegistry()

    def on_trace_start(self, meta: dict[str, Any]) -> None:
        self.registry = TaintRegistry()
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
        if _encoded_secret_literal_present(args):
            return Decision("deny", "encoded secret literal", "taint")
        context = request.get("context", {})
        if not isinstance(context, dict):
            return Decision("deny", "bad context", "schema")
        context_decision = self._contextual_denial(context)
        if context_decision is not None:
            return context_decision
        lease_decision = self._lease_reference_denial(tool, tool_meta, args, context)
        if lease_decision is not None:
            return lease_decision
        if (
            str(tool_meta.get("risk", "")).lower() == "critical"
            and context.get("origin") == "user"
            and not _has_privileged_tool_grant(context)
        ):
            return Decision("deny", "missing user-originated privileged-tool grant", "authority")
        if (
            tool == "email.send"
            and context.get("origin") == "retrieved_doc"
            and not _email_egress_declared(context)
        ):
            return Decision("deny", "email egress not user-declared", "authority")
        if tool == "secrets.get" and not _has_explicit_secret_grant(context):
            return Decision("deny", "missing user-originated secret grant", "authority")
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

    def _contextual_denial(self, context: dict[str, Any]) -> Decision | None:
        text = " ".join(
            str(context.get(key, "")) for key in ("content", "tool_description", "raw_generation")
        )
        if _has_format_control(text):
            return Decision("deny", "hidden format-control instruction", "authority")
        if _CONTROL_TOKEN_RE.search(text) and int(context.get("reasoning_tokens", 1)) == 0:
            return Decision("deny", "control token in zero-reasoning tool frame", "parser")
        raw_generation = context.get("raw_generation")
        if isinstance(raw_generation, str) and _malformed_tool_frame(raw_generation):
            return Decision("deny", "malformed tool frame", "parser")
        return None

    def _lease_reference_denial(
        self, tool: str, tool_meta: dict[str, Any], args: dict[str, Any], context: dict[str, Any]
    ) -> Decision | None:
        refs = _secret_references(args)
        if not refs:
            return None
        for field, value in refs:
            if not _OPAQUE_SECRET_REF_RE.fullmatch(value.strip()):
                return Decision("deny", "non-opaque lease reference", "lease")
            if bool(tool_meta.get("egress", False)) and "ref" not in field.lower():
                return Decision("deny", "lease reference is outside declared egress field", "lease")
        if bool(tool_meta.get("egress", False)) and not _egress_declared_by_user(
            tool, args, context
        ):
            return Decision("deny", "lease egress destination not declared", "lease")
        return None


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


_CONTROL_TOKEN_RE = re.compile(r"<\|(?:start|end|channel|message)\|>|<start_of_turn>|<end_of_turn>")
_SECRET_REF_RE = re.compile(r"secret://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_OPAQUE_SECRET_REF_RE = re.compile(r"secret://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_NEGATED_SECRET_GRANT_RE = re.compile(
    r"\b(?:no|without|never)\s+(?:raw\s+)?(?:secret|token|credential)s?\b"
)
_SECRET_GRANT_RE = re.compile(
    r"\b(?:secret|credential|token|broker|opaque|handle|reference|ref|deploy(?:ment)?)\b"
)
_EMAIL_GRANT_RE = re.compile(r"\b(?:email|send|forward|share|notify|recipient|alias)\b")
_HTTP_GRANT_RE = re.compile(r"\b(?:api|request|call|post|deploy|broker|reference|handle|token)\b")
_PRIVILEGED_TOOL_GRANT_RE = re.compile(
    r"\b(?:run|execute|command|shell|admin|test|build|compile|check|deploy)\b"
)
_COMMON_SECRET_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk_(?:live|test)_[A-Za-z0-9_]{16,})"
)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_=%+./:-]{8,}")


def _has_format_control(text: str) -> bool:
    return any(unicodedata.category(char) == "Cf" for char in text)


def _malformed_tool_frame(raw: str) -> bool:
    stripped = raw.strip()
    return bool(stripped) and (
        stripped.count("{") > stripped.count("}")
        or stripped.count("[") > stripped.count("]")
        or stripped.endswith(('"', ":", ","))
    )


def _secret_references(args: dict[str, Any]) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []

    def walk(obj: Any, field: str) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                walk(value, str(key))
        elif isinstance(obj, list):
            for value in obj:
                walk(value, field)
        elif isinstance(obj, str) and _SECRET_REF_RE.search(obj):
            refs.append((field, obj))

    walk(args, "")
    return refs


def _has_explicit_secret_grant(context: dict[str, Any]) -> bool:
    user_task = str(context.get("user_task", "")).lower()
    if _NEGATED_SECRET_GRANT_RE.search(user_task):
        return False
    return bool(_SECRET_GRANT_RE.search(user_task))


def _has_privileged_tool_grant(context: dict[str, Any]) -> bool:
    user_task = str(context.get("user_task", "")).lower()
    return bool(_PRIVILEGED_TOOL_GRANT_RE.search(user_task))


def _email_egress_declared(context: dict[str, Any]) -> bool:
    user_task = str(context.get("user_task", "")).lower()
    return bool(_EMAIL_GRANT_RE.search(user_task))


def _egress_declared_by_user(tool: str, args: dict[str, Any], context: dict[str, Any]) -> bool:
    if context.get("origin") == "user":
        return True
    user_task = str(context.get("user_task", "")).lower()
    if tool == "email.send":
        return bool(_EMAIL_GRANT_RE.search(user_task))
    if tool in {"http.post", "http.get"}:
        if _HTTP_GRANT_RE.search(user_task):
            return True
        refs = _secret_references(args)
        return bool(refs and _has_explicit_secret_grant(context))
    return True


def _encoded_secret_literal_present(args: dict[str, Any]) -> bool:
    for value in _walk(args):
        if not isinstance(value, str):
            continue
        if _COMMON_SECRET_RE.search(value):
            return True
        compact = re.sub(r"[\s.\-]", "", value)
        if compact != value and _COMMON_SECRET_RE.search(compact):
            return True
        for token in _TOKEN_RE.findall(value):
            if _COMMON_SECRET_RE.search(token):
                return True
            for decoded in _decode_candidates(token):
                if _COMMON_SECRET_RE.search(decoded):
                    return True
    return False


def _decode_candidates(token: str) -> list[str]:
    candidates = [unquote(token), token[::-1], codecs.encode(token, "rot_13")]
    if re.fullmatch(r"[0-9A-Fa-f]{16,}", token) and len(token) % 2 == 0:
        with suppress(binascii.Error, ValueError):
            candidates.append(binascii.unhexlify(token).decode("utf-8", errors="ignore"))
    b64 = token + "=" * (-len(token) % 4)
    if re.fullmatch(r"[A-Za-z0-9_\-+/=]{16,}", b64):
        for altchars in (None, b"-_"):
            with suppress(binascii.Error, ValueError):
                candidates.append(
                    base64.b64decode(b64.encode(), altchars=altchars, validate=False).decode(
                        "utf-8", errors="ignore"
                    )
                )
    return candidates


defense = SecretLeaseDefense()
