"""Lease broker and Starlette API."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .backends import SecretBackend
from .policy import Policy
from .taint import TaintRegistry


@dataclass(slots=True)
class Lease:
    lease_id: str
    path: str
    value: str
    ttl_s: int
    max_uses: int
    bound_spiffe_id: str
    bound_cert_sha256: str
    issued_at_s: float
    expires_at_s: float
    uses: int = 0
    revoked: bool = False
    version: int = 1

    def active(self, now_s: float | None = None) -> bool:
        now = time.time() if now_s is None else now_s
        return (not self.revoked) and self.expires_at_s > now and self.uses < self.max_uses

    def public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("value", None)
        return data


class SecretBroker:
    def __init__(
        self,
        backend: SecretBackend,
        policy: Policy,
        *,
        registry: TaintRegistry | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.backend = backend
        self.policy = policy
        self.registry = registry or TaintRegistry()
        self.clock = clock
        self._leases: dict[str, Lease] = {}

    @property
    def leases(self) -> dict[str, Lease]:
        return dict(self._leases)

    def issue(
        self, spiffe_id: str, cert_sha256: str, path: str, *, ttl_s: int = 30, max_uses: int = 1
    ) -> Lease:
        self.policy.authorize(spiffe_id, path, ttl_s, max_uses)
        now = self.clock()
        value = self.backend.get(path)
        lease = Lease(
            "lease_" + secrets.token_urlsafe(18),
            path,
            value,
            ttl_s,
            max_uses,
            spiffe_id,
            cert_sha256,
            now,
            now + ttl_s,
        )
        self._leases[lease.lease_id] = lease
        self.registry.register(lease.lease_id, value)
        return lease

    def use(self, lease_id: str, spiffe_id: str, cert_sha256: str) -> str:
        lease = self._require_bound(lease_id, spiffe_id, cert_sha256)
        if not lease.active(self.clock()):
            raise PermissionError("lease is expired, revoked, or exhausted")
        lease.uses += 1
        return lease.value

    def renew(self, lease_id: str, spiffe_id: str, cert_sha256: str, ttl_s: int) -> Lease:
        lease = self._require_bound(lease_id, spiffe_id, cert_sha256)
        self.policy.authorize(spiffe_id, lease.path, ttl_s, lease.max_uses)
        if lease.revoked:
            raise PermissionError("revoked lease cannot be renewed")
        lease.ttl_s = ttl_s
        lease.expires_at_s = self.clock() + ttl_s
        return lease

    def revoke(self, lease_id: str) -> None:
        lease = self._leases.get(lease_id)
        if lease is not None:
            lease.revoked = True
            self.registry.revoke(lease_id)

    def revoke_by_identity(self, spiffe_id: str) -> int:
        count = 0
        for lease in self._leases.values():
            if lease.bound_spiffe_id == spiffe_id and not lease.revoked:
                lease.revoked = True
                self.registry.revoke(lease.lease_id)
                count += 1
        return count

    def reap_expired(self) -> int:
        now = self.clock()
        expired = [lid for lid, lease in self._leases.items() if lease.expires_at_s <= now]
        for lid in expired:
            self.registry.revoke(lid)
            del self._leases[lid]
        return len(expired)

    def rotate(self, path: str, new_value: str, *, grace_s: int) -> None:
        self.backend.put(path, new_value)
        now = self.clock()
        for lease in self._leases.values():
            if lease.path == path and lease.active(now):
                lease.expires_at_s = min(lease.expires_at_s, now + grace_s)

    def valid_versions(self, path: str) -> int:
        return min(
            2,
            len(
                {
                    lease.value
                    for lease in self._leases.values()
                    if lease.path == path and lease.active(self.clock())
                }
            ),
        )

    def _require_bound(self, lease_id: str, spiffe_id: str, cert_sha256: str) -> Lease:
        try:
            lease = self._leases[lease_id]
        except KeyError as exc:
            raise PermissionError("unknown lease") from exc
        if lease.bound_spiffe_id != spiffe_id or lease.bound_cert_sha256 != cert_sha256:
            raise PermissionError("lease is bound to a different identity or certificate")
        return lease


def create_app(broker: SecretBroker) -> Starlette:
    async def issue(request: Request) -> JSONResponse:
        body = await request.json()
        try:
            lease = broker.issue(
                str(body["spiffe_id"]),
                str(body["cert_sha256"]),
                str(body["path"]),
                ttl_s=int(body.get("ttl_s", 30)),
                max_uses=int(body.get("max_uses", 1)),
            )
            return JSONResponse({"lease": lease.public_dict(), "value": lease.value})
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)

    async def use(request: Request) -> JSONResponse:
        body = await request.json()
        try:
            return JSONResponse(
                {
                    "value": broker.use(
                        str(body["lease_id"]), str(body["spiffe_id"]), str(body["cert_sha256"])
                    )
                }
            )
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)

    async def renew(request: Request) -> JSONResponse:
        body = await request.json()
        try:
            return JSONResponse(
                {
                    "lease": broker.renew(
                        str(body["lease_id"]),
                        str(body["spiffe_id"]),
                        str(body["cert_sha256"]),
                        int(body["ttl_s"]),
                    ).public_dict()
                }
            )
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)

    async def revoke(request: Request) -> JSONResponse:
        broker.revoke(str((await request.json())["lease_id"]))
        return JSONResponse({"revoked": True})

    return Starlette(
        routes=[
            Route("/v1/leases", issue, methods=["POST"]),
            Route("/v1/leases/use", use, methods=["POST"]),
            Route("/v1/leases/renew", renew, methods=["POST"]),
            Route("/v1/leases/revoke", revoke, methods=["POST"]),
        ]
    )
