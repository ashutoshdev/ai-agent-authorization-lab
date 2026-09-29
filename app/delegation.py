from dataclasses import dataclass


@dataclass(frozen=True)
class Delegation:
    source: str
    target: str
    capability: str
    tenant_id: str


@dataclass(frozen=True)
class AuthorizationRequest:
    caller: str
    caller_tenant: str
    service: str
    resource: str
    requested_capability: str


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str
    effective_tenant: str | None