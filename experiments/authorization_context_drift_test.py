from dataclasses import dataclass
import json
import os
from datetime import datetime, timezone

from app.models import DOCUMENTS
from app.resource_security import get_document_tenant


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports")
REPORT_PATH = os.path.join(
    REPORT_DIR,
    "authorization_context_drift.json",
)


@dataclass(frozen=True)
class AuthorizationContext:
    original_tenant: str
    effective_tenant: str


@dataclass(frozen=True)
class CapabilityContext:
    capability: str
    tenant_id: str


@dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    reason: str


def authorize_strict(
    context: AuthorizationContext,
    capability: CapabilityContext,
    resource_tenant: str,
) -> AuthorizationResult:
    """
    Secure composition model.

    The original caller tenant remains authoritative throughout
    the authorization chain.

    A downstream context change cannot replace the tenant bound
    to the capability.
    """

    if context.original_tenant != capability.tenant_id:
        return AuthorizationResult(
            allowed=False,
            reason="Capability is not bound to the original caller tenant.",
        )

    if context.original_tenant != context.effective_tenant:
        return AuthorizationResult(
            allowed=False,
            reason="Authorization context drift detected.",
        )

    if context.original_tenant != resource_tenant:
        return AuthorizationResult(
            allowed=False,
            reason="Resource belongs to another tenant.",
        )

    return AuthorizationResult(
        allowed=True,
        reason="Caller, capability, context, and resource tenant match.",
    )


def authorize_context_consuming(
    context: AuthorizationContext,
    capability: CapabilityContext,
    resource_tenant: str,
) -> AuthorizationResult:
    """
    Intentionally vulnerable composition model.

    The downstream authorization boundary trusts the current
    effective tenant instead of preserving the original caller
    tenant.

    This models a context-confusion / authorization-context-drift
    failure in the local research lab.
    """

    if context.effective_tenant != resource_tenant:
        return AuthorizationResult(
            allowed=False,
            reason="Effective tenant does not own the resource.",
        )

    if capability.capability != "read_document":
        return AuthorizationResult(
            allowed=False,
            reason="Capability does not authorize document reads.",
        )

    return AuthorizationResult(
        allowed=True,
        reason=(
            "Downstream authorization trusted the effective tenant "
            "without binding it to the original caller."
        ),
    )


def get_resource_tenant(document_id: str) -> str | None:
    return get_document_tenant(document_id)


def run_case(
    case_id: str,
    original_tenant: str,
    resource_id: str,
    drift: bool,
) -> dict:
    resource_tenant = get_resource_tenant(resource_id)

    if resource_tenant is None:
        raise ValueError(f"Unknown resource: {resource_id}")

    context_before = original_tenant

    if drift:
        effective_tenant = resource_tenant
    else:
        effective_tenant = original_tenant

    context = AuthorizationContext(
        original_tenant=original_tenant,
        effective_tenant=effective_tenant,
    )

    capability = CapabilityContext(
        capability="read_document",
        tenant_id=original_tenant,
    )

    strict_result = authorize_strict(
        context=context,
        capability=capability,
        resource_tenant=resource_tenant,
    )

    vulnerable_result = authorize_context_consuming(
        context=context,
        capability=capability,
        resource_tenant=resource_tenant,
    )

    actual_cross_tenant = original_tenant != resource_tenant

    context_drift = context_before != effective_tenant

    context_drift_violation = (
        actual_cross_tenant
        and context_drift
        and capability.tenant_id == original_tenant
        and strict_result.allowed is False
        and vulnerable_result.allowed is True
    )

    return {
        "case_id": case_id,
        "original_tenant": original_tenant,
        "capability_tenant": capability.tenant_id,
        "resource_id": resource_id,
        "resource_tenant": resource_tenant,
        "context_before": context_before,
        "context_after": effective_tenant,
        "context_drift": context_drift,
        "cross_tenant_request": actual_cross_tenant,
        "strict": {
            "allowed": strict_result.allowed,
            "reason": strict_result.reason,
        },
        "context_consuming_model": {
            "allowed": vulnerable_result.allowed,
            "reason": vulnerable_result.reason,
        },
        "context_drift_violation": context_drift_violation,
    }


def build_cases() -> list[dict]:
    return [
        # Legitimate same-tenant request.
        run_case(
            case_id="DRIFT-001",
            original_tenant="tenant-a",
            resource_id="doc-a-1",
            drift=False,
        ),

        # Cross-tenant request without context drift.
        run_case(
            case_id="DRIFT-002",
            original_tenant="tenant-a",
            resource_id="doc-b-1",
            drift=False,
        ),

        # Cross-tenant request where context changes to resource tenant.
        run_case(
            case_id="DRIFT-003",
            original_tenant="tenant-a",
            resource_id="doc-b-1",
            drift=True,
        ),

        # Reverse direction.
        run_case(
            case_id="DRIFT-004",
            original_tenant="tenant-b",
            resource_id="doc-a-1",
            drift=True,
        ),

        # Same-tenant request with no drift.
        run_case(
            case_id="DRIFT-005",
            original_tenant="tenant-b",
            resource_id="doc-b-1",
            drift=False,
        ),
    ]


def build_report(cases: list[dict]) -> dict:
    cross_tenant = [
        case
        for case in cases
        if case["cross_tenant_request"]
    ]

    drift_cases = [
        case
        for case in cases
        if case["context_drift"]
    ]

    violations = [
        case
        for case in cases
        if case["context_drift_violation"]
    ]

    return {
        "metadata": {
            "experiment": "authorization_context_drift",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scope": "local controlled security research lab",
            "hypothesis": (
                "A capability bound to the original tenant must not "
                "become authorized for another tenant merely because "
                "the authorization context changes during composition."
            ),
        },
        "security_property": {
            "name": "authorization_context_integrity",
            "invariant": (
                "original caller tenant remains authoritative "
                "throughout the authorization chain"
            ),
        },
        "summary": {
            "cases": len(cases),
            "cross_tenant_cases": len(cross_tenant),
            "context_drift_cases": len(drift_cases),
            "context_drift_violations": len(violations),
            "strict_cross_tenant_allowed": sum(
                1
                for case in cross_tenant
                if case["strict"]["allowed"]
            ),
            "context_consuming_cross_tenant_allowed": sum(
                1
                for case in cross_tenant
                if case["context_consuming_model"]["allowed"]
            ),
        },
        "findings": cases,
    }


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)

    cases = build_cases()
    report = build_report(cases)

    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    summary = report["summary"]

    print("Authorization Context Drift Experiment")
    print("=" * 45)
    print(f"Cases: {summary['cases']}")
    print(f"Cross-tenant cases: {summary['cross_tenant_cases']}")
    print(f"Context drift cases: {summary['context_drift_cases']}")
    print(
        "Strict cross-tenant allowed: "
        f"{summary['strict_cross_tenant_allowed']}"
    )
    print(
        "Context-consuming cross-tenant allowed: "
        f"{summary['context_consuming_cross_tenant_allowed']}"
    )
    print(
        "Context-drift violations: "
        f"{summary['context_drift_violations']}"
    )
    print()
    print(f"Report: {REPORT_PATH}")

    if summary["context_drift_violations"] > 0:
        print()
        print("CONTROLLED FINDING DETECTED")
        print(
            "A downstream authorization model accepted a "
            "cross-tenant request after context drift."
        )
    else:
        print()
        print("NO CONTEXT-DRIFT VIOLATION DETECTED")


if __name__ == "__main__":
    main()