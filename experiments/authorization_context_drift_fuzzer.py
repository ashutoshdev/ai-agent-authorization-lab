import json
import os
import random
from dataclasses import dataclass
from datetime import datetime, timezone

from app.resource_security import get_document_tenant


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports")
REPORT_PATH = os.path.join(
    REPORT_DIR,
    "authorization_context_drift_fuzzer.json",
)

SEED = 42
ITERATIONS = 5000

TENANTS = [
    "tenant-a",
    "tenant-b",
]

DOCUMENTS = {
    "tenant-a": "doc-a-1",
    "tenant-b": "doc-b-1",
}


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
    if context.original_tenant != capability.tenant_id:
        return AuthorizationResult(
            allowed=False,
            reason="Capability is not bound to original caller.",
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
        reason="All authorization contexts match.",
    )


def authorize_context_consuming(
    context: AuthorizationContext,
    capability: CapabilityContext,
    resource_tenant: str,
) -> AuthorizationResult:
    """
    Intentionally vulnerable local research model.

    The downstream authorization boundary trusts the mutable
    effective tenant rather than the original authenticated tenant.
    """

    if capability.capability != "read_document":
        return AuthorizationResult(
            allowed=False,
            reason="Capability does not authorize document reads.",
        )

    if context.effective_tenant != resource_tenant:
        return AuthorizationResult(
            allowed=False,
            reason="Effective tenant does not own resource.",
        )

    return AuthorizationResult(
        allowed=True,
        reason=(
            "Authorization trusted effective tenant without "
            "binding it to the original caller."
        ),
    )


def choose_other_tenant(tenant: str) -> str:
    return next(
        candidate
        for candidate in TENANTS
        if candidate != tenant
    )


def run_case(rng: random.Random, case_number: int) -> dict:
    original_tenant = rng.choice(TENANTS)

    resource_tenant = rng.choice(TENANTS)

    capability_tenant = rng.choice(TENANTS)

    drift_type = rng.choice(
        [
            "none",
            "same_tenant",
            "resource_tenant",
            "other_tenant",
        ]
    )

    if drift_type == "none":
        effective_tenant = original_tenant

    elif drift_type == "same_tenant":
        effective_tenant = original_tenant

    elif drift_type == "resource_tenant":
        effective_tenant = resource_tenant

    else:
        effective_tenant = choose_other_tenant(
            original_tenant
        )

    context = AuthorizationContext(
        original_tenant=original_tenant,
        effective_tenant=effective_tenant,
    )

    capability = CapabilityContext(
        capability="read_document",
        tenant_id=capability_tenant,
    )

    resource_id = DOCUMENTS[resource_tenant]

    # Verify that the resource mapping used by the fuzzer
    # matches the application's resource model.
    actual_resource_tenant = get_document_tenant(resource_id)

    if actual_resource_tenant != resource_tenant:
        raise RuntimeError(
            "Resource model mismatch: "
            f"{resource_id} expected {resource_tenant}, "
            f"got {actual_resource_tenant}"
        )

    strict = authorize_strict(
        context=context,
        capability=capability,
        resource_tenant=resource_tenant,
    )

    context_consuming = authorize_context_consuming(
        context=context,
        capability=capability,
        resource_tenant=resource_tenant,
    )

    cross_tenant = original_tenant != resource_tenant
    context_drift = (
        original_tenant != effective_tenant
    )

    # The capability itself must belong to the original caller.
    capability_is_legitimate = (
        capability_tenant == original_tenant
    )

    # This is the key research property.
    #
    # A legitimate capability issued to tenant A must not become
    # sufficient to access tenant B merely because the downstream
    # authorization context becomes tenant B.
    violation = (
        cross_tenant
        and context_drift
        and capability_is_legitimate
        and effective_tenant == resource_tenant
        and strict.allowed is False
        and context_consuming.allowed is True
    )

    return {
        "case_id": f"CTX-{case_number:05d}",
        "original_tenant": original_tenant,
        "capability_tenant": capability_tenant,
        "resource_tenant": resource_tenant,
        "resource_id": resource_id,
        "effective_tenant": effective_tenant,
        "context_drift": context_drift,
        "cross_tenant_request": cross_tenant,
        "capability_is_legitimate": capability_is_legitimate,
        "drift_type": drift_type,
        "strict_allowed": strict.allowed,
        "context_consuming_allowed": context_consuming.allowed,
        "strict_reason": strict.reason,
        "context_consuming_reason": context_consuming.reason,
        "context_drift_violation": violation,
    }


def build_report(findings: list[dict]) -> dict:
    cross_tenant = [
        finding
        for finding in findings
        if finding["cross_tenant_request"]
    ]

    drift_cases = [
        finding
        for finding in findings
        if finding["context_drift"]
    ]

    legitimate_capability_cases = [
        finding
        for finding in findings
        if finding["capability_is_legitimate"]
    ]

    violations = [
        finding
        for finding in findings
        if finding["context_drift_violation"]
    ]

    strict_allowed = [
        finding
        for finding in findings
        if finding["strict_allowed"]
    ]

    context_consuming_allowed = [
        finding
        for finding in findings
        if finding["context_consuming_allowed"]
    ]

    return {
        "metadata": {
            "experiment": "authorization_context_drift_fuzzer",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seed": SEED,
            "iterations": ITERATIONS,
            "scope": "local controlled security research lab",
            "hypothesis": (
                "A legitimate capability bound to the original "
                "tenant must not become cross-tenant authorization "
                "because a downstream authorization context changes."
            ),
        },
        "security_invariant": {
            "name": "authorization_context_integrity",
            "rule": (
                "If the original caller tenant differs from the "
                "resource tenant, a legitimate capability issued "
                "to the original caller must not authorize access "
                "through a drifted effective tenant."
            ),
        },
        "summary": {
            "cases": len(findings),
            "cross_tenant_cases": len(cross_tenant),
            "context_drift_cases": len(drift_cases),
            "legitimate_capability_cases": len(
                legitimate_capability_cases
            ),
            "strict_allowed": len(strict_allowed),
            "context_consuming_allowed": len(
                context_consuming_allowed
            ),
            "context_drift_violations": len(violations),
        },
        "findings": findings,
    }


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)

    rng = random.Random(SEED)

    findings = [
        run_case(rng, case_number)
        for case_number in range(1, ITERATIONS + 1)
    ]

    report = build_report(findings)

    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    summary = report["summary"]

    print("Authorization Context Drift Fuzzer")
    print("=" * 45)
    print(f"Seed: {SEED}")
    print(f"Cases: {summary['cases']}")
    print(f"Cross-tenant cases: {summary['cross_tenant_cases']}")
    print(f"Context drift cases: {summary['context_drift_cases']}")
    print(
        "Legitimate capability cases: "
        f"{summary['legitimate_capability_cases']}"
    )
    print(
        "Strict allowed: "
        f"{summary['strict_allowed']}"
    )
    print(
        "Context-consuming allowed: "
        f"{summary['context_consuming_allowed']}"
    )
    print(
        "Context-drift violations: "
        f"{summary['context_drift_violations']}"
    )
    print()
    print(f"Report: {REPORT_PATH}")

    if summary["context_drift_violations"] > 0:
        print()
        print("CONTROLLED FINDINGS DETECTED")
    else:
        print()
        print("NO CONTEXT-DRIFT VIOLATIONS DETECTED")


if __name__ == "__main__":
    main()