from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import json
import random


REPORT_PATH = "reports/property_security_campaign.json"


@dataclass
class Case:
    caller_tenant: str
    resource_tenant: str
    capability_tenant: str
    subject_matches: bool
    audience_matches: bool
    expired: bool
    revoked: bool


@dataclass
class Capability:
    capability_id: str
    name: str
    issuer: str
    subject: str
    tenant_id: str
    audience: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool


@dataclass
class SecurityResult:
    case_id: int
    allowed: bool
    effective_tenant: str | None
    status: str
    reason: str


def build_capability(
    case: Case,
    case_id: int,
) -> Capability:
    now = datetime.now(timezone.utc)

    expires_at = (
        now - timedelta(minutes=5)
        if case.expired
        else now + timedelta(minutes=5)
    )

    return Capability(
        capability_id=f"cap-{case_id}",
        name="read_document",
        issuer="authorization-service",
        subject=(
            "agent:tenant-a"
            if case.subject_matches
            else "agent:unexpected"
        ),
        tenant_id=case.capability_tenant,
        audience=(
            "document-service"
            if case.audience_matches
            else "unexpected-service"
        ),
        issued_at=now,
        expires_at=expires_at,
        revoked=case.revoked,
    )


def authorize(
    case: Case,
    capability: Capability,
) -> tuple[bool, str | None, str]:
    now = datetime.now(timezone.utc)

    expected_subject = f"agent:{case.caller_tenant}"
    expected_audience = "document-service"

    if capability.revoked:
        return (
            False,
            None,
            "Capability is revoked.",
        )

    if capability.expires_at <= now:
        return (
            False,
            None,
            "Capability is expired.",
        )

    if capability.subject != expected_subject:
        return (
            False,
            None,
            "Capability subject does not match caller.",
        )

    if capability.audience != expected_audience:
        return (
            False,
            None,
            "Capability audience does not match service.",
        )

    if capability.tenant_id != case.caller_tenant:
        return (
            False,
            None,
            "Capability tenant does not match caller tenant.",
        )

    if case.resource_tenant != case.caller_tenant:
        return (
            False,
            None,
            "Resource belongs to another tenant.",
        )

    return (
        True,
        case.caller_tenant,
        "Authorization checks passed.",
    )


def classify_result(
    case: Case,
    allowed: bool,
    effective_tenant: str | None,
) -> str:
    """
    Security classification.

    PASS:
        Authorization correctly permits a valid
        same-tenant request.

    PROTECTED:
        Authorization correctly denies an invalid
        or cross-tenant request.

    VIOLATION:
        Authorization permits a request that violates
        the tenant-binding invariant.

    """

    if not allowed:
        return "PROTECTED"

    if effective_tenant != case.caller_tenant:
        return "VIOLATION"

    if case.resource_tenant != case.caller_tenant:
        return "VIOLATION"

    if case.capability_tenant != case.caller_tenant:
        return "VIOLATION"

    if not case.subject_matches:
        return "VIOLATION"

    if not case.audience_matches:
        return "VIOLATION"

    if case.expired:
        return "VIOLATION"

    if case.revoked:
        return "VIOLATION"

    return "PASS"


def generate_case(
    rng: random.Random,
) -> Case:
    tenants = [
        "tenant-a",
        "tenant-b",
        "tenant-c",
    ]

    caller_tenant = rng.choice(tenants)

    resource_tenant = rng.choice(tenants)

    capability_tenant = rng.choice(tenants)

    return Case(
        caller_tenant=caller_tenant,
        resource_tenant=resource_tenant,
        capability_tenant=capability_tenant,
        subject_matches=rng.choice(
            [True, False]
        ),
        audience_matches=rng.choice(
            [True, False]
        ),
        expired=rng.choice(
            [True, False]
        ),
        revoked=rng.choice(
            [True, False]
        ),
    )


def run_campaign(
    iterations: int = 5000,
    seed: int = 42,
) -> dict:
    rng = random.Random(seed)

    results: list[SecurityResult] = []

    violations = []
    protected = []
    passed = []

    for case_id in range(iterations):
        case = generate_case(rng)

        capability = build_capability(
            case,
            case_id,
        )

        allowed, effective_tenant, reason = authorize(
            case,
            capability,
        )

        status = classify_result(
            case,
            allowed,
            effective_tenant,
        )

        result = SecurityResult(
            case_id=case_id,
            allowed=allowed,
            effective_tenant=effective_tenant,
            status=status,
            reason=reason,
        )

        results.append(result)

        if status == "VIOLATION":
            violations.append(
                {
                    "case_id": case_id,
                    "case": asdict(case),
                    "capability": {
                        **asdict(capability),
                        "issued_at": (
                            capability.issued_at.isoformat()
                        ),
                        "expires_at": (
                            capability.expires_at.isoformat()
                        ),
                    },
                    "result": asdict(result),
                }
            )

        elif status == "PROTECTED":
            protected.append(result)

        elif status == "PASS":
            passed.append(result)

    summary = {
        "iterations": iterations,
        "seed": seed,
        "passed": len(passed),
        "protected": len(protected),
        "violations": len(violations),
        "allowed": sum(
            1
            for result in results
            if result.allowed
        ),
        "denied": sum(
            1
            for result in results
            if not result.allowed
        ),
    }

    report = {
        "experiment": (
            "Property-Based Security Campaign"
        ),
        "security_invariant": (
            "Authorization must require valid "
            "subject, audience, tenant binding, "
            "expiration, revocation state, and "
            "resource tenant binding."
        ),
        "summary": summary,
        "violations": violations,
    }

    return report


def save_report(
    report: dict,
    path: str = REPORT_PATH,
):
    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
        )


def main():
    report = run_campaign(
        iterations=5000,
        seed=42,
    )

    save_report(report)

    summary = report["summary"]

    print(
        "Property-Based Security Campaign"
    )
    print(
        "================================="
    )
    print(
        f"Iterations : {summary['iterations']}"
    )
    print(
        f"Passed     : {summary['passed']}"
    )
    print(
        f"Protected  : {summary['protected']}"
    )
    print(
        f"Violations : {summary['violations']}"
    )
    print(
        f"Allowed    : {summary['allowed']}"
    )
    print(
        f"Denied     : {summary['denied']}"
    )
    print()
    print(
        f"Report saved to: {REPORT_PATH}"
    )


if __name__ == "__main__":
    main()