import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class SecurityContext:
    subject: str
    tenant_id: str
    source: str


@dataclass(frozen=True)
class TamperingCase:
    case_id: str
    injection_point: str
    original_tenant: str
    injected_tenant: str
    expected: str


@dataclass(frozen=True)
class TamperingResult:
    case_id: str
    injection_point: str
    original_tenant: str
    injected_tenant: str
    context_tenant_after_tampering: str
    allowed: bool
    effective_tenant: str
    status: str
    reason: str


@dataclass(frozen=True)
class Resource:
    resource_id: str
    tenant_id: str


def authenticated_context() -> SecurityContext:
    return SecurityContext(
        subject="agent-tenant-a",
        tenant_id="tenant-a",
        source="authenticated-session",
    )


def agent_hop(
    context: SecurityContext,
) -> SecurityContext:
    return context


def tool_hop(
    context: SecurityContext,
) -> SecurityContext:
    return context


def service_hop(
    context: SecurityContext,
) -> SecurityContext:
    return context


def authorization_boundary(
    context: SecurityContext,
    resource: Resource,
) -> tuple[bool, str, str]:
    """
    Final authorization boundary.

    The resource owner is compared against the
    authenticated security context.

    The model or request arguments cannot replace
    this context.
    """

    if (
        context.tenant_id
        != resource.tenant_id
    ):
        return (
            False,
            context.tenant_id,
            "Tenant mismatch.",
        )

    return (
        True,
        context.tenant_id,
        "Tenant matches resource.",
    )


def tamper_context(
    context: SecurityContext,
    injected_tenant: str,
) -> SecurityContext:
    """
    Simulate malicious context replacement.

    This function represents a deliberately vulnerable
    propagation point.

    The fuzzer uses it to determine whether a downstream
    authorization boundary can detect the substitution.
    """

    return SecurityContext(
        subject=context.subject,
        tenant_id=injected_tenant,
        source="tampered-context",
    )


def build_cases() -> list[TamperingCase]:
    original = "tenant-a"
    injected = "tenant-b"

    return [
        TamperingCase(
            case_id="CTX-001",
            injection_point="agent",
            original_tenant=original,
            injected_tenant=injected,
            expected="DENY",
        ),
        TamperingCase(
            case_id="CTX-002",
            injection_point="tool",
            original_tenant=original,
            injected_tenant=injected,
            expected="DENY",
        ),
        TamperingCase(
            case_id="CTX-003",
            injection_point="shared-service",
            original_tenant=original,
            injected_tenant=injected,
            expected="DENY",
        ),
        TamperingCase(
            case_id="CTX-004",
            injection_point="authorization",
            original_tenant=original,
            injected_tenant=injected,
            expected="DENY",
        ),
    ]


def execute_case(
    case: TamperingCase,
) -> TamperingResult:
    original_context = (
        authenticated_context()
    )

    resource = Resource(
        resource_id="doc-b-1",
        tenant_id="tenant-b",
    )

    context = original_context

    if case.injection_point == "agent":
        context = tamper_context(
            context,
            case.injected_tenant,
        )

        context = agent_hop(
            context
        )

        context = tool_hop(
            context
        )

        context = service_hop(
            context
        )

    elif case.injection_point == "tool":
        context = agent_hop(
            context
        )

        context = tamper_context(
            context,
            case.injected_tenant,
        )

        context = tool_hop(
            context
        )

        context = service_hop(
            context
        )

    elif case.injection_point == "shared-service":
        context = agent_hop(
            context
        )

        context = tool_hop(
            context
        )

        context = tamper_context(
            context,
            case.injected_tenant,
        )

        context = service_hop(
            context
        )

    elif case.injection_point == "authorization":
        context = agent_hop(
            context
        )

        context = tool_hop(
            context
        )

        context = service_hop(
            context
        )

        context = tamper_context(
            context,
            case.injected_tenant,
        )

    else:
        raise ValueError(
            f"Unknown injection point: "
            f"{case.injection_point}"
        )

    allowed, effective_tenant, reason = (
        authorization_boundary(
            context,
            resource,
        )
    )

    if allowed:
        status = "VIOLATION"

    elif (
        context.tenant_id
        != case.original_tenant
    ):
        status = "DETECTED_TAMPERING"

    else:
        status = "PASS"

    return TamperingResult(
        case_id=case.case_id,
        injection_point=case.injection_point,
        original_tenant=case.original_tenant,
        injected_tenant=case.injected_tenant,
        context_tenant_after_tampering=(
            context.tenant_id
        ),
        allowed=allowed,
        effective_tenant=effective_tenant,
        status=status,
        reason=reason,
    )


def save_report(
    results: list[TamperingResult],
):
    os.makedirs(
        "reports",
        exist_ok=True,
    )

    violations = [
        result
        for result in results
        if result.status
        == "VIOLATION"
    ]

    detected = [
        result
        for result in results
        if result.status
        == "DETECTED_TAMPERING"
    ]

    report = {
        "experiment": (
            "context_tampering_fuzzer"
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "security_property": (
            "A tenant substitution must never "
            "produce unauthorized resource access."
        ),
        "cases": len(results),
        "violations": len(violations),
        "detected_tampering": len(detected),
        "results": [
            asdict(result)
            for result in results
        ],
    }

    with open(
        "reports/context_tampering.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
        )


def main():
    print(
        "=" * 70
    )

    print(
        "CONTEXT-TAMPERING FUZZER"
    )

    print(
        "=" * 70
    )

    cases = build_cases()

    results = []

    for case in cases:
        result = execute_case(
            case
        )

        results.append(
            result
        )

        print(
            "\n"
            f"{result.case_id} | "
            f"{result.injection_point}"
        )

        print(
            f"  Original tenant: "
            f"{result.original_tenant}"
        )

        print(
            f"  Injected tenant: "
            f"{result.injected_tenant}"
        )

        print(
            f"  Effective tenant: "
            f"{result.effective_tenant}"
        )

        print(
            f"  Authorization: "
            f"{'ALLOWED' if result.allowed else 'DENIED'}"
        )

        print(
            f"  Status: "
            f"{result.status}"
        )

    save_report(
        results
    )

    violations = [
        result
        for result in results
        if result.status
        == "VIOLATION"
    ]

    detected = [
        result
        for result in results
        if result.status
        == "DETECTED_TAMPERING"
    ]

    print(
        "\n"
        + "=" * 70
    )

    print(
        "FUZZING COMPLETE"
    )

    print(
        "=" * 70
    )

    print(
        f"\nCases: "
        f"{len(results)}"
    )

    print(
        f"Tampering detected: "
        f"{len(detected)}"
    )

    print(
        f"Security violations: "
        f"{len(violations)}"
    )

    if violations:
        print(
            "\nSECURITY INVARIANT: VIOLATED"
        )

        for result in violations:
            print(
                f"  {result.case_id} "
                f"at {result.injection_point}"
            )
    else:
        print(
            "\nSECURITY INVARIANT: PASSED"
        )

    print(
        "\nReport:"
    )

    print(
        "  reports/context_tampering.json"
    )


if __name__ == "__main__":
    main()