from dataclasses import dataclass

from app.authorization_engine import (
    authorize_confused_deputy,
    authorize_strict,
)
from app.delegation import AuthorizationRequest
from app.security_analyzer import (
    check_tenant_binding_invariant,
    classify_authorization_result,
)
from experiments.scenario_generator import (
    Scenario,
    build_scenario,
)


@dataclass
class ScanResult:
    scenario: Scenario
    caller_tenant: str
    service: str
    resource: str
    resource_tenant: str
    capability: str
    strict_allowed: bool
    weak_allowed: bool
    strict_effective_tenant: str | None
    weak_effective_tenant: str | None
    classification: str


def get_tenants(scenario: Scenario):
    return [
        f"tenant-{index}"
        for index in range(
            1,
            scenario.tenant_count + 1,
        )
    ]


def run_scenario(
    scenario: Scenario,
) -> list[ScanResult]:
    graph = build_scenario(scenario)

    tenants = get_tenants(scenario)

    results = []

    for caller_tenant in tenants:
        for service_index in range(
            1,
            scenario.shared_service_count + 1,
        ):
            service = (
                f"shared-service-{service_index}"
            )

            for resource_tenant in tenants:
                resource = (
                    f"resource-{resource_tenant}"
                )

                if resource_tenant == caller_tenant:
                    continue

                request = AuthorizationRequest(
                    caller=f"agent-{caller_tenant}",
                    caller_tenant=caller_tenant,
                    service=service,
                    resource=resource,
                    requested_capability="read_document",
                )

                strict_decision = authorize_strict(
                    graph,
                    request,
                )

                weak_decision = authorize_confused_deputy(
                    graph,
                    request,
                )

                classification = classify_authorization_result(
                    caller_tenant=caller_tenant,
                    effective_tenant=(
                        weak_decision.effective_tenant
                    ),
                    allowed=weak_decision.allowed,
                )

                results.append(
                    ScanResult(
                        scenario=scenario,
                        caller_tenant=caller_tenant,
                        service=service,
                        resource=resource,
                        resource_tenant=resource_tenant,
                        capability="read_document",
                        strict_allowed=(
                            strict_decision.allowed
                        ),
                        weak_allowed=(
                            weak_decision.allowed
                        ),
                        strict_effective_tenant=(
                            strict_decision.effective_tenant
                        ),
                        weak_effective_tenant=(
                            weak_decision.effective_tenant
                        ),
                        classification=classification,
                    )
                )

    return results


def print_result(
    index: int,
    result: ScanResult,
):
    print("\n" + "-" * 70)

    print(
        f"Case #{index}"
    )

    print(
        f"Caller tenant: "
        f"{result.caller_tenant}"
    )

    print(
        f"Service: "
        f"{result.service}"
    )

    print(
        f"Resource: "
        f"{result.resource}"
    )

    print(
        f"Resource tenant: "
        f"{result.resource_tenant}"
    )

    print(
        f"Capability: "
        f"{result.capability}"
    )

    print(
        f"\nStrict authorization: "
        f"{'ALLOWED' if result.strict_allowed else 'DENIED'}"
    )

    print(
        f"Strict effective tenant: "
        f"{result.strict_effective_tenant}"
    )

    print(
        f"\nWeak authorization: "
        f"{'ALLOWED' if result.weak_allowed else 'DENIED'}"
    )

    print(
        f"Weak effective tenant: "
        f"{result.weak_effective_tenant}"
    )

    print(
        f"\nClassification: "
        f"{result.classification}"
    )


def main():
    scenarios = [
        Scenario(
            tenant_count=2,
            shared_service_count=1,
            cross_tenant_capability=False,
        ),
        Scenario(
            tenant_count=2,
            shared_service_count=1,
            cross_tenant_capability=True,
        ),
        Scenario(
            tenant_count=3,
            shared_service_count=1,
            cross_tenant_capability=True,
        ),
        Scenario(
            tenant_count=4,
            shared_service_count=2,
            cross_tenant_capability=True,
        ),
    ]

    print("=" * 70)
    print("AUTOMATED AUTHORIZATION SECURITY SCANNER")
    print("=" * 70)

    all_results = []

    for scenario in scenarios:
        results = run_scenario(
            scenario
        )

        all_results.extend(results)

    violations = [
        result
        for result in all_results
        if result.classification == "VIOLATION"
    ]

    suspicious = [
        result
        for result in all_results
        if result.classification == "SUSPICIOUS"
    ]

    safe = [
        result
        for result in all_results
        if result.classification == "SAFE"
    ]

    print(
        f"\nTotal authorization cases: "
        f"{len(all_results)}"
    )

    print(
        f"SAFE: "
        f"{len(safe)}"
    )

    print(
        f"SUSPICIOUS: "
        f"{len(suspicious)}"
    )

    print(
        f"VIOLATION: "
        f"{len(violations)}"
    )

    # ============================================================
    # Show violations
    # ============================================================

    if violations:
        print("\n" + "=" * 70)
        print("SECURITY VIOLATIONS")
        print("=" * 70)

        for index, result in enumerate(
            violations,
            start=1,
        ):
            print_result(
                index,
                result,
            )

    else:
        print("\nNo authorization violations detected.")

    # ============================================================
    # Differential validation
    # ============================================================

    print("\n" + "=" * 70)
    print("DIFFERENTIAL VALIDATION")
    print("=" * 70)

    differential_cases = [
        result
        for result in all_results
        if (
            not result.strict_allowed
            and result.weak_allowed
            and result.weak_effective_tenant
            != result.caller_tenant
        )
    ]

    print(
        f"\nDifferential cases: "
        f"{len(differential_cases)}"
    )

    if differential_cases:
        print(
            "\nThe weak authorization model produced "
            "cross-tenant authorization outcomes that "
            "the strict model rejected."
        )

    else:
        print(
            "\nNo differential authorization behavior detected."
        )


if __name__ == "__main__":
    main()