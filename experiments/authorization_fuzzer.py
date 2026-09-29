import json
import random
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from app.authorization_engine import (
    authorize_confused_deputy,
    authorize_strict,
)
from app.delegation import AuthorizationRequest
from app.graph import PermissionGraph


@dataclass(frozen=True)
class FuzzScenario:
    scenario_id: int
    tenant_count: int
    service_count: int
    capability_count: int
    cross_tenant_edges: int
    caller_tenant: str
    resource_tenant: str
    capability: str


@dataclass(frozen=True)
class FuzzFinding:
    scenario_id: int
    caller_tenant: str
    resource_tenant: str
    service: str
    capability: str
    strict_allowed: bool
    weak_allowed: bool
    strict_effective_tenant: str | None
    weak_effective_tenant: str | None
    finding_type: str
    reason: str


CAPABILITIES = [
    "read_document",
    "list_documents",
    "write_document",
]


def random_tenant(
    tenant_count: int,
) -> str:
    return f"tenant-{random.randint(1, tenant_count)}"


def random_capability() -> str:
    return random.choice(
        CAPABILITIES
    )


def build_random_graph(
    scenario: FuzzScenario,
) -> PermissionGraph:
    graph = PermissionGraph()

    tenants = [
        f"tenant-{index}"
        for index in range(
            1,
            scenario.tenant_count + 1,
        )
    ]

    services = [
        f"shared-service-{index}"
        for index in range(
            1,
            scenario.service_count + 1,
        )
    ]

    resources = [
        f"resource-{tenant}"
        for tenant in tenants
    ]

    for tenant in tenants:
        graph.add_node(
            tenant,
            "tenant",
        )

    for resource in resources:
        graph.add_node(
            resource,
            "resource",
        )

    for service in services:
        graph.add_node(
            service,
            "shared_service",
        )

    for tenant in tenants:
        agent = f"agent-{tenant}"

        graph.add_node(
            agent,
            "agent",
        )

        service = random.choice(
            services
        )

        capability = random_capability()

        graph.add_edge(
            agent,
            service,
            "delegates",
            tenant_id=tenant,
            capability=capability,
        )

    cross_tenant_edges = 0

    for service in services:
        for _ in range(
            random.randint(
                1,
                max(
                    1,
                    scenario.capability_count,
                ),
            )
        ):
            resource_tenant = random.choice(
                tenants
            )

            capability = random_capability()

            graph.add_edge(
                service,
                f"resource-{resource_tenant}",
                "read",
                tenant_id=resource_tenant,
                capability=capability,
            )

            if (
                resource_tenant
                != scenario.caller_tenant
            ):
                cross_tenant_edges += 1

    return graph


def run_fuzz_case(
    scenario: FuzzScenario,
) -> FuzzFinding | None:
    graph = build_random_graph(
        scenario
    )

    service = random.choice(
        [
            node.name
            for node in graph.nodes.values()
            if node.kind == "shared_service"
        ]
    )

    request = AuthorizationRequest(
        caller=(
            f"agent-{scenario.caller_tenant}"
        ),
        caller_tenant=scenario.caller_tenant,
        service=service,
        resource=(
            f"resource-{scenario.resource_tenant}"
        ),
        requested_capability=scenario.capability,
    )

    strict = authorize_strict(
        graph,
        request,
    )

    weak = authorize_confused_deputy(
        graph,
        request,
    )

    if (
        not strict.allowed
        and weak.allowed
        and weak.effective_tenant
        != scenario.caller_tenant
    ):
        return FuzzFinding(
            scenario_id=scenario.scenario_id,
            caller_tenant=scenario.caller_tenant,
            resource_tenant=scenario.resource_tenant,
            service=service,
            capability=scenario.capability,
            strict_allowed=strict.allowed,
            weak_allowed=weak.allowed,
            strict_effective_tenant=(
                strict.effective_tenant
            ),
            weak_effective_tenant=(
                weak.effective_tenant
            ),
            finding_type="AUTHORIZATION_DIVERGENCE",
            reason=(
                "Strict authorization rejected the "
                "request while the weak model accepted "
                "it with a different effective tenant."
            ),
        )

    return None


def generate_scenario(
    scenario_id: int,
) -> FuzzScenario:
    tenant_count = random.randint(
        2,
        6,
    )

    caller_tenant = random_tenant(
        tenant_count
    )

    resource_tenant = random_tenant(
        tenant_count
    )

    while (
        resource_tenant
        == caller_tenant
    ):
        resource_tenant = random_tenant(
            tenant_count
        )

    return FuzzScenario(
        scenario_id=scenario_id,
        tenant_count=tenant_count,
        service_count=random.randint(
            1,
            4,
        ),
        capability_count=random.randint(
            1,
            5,
        ),
        cross_tenant_edges=0,
        caller_tenant=caller_tenant,
        resource_tenant=resource_tenant,
        capability=random_capability(),
    )


def save_report(
    scenarios: list[FuzzScenario],
    findings: list[FuzzFinding],
):
    report = {
        "experiment": (
            "authorization_graph_fuzzer"
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "scenario_count": len(
            scenarios
        ),
        "finding_count": len(
            findings
        ),
        "security_property": (
            "A caller must not obtain an effective "
            "tenant different from its caller tenant."
        ),
        "findings": [
            asdict(finding)
            for finding in findings
        ],
    }

    with open(
        "reports/authorization_fuzz.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
        )


def main():
    random.seed(42)

    iterations = 1000

    print(
        "=" * 70
    )

    print(
        "AUTHORIZATION GRAPH FUZZER"
    )

    print(
        "=" * 70
    )

    print(
        f"\nIterations: {iterations}"
    )

    scenarios = []
    findings = []

    for scenario_id in range(
        1,
        iterations + 1,
    ):
        scenario = generate_scenario(
            scenario_id
        )

        scenarios.append(
            scenario
        )

        finding = run_fuzz_case(
            scenario
        )

        if finding is not None:
            findings.append(
                finding
            )

    save_report(
        scenarios=scenarios,
        findings=findings,
    )

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
        f"\nScenarios tested: "
        f"{len(scenarios)}"
    )

    print(
        f"Authorization divergences: "
        f"{len(findings)}"
    )

    if findings:
        print(
            "\nFirst findings:"
        )

        for finding in findings[:10]:
            print(
                "\n"
                f"Scenario #{finding.scenario_id}\n"
                f"  Caller: "
                f"{finding.caller_tenant}\n"
                f"  Resource tenant: "
                f"{finding.resource_tenant}\n"
                f"  Service: "
                f"{finding.service}\n"
                f"  Capability: "
                f"{finding.capability}\n"
                f"  Strict: "
                f"{'ALLOWED' if finding.strict_allowed else 'DENIED'}\n"
                f"  Weak: "
                f"{'ALLOWED' if finding.weak_allowed else 'DENIED'}\n"
                f"  Weak effective tenant: "
                f"{finding.weak_effective_tenant}"
            )

    else:
        print(
            "\nNo authorization divergences found."
        )

    print(
        "\nReport:"
    )

    print(
        "  reports/authorization_fuzz.json"
    )


if __name__ == "__main__":
    main()