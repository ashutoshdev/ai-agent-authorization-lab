import json
import os
import random
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from app.authorization_engine import (
    authorize_confused_deputy,
    authorize_strict,
)
from app.delegation import (
    AuthorizationRequest,
    Delegation,
)
from app.graph import PermissionGraph
from app.permissions import READ_DOCUMENT
from app.resource_security import get_document_tenant


PROJECT_ROOT = os.path.expanduser(
    "~/cloud-security-research-lab"
)

REPORT_DIR = os.path.join(
    PROJECT_ROOT,
    "reports",
)

REPORT_PATH = os.path.join(
    REPORT_DIR,
    "authorization_composition_fuzzer.json",
)

SEED = 42
ITERATIONS = 1000

TENANTS = [
    "tenant-a",
    "tenant-b",
]

SERVICES = [
    "document-reader",
    "shared-document-service",
]


@dataclass
class CompositionStep:
    step: int
    source: str
    target: str
    capability: str
    tenant_id: str
    context_before: str
    context_after: str
    strict_allowed: bool
    weak_allowed: bool


@dataclass
class CompositionFinding:
    case_id: str
    caller_tenant: str
    capability_tenant: str
    resource_tenant: str
    resource_id: str
    context_drift: bool
    steps: list[dict]
    all_steps_individually_valid: bool
    strict_final_allowed: bool
    weak_final_allowed: bool
    weak_effective_tenant: str | None
    composition_violation: bool


def make_request(
    caller_tenant: str,
    service: str,
    resource: str,
) -> AuthorizationRequest:
    return AuthorizationRequest(
        caller="agent",
        caller_tenant=caller_tenant,
        service=service,
        resource=resource,
        requested_capability=READ_DOCUMENT,
    )


def make_graph(
    service: str,
    resource_id: str,
    capability_tenant: str,
) -> PermissionGraph:
    graph = PermissionGraph()

    graph.add_node(
        "agent",
        "agent",
    )

    graph.add_node(
        "tool",
        "tool",
    )

    graph.add_node(
        service,
        "service",
    )

    graph.add_node(
        resource_id,
        "resource",
    )

    graph.add_edge(
        source="agent",
        target="tool",
        action="invoke",
        tenant_id=capability_tenant,
        capability=READ_DOCUMENT,
    )

    graph.add_edge(
        source="tool",
        target=service,
        action="call",
        tenant_id=capability_tenant,
        capability=READ_DOCUMENT,
    )

    graph.add_edge(
        source=service,
        target=resource_id,
        action="read",
        tenant_id=capability_tenant,
        capability=READ_DOCUMENT,
    )

    return graph


def resource_for_tenant(
    tenant: str,
) -> str:
    if tenant == "tenant-a":
        return "doc-a-1"

    return "doc-b-1"


def create_delegation_chain(
    capability_tenant: str,
) -> list[Delegation]:
    return [
        Delegation(
            source="agent",
            target="tool",
            capability=READ_DOCUMENT,
            tenant_id=capability_tenant,
        ),
        Delegation(
            source="tool",
            target="shared-document-service",
            capability=READ_DOCUMENT,
            tenant_id=capability_tenant,
        ),
        Delegation(
            source="shared-document-service",
            target="authorization",
            capability=READ_DOCUMENT,
            tenant_id=capability_tenant,
        ),
    ]


def run_case(
    rng: random.Random,
    case_number: int,
) -> CompositionFinding:
    caller_tenant = rng.choice(
        TENANTS
    )

    capability_tenant = caller_tenant

    resource_tenant = rng.choice(
        TENANTS
    )

    resource_id = resource_for_tenant(
        resource_tenant
    )

    context_tenant = caller_tenant

    delegation_chain = create_delegation_chain(
        capability_tenant
    )

    steps = []

    all_steps_individually_valid = True

    for index, delegation in enumerate(
        delegation_chain,
        start=1,
    ):
        context_before = context_tenant

        strict_graph = make_graph(
            service="shared-document-service",
            resource_id=resource_id,
            capability_tenant=(
                delegation.tenant_id
            ),
        )

        request = make_request(
            caller_tenant=context_tenant,
            service="shared-document-service",
            resource=resource_id,
        )

        strict_decision = authorize_strict(
            strict_graph,
            request,
        )

        weak_decision = authorize_confused_deputy(
            strict_graph,
            request,
        )

        if not strict_decision.allowed:
            all_steps_individually_valid = False

        should_drift = (
            resource_tenant != caller_tenant
            and rng.random() < 0.20
        )

        if should_drift:
            context_tenant = resource_tenant

        steps.append(
            CompositionStep(
                step=index,
                source=delegation.source,
                target=delegation.target,
                capability=delegation.capability,
                tenant_id=delegation.tenant_id,
                context_before=context_before,
                context_after=context_tenant,
                strict_allowed=(
                    strict_decision.allowed
                ),
                weak_allowed=(
                    weak_decision.allowed
                ),
            )
        )

    final_graph = make_graph(
        service="shared-document-service",
        resource_id=resource_id,
        capability_tenant=capability_tenant,
    )

    final_request = make_request(
        caller_tenant=context_tenant,
        service="shared-document-service",
        resource=resource_id,
    )

    strict_final = authorize_strict(
        final_graph,
        final_request,
    )

    weak_final = authorize_confused_deputy(
        final_graph,
        final_request,
    )

    context_drift = (
        context_tenant != caller_tenant
    )

    resource_owner = get_document_tenant(
        resource_id
    )

    composition_violation = (
        resource_owner is not None
        and caller_tenant != resource_owner
        and capability_tenant == caller_tenant
        and context_drift
        and all_steps_individually_valid
        and strict_final.allowed is False
        and weak_final.allowed
        and weak_final.effective_tenant
        == capability_tenant
    )

    return CompositionFinding(
        case_id=f"COMP-{case_number:04d}",
        caller_tenant=caller_tenant,
        capability_tenant=capability_tenant,
        resource_tenant=resource_tenant,
        resource_id=resource_id,
        context_drift=context_drift,
        steps=[
            asdict(step)
            for step in steps
        ],
        all_steps_individually_valid=(
            all_steps_individually_valid
        ),
        strict_final_allowed=(
            strict_final.allowed
        ),
        weak_final_allowed=(
            weak_final.allowed
        ),
        weak_effective_tenant=(
            weak_final.effective_tenant
        ),
        composition_violation=(
            composition_violation
        ),
    )


def build_report():
    rng = random.Random(
        SEED
    )

    findings = []

    cross_tenant_cases = 0
    context_drift_cases = 0
    individually_valid_cases = 0
    strict_final_allowed = 0
    weak_final_allowed = 0
    composition_violations = 0

    for case_number in range(
        1,
        ITERATIONS + 1,
    ):
        finding = run_case(
            rng,
            case_number,
        )

        findings.append(
            asdict(finding)
        )

        if (
            finding.caller_tenant
            != finding.resource_tenant
        ):
            cross_tenant_cases += 1

        if finding.context_drift:
            context_drift_cases += 1

        if finding.all_steps_individually_valid:
            individually_valid_cases += 1

        if finding.strict_final_allowed:
            strict_final_allowed += 1

        if finding.weak_final_allowed:
            weak_final_allowed += 1

        if finding.composition_violation:
            composition_violations += 1

    report = {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "seed": SEED,
        "iterations": ITERATIONS,
        "summary": {
            "cases": ITERATIONS,
            "cross_tenant_cases": (
                cross_tenant_cases
            ),
            "context_drift_cases": (
                context_drift_cases
            ),
            "individually_valid_cases": (
                individually_valid_cases
            ),
            "strict_final_allowed": (
                strict_final_allowed
            ),
            "weak_final_allowed": (
                weak_final_allowed
            ),
            "composition_violations": (
                composition_violations
            ),
        },
        "research_property": (
            "A capability issued to one tenant must "
            "not become an authorization for another "
            "tenant through multi-step context "
            "composition."
        ),
        "findings": findings,
    }

    return report


def save_report(
    report: dict,
):
    os.makedirs(
        REPORT_DIR,
        exist_ok=True,
    )

    with open(
        REPORT_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
        )


def print_summary(
    report: dict,
):
    summary = report[
        "summary"
    ]

    print()
    print(
        "AUTHORIZATION COMPOSITION FUZZER"
    )
    print(
        "================================"
    )
    print(
        f"Iterations                : "
        f"{summary['cases']}"
    )
    print(
        f"Cross-tenant cases        : "
        f"{summary['cross_tenant_cases']}"
    )
    print(
        f"Context drift cases       : "
        f"{summary['context_drift_cases']}"
    )
    print(
        f"Individually valid cases  : "
        f"{summary['individually_valid_cases']}"
    )
    print(
        f"Strict final ALLOWED      : "
        f"{summary['strict_final_allowed']}"
    )
    print(
        f"Weak final ALLOWED        : "
        f"{summary['weak_final_allowed']}"
    )
    print(
        f"Composition violations    : "
        f"{summary['composition_violations']}"
    )

    if (
        summary[
            "composition_violations"
        ]
        > 0
    ):
        print(
            "Security status           : "
            "CONTROLLED_FINDINGS"
        )
    else:
        print(
            "Security status           : "
            "NO_COMPOSITION_VIOLATIONS"
        )

    print()
    print(
        f"Report: {REPORT_PATH}"
    )


def main():
    report = build_report()

    save_report(
        report
    )

    print_summary(
        report
    )


if __name__ == "__main__":
    main()