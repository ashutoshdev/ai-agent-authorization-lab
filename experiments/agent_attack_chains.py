import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class SecurityContext:
    subject: str
    tenant_id: str


@dataclass(frozen=True)
class Capability:
    name: str
    tenant_id: str
    issued_to: str
    active: bool = True


@dataclass(frozen=True)
class Resource:
    resource_id: str
    tenant_id: str


@dataclass(frozen=True)
class ChainStep:
    step: int
    action: str
    tenant: str
    target: str
    result: str
    effective_tenant: str | None
    reason: str


@dataclass(frozen=True)
class ChainResult:
    chain_id: str
    name: str
    caller_tenant: str
    resource_tenant: str
    steps: list[dict]
    successful_cross_tenant_access: int
    invariant_status: str


class AgentState:
    def __init__(
        self,
        context: SecurityContext,
    ):
        self.context = context
        self.capabilities: list[
            Capability
        ] = []
        self.steps: list[ChainStep] = []

    def add_step(
        self,
        action: str,
        target: str,
        result: str,
        effective_tenant: str | None,
        reason: str,
    ):
        self.steps.append(
            ChainStep(
                step=len(self.steps) + 1,
                action=action,
                tenant=self.context.tenant_id,
                target=target,
                result=result,
                effective_tenant=effective_tenant,
                reason=reason,
            )
        )


def issue_capability(
    state: AgentState,
    capability_name: str,
    tenant_id: str,
):
    capability = Capability(
        name=capability_name,
        tenant_id=tenant_id,
        issued_to=state.context.subject,
    )

    state.capabilities.append(
        capability
    )

    state.add_step(
        action="issue_capability",
        target=capability_name,
        result="success",
        effective_tenant=tenant_id,
        reason=(
            "Capability issued for controlled "
            "laboratory scenario."
        ),
    )

    return capability


def capability_matches_context(
    state: AgentState,
    capability: Capability,
) -> bool:
    return (
        capability.active
        and capability.issued_to
        == state.context.subject
        and capability.tenant_id
        == state.context.tenant_id
    )


def strict_read_resource(
    state: AgentState,
    capability: Capability,
    resource: Resource,
):
    if not capability_matches_context(
        state,
        capability,
    ):
        state.add_step(
            action="read_resource",
            target=resource.resource_id,
            result="denied",
            effective_tenant=(
                state.context.tenant_id
            ),
            reason=(
                "Capability is not bound to "
                "the caller tenant."
            ),
        )

        return False

    if (
        resource.tenant_id
        != state.context.tenant_id
    ):
        state.add_step(
            action="read_resource",
            target=resource.resource_id,
            result="denied",
            effective_tenant=(
                state.context.tenant_id
            ),
            reason=(
                "Resource belongs to another tenant."
            ),
        )

        return False

    state.add_step(
        action="read_resource",
        target=resource.resource_id,
        result="success",
        effective_tenant=(
            state.context.tenant_id
        ),
        reason=(
            "Capability and resource belong "
            "to caller tenant."
        ),
    )

    return True


def weak_read_resource(
    state: AgentState,
    capability: Capability,
    resource: Resource,
):
    """
    Intentionally weak laboratory implementation.

    The capability tenant is treated as authoritative
    instead of the authenticated caller tenant.
    """

    if not capability.active:
        state.add_step(
            action="read_resource",
            target=resource.resource_id,
            result="denied",
            effective_tenant=None,
            reason="Capability is inactive.",
        )

        return False

    if (
        capability.name
        != "read_document"
    ):
        state.add_step(
            action="read_resource",
            target=resource.resource_id,
            result="denied",
            effective_tenant=None,
            reason="Capability is unavailable.",
        )

        return False

    effective_tenant = (
        capability.tenant_id
    )

    if (
        resource.tenant_id
        != effective_tenant
    ):
        state.add_step(
            action="read_resource",
            target=resource.resource_id,
            result="denied",
            effective_tenant=effective_tenant,
            reason=(
                "Capability tenant does not own "
                "the resource."
            ),
        )

        return False

    state.add_step(
        action="read_resource",
        target=resource.resource_id,
        result="success",
        effective_tenant=effective_tenant,
        reason=(
            "Weak model accepted the capability "
            "tenant as the effective tenant."
        ),
    )

    return True


def run_same_tenant_chain() -> ChainResult:
    context = SecurityContext(
        subject="agent-tenant-a",
        tenant_id="tenant-a",
    )

    resource = Resource(
        resource_id="doc-a-1",
        tenant_id="tenant-a",
    )

    state = AgentState(
        context
    )

    capability = issue_capability(
        state=state,
        capability_name="read_document",
        tenant_id="tenant-a",
    )

    strict_read_resource(
        state=state,
        capability=capability,
        resource=resource,
    )

    return build_result(
        chain_id="CHAIN-001",
        name="Same-tenant normal flow",
        state=state,
        resource=resource,
    )


def run_cross_tenant_chain() -> ChainResult:
    context = SecurityContext(
        subject="agent-tenant-a",
        tenant_id="tenant-a",
    )

    resource = Resource(
        resource_id="doc-b-1",
        tenant_id="tenant-b",
    )

    state = AgentState(
        context
    )

    capability = issue_capability(
        state=state,
        capability_name="read_document",
        tenant_id="tenant-b",
    )

    strict_read_resource(
        state=state,
        capability=capability,
        resource=resource,
    )

    return build_result(
        chain_id="CHAIN-002",
        name="Cross-tenant delegated capability",
        state=state,
        resource=resource,
    )


def run_weak_cross_tenant_chain() -> ChainResult:
    context = SecurityContext(
        subject="agent-tenant-a",
        tenant_id="tenant-a",
    )

    resource = Resource(
        resource_id="doc-b-1",
        tenant_id="tenant-b",
    )

    state = AgentState(
        context
    )

    capability = issue_capability(
        state=state,
        capability_name="read_document",
        tenant_id="tenant-b",
    )

    weak_read_resource(
        state=state,
        capability=capability,
        resource=resource,
    )

    return build_result(
        chain_id="CHAIN-003",
        name="Weak cross-tenant capability reuse",
        state=state,
        resource=resource,
    )


def run_capability_reuse_chain() -> ChainResult:
    context = SecurityContext(
        subject="agent-tenant-a",
        tenant_id="tenant-a",
    )

    state = AgentState(
        context
    )

    tenant_a_resource = Resource(
        resource_id="doc-a-1",
        tenant_id="tenant-a",
    )

    tenant_b_resource = Resource(
        resource_id="doc-b-1",
        tenant_id="tenant-b",
    )

    capability = issue_capability(
        state=state,
        capability_name="read_document",
        tenant_id="tenant-a",
    )

    strict_read_resource(
        state=state,
        capability=capability,
        resource=tenant_a_resource,
    )

    capability_reused = Capability(
        name=capability.name,
        tenant_id="tenant-b",
        issued_to=capability.issued_to,
        active=True,
    )

    weak_read_resource(
        state=state,
        capability=capability_reused,
        resource=tenant_b_resource,
    )

    return build_result(
        chain_id="CHAIN-004",
        name="Capability tenant substitution",
        state=state,
        resource=tenant_b_resource,
    )


def build_result(
    chain_id: str,
    name: str,
    state: AgentState,
    resource: Resource,
) -> ChainResult:
    successful_cross_tenant_access = 0

    for step in state.steps:
        if (
            step.action
            == "read_resource"
            and step.result
            == "success"
            and step.effective_tenant
            != state.context.tenant_id
        ):
            successful_cross_tenant_access += 1

    if successful_cross_tenant_access > 0:
        invariant_status = "VIOLATION"

    elif any(
        step.action == "read_resource"
        and step.result == "denied"
        and resource.tenant_id
        != state.context.tenant_id
        for step in state.steps
    ):
        invariant_status = "PROTECTED"

    else:
        invariant_status = "PASS"

    return ChainResult(
        chain_id=chain_id,
        name=name,
        caller_tenant=(
            state.context.tenant_id
        ),
        resource_tenant=(
            resource.tenant_id
        ),
        steps=[
            asdict(step)
            for step in state.steps
        ],
        successful_cross_tenant_access=(
            successful_cross_tenant_access
        ),
        invariant_status=invariant_status,
    )


def print_chain(
    result: ChainResult,
):
    print(
        "\n"
        + "-" * 70
    )

    print(
        f"{result.chain_id} | "
        f"{result.name}"
    )

    print(
        f"Caller tenant: "
        f"{result.caller_tenant}"
    )

    print(
        f"Resource tenant: "
        f"{result.resource_tenant}"
    )

    for step in result.steps:
        print(
            "\n"
            f"  Step {step['step']}: "
            f"{step['action']}"
        )

        print(
            f"    Target: "
            f"{step['target']}"
        )

        print(
            f"    Result: "
            f"{step['result']}"
        )

        print(
            f"    Effective tenant: "
            f"{step['effective_tenant']}"
        )

        print(
            f"    Reason: "
            f"{step['reason']}"
        )

    print(
        f"\n  Invariant: "
        f"{result.invariant_status}"
    )


def save_report(
    results: list[ChainResult],
):
    os.makedirs(
        "reports",
        exist_ok=True,
    )

    report = {
        "experiment": (
            "stateful_agent_attack_chains"
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "security_invariant": (
            "successful cross-tenant resource "
            "access must equal zero"
        ),
        "chain_count": len(results),
        "violations": sum(
            result.invariant_status
            == "VIOLATION"
            for result in results
        ),
        "protected": sum(
            result.invariant_status
            == "PROTECTED"
            for result in results
        ),
        "results": [
            asdict(result)
            for result in results
        ],
    }

    with open(
        "reports/agent_attack_chains.json",
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
        "STATEFUL AGENT ATTACK-CHAIN TEST"
    )

    print(
        "=" * 70
    )

    results = [
        run_same_tenant_chain(),
        run_cross_tenant_chain(),
        run_weak_cross_tenant_chain(),
        run_capability_reuse_chain(),
    ]

    for result in results:
        print_chain(
            result
        )

    save_report(
        results
    )

    violations = [
        result
        for result in results
        if result.invariant_status
        == "VIOLATION"
    ]

    print(
        "\n"
        + "=" * 70
    )

    print(
        "CHAIN TEST COMPLETE"
    )

    print(
        "=" * 70
    )

    print(
        f"\nChains tested: "
        f"{len(results)}"
    )

    print(
        f"Violations: "
        f"{len(violations)}"
    )

    if violations:
        print(
            "\nCONTROLLED AUTHORIZATION "
            "VIOLATIONS REPRODUCED:"
        )

        for result in violations:
            print(
                f"  {result.chain_id} - "
                f"{result.name}"
            )

    else:
        print(
            "\nNo authorization violations detected."
        )

    print(
        "\nReport:"
    )

    print(
        "  reports/agent_attack_chains.json"
    )


if __name__ == "__main__":
    main()