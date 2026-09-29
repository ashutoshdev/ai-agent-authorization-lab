from dataclasses import dataclass

from app.graph import PermissionGraph
from app.pathfinder import find_paths


@dataclass
class SecurityFinding:
    source: str
    target: str
    source_tenant: str
    target_tenant: str
    path: list[str]
    severity: str
    description: str
    capability: str | None = None


@dataclass
class InvariantResult:
    name: str
    status: str
    description: str
    caller_tenant: str | None = None
    effective_tenant: str | None = None


def get_agent_tenant(
    graph: PermissionGraph,
    agent_name: str,
) -> str | None:
    for edge in graph.edges:
        if (
            edge.source == agent_name
            and edge.tenant_id is not None
        ):
            return edge.tenant_id

    return None


def get_resource_tenant(
    graph: PermissionGraph,
    resource_name: str,
) -> str | None:
    for edge in graph.edges:
        if (
            edge.target == resource_name
            and edge.action == "owns"
            and edge.tenant_id is not None
        ):
            return edge.tenant_id

    return None


def find_cross_tenant_paths(
    graph: PermissionGraph,
) -> list[SecurityFinding]:
    findings = []

    agents = [
        node
        for node in graph.nodes.values()
        if node.kind == "agent"
    ]

    resources = [
        node
        for node in graph.nodes.values()
        if node.kind == "resource"
    ]

    for agent in agents:
        source_tenant = get_agent_tenant(
            graph,
            agent.name,
        )

        if source_tenant is None:
            continue

        for resource in resources:
            target_tenant = get_resource_tenant(
                graph,
                resource.name,
            )

            if target_tenant is None:
                continue

            if source_tenant == target_tenant:
                continue

            paths = find_paths(
                graph,
                agent.name,
                resource.name,
            )

            for path in paths:
                findings.append(
                    SecurityFinding(
                        source=agent.name,
                        target=resource.name,
                        source_tenant=source_tenant,
                        target_tenant=target_tenant,
                        path=path,
                        severity="HIGH",
                        description=(
                            "A path crosses a tenant boundary. "
                            "Authorization semantics must be "
                            "checked before classifying this "
                            "as a vulnerability."
                        ),
                    )
                )

    return findings


def find_suspicious_delegation_paths(
    graph: PermissionGraph,
) -> list[SecurityFinding]:
    findings = []

    agents = [
        node
        for node in graph.nodes.values()
        if node.kind == "agent"
    ]

    resources = [
        node
        for node in graph.nodes.values()
        if node.kind == "resource"
    ]

    for agent in agents:
        source_tenant = get_agent_tenant(
            graph,
            agent.name,
        )

        if source_tenant is None:
            continue

        for resource in resources:
            target_tenant = get_resource_tenant(
                graph,
                resource.name,
            )

            if target_tenant is None:
                continue

            if source_tenant == target_tenant:
                continue

            paths = find_paths(
                graph,
                agent.name,
                resource.name,
            )

            for path in paths:
                capabilities = []

                for edge in graph.edges:
                    if (
                        edge.source in path
                        and edge.target in path
                        and edge.capability is not None
                    ):
                        capabilities.append(
                            edge.capability
                        )

                findings.append(
                    SecurityFinding(
                        source=agent.name,
                        target=resource.name,
                        source_tenant=source_tenant,
                        target_tenant=target_tenant,
                        path=path,
                        severity="HIGH",
                        capability=(
                            capabilities[0]
                            if capabilities
                            else None
                        ),
                        description=(
                            "A delegated authorization path "
                            "crosses a tenant boundary."
                        ),
                    )
                )

    return findings


def check_tenant_binding_invariant(
    caller_tenant: str,
    effective_tenant: str | None,
    allowed: bool,
) -> InvariantResult:
    """
    Security invariant:

        If authorization is allowed,
        the effective tenant must equal
        the caller tenant.
    """

    if not allowed:
        return InvariantResult(
            name="tenant_binding",
            status="SAFE",
            description=(
                "Request was denied, so no unauthorized "
                "tenant transition occurred."
            ),
            caller_tenant=caller_tenant,
            effective_tenant=effective_tenant,
        )

    if effective_tenant == caller_tenant:
        return InvariantResult(
            name="tenant_binding",
            status="SAFE",
            description=(
                "Authorization remained bound to "
                "the caller tenant."
            ),
            caller_tenant=caller_tenant,
            effective_tenant=effective_tenant,
        )

    return InvariantResult(
        name="tenant_binding",
        status="VIOLATION",
        description=(
            "Authorization was allowed even though "
            "the effective tenant differed from "
            "the caller tenant."
        ),
        caller_tenant=caller_tenant,
        effective_tenant=effective_tenant,
    )


def classify_authorization_result(
    caller_tenant: str,
    effective_tenant: str | None,
    allowed: bool,
) -> str:
    """
    Return one of:

        SAFE
        SUSPICIOUS
        VIOLATION
    """

    if not allowed:
        return "SAFE"

    if effective_tenant is None:
        return "SUSPICIOUS"

    if effective_tenant != caller_tenant:
        return "VIOLATION"

    return "SAFE"