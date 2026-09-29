from dataclasses import dataclass

from app.graph import PermissionGraph


@dataclass(frozen=True)
class Scenario:
    tenant_count: int
    shared_service_count: int
    cross_tenant_capability: bool


def build_scenario(
    scenario: Scenario,
) -> PermissionGraph:
    graph = PermissionGraph()

    tenants = [
        f"tenant-{index}"
        for index in range(1, scenario.tenant_count + 1)
    ]

    # ============================================================
    # Tenants, agents, tools and resources
    # ============================================================

    for tenant in tenants:
        agent = f"agent-{tenant}"
        tool = f"tool-{tenant}"
        resource = f"resource-{tenant}"

        graph.add_node(agent, "agent")
        graph.add_node(tool, "tool")
        graph.add_node(tenant, "tenant")
        graph.add_node(resource, "resource")

        graph.add_edge(
            agent,
            tool,
            "invoke",
            tenant_id=tenant,
            capability="read_document",
        )

        graph.add_edge(
            tool,
            tenant,
            "access",
            tenant_id=tenant,
            capability="read_document",
        )

        graph.add_edge(
            tenant,
            resource,
            "owns",
            tenant_id=tenant,
        )

    # ============================================================
    # Shared services
    # ============================================================

    for service_index in range(
        1,
        scenario.shared_service_count + 1,
    ):
        service = (
            f"shared-service-{service_index}"
        )

        graph.add_node(
            service,
            "shared_service",
        )

        for tenant in tenants:
            tool = f"tool-{tenant}"

            graph.add_edge(
                tool,
                service,
                "delegates",
                tenant_id=tenant,
                capability="read_document",
            )

        # --------------------------------------------------------
        # Normal capabilities
        # --------------------------------------------------------

        for tenant in tenants:
            resource = f"resource-{tenant}"

            if (
                not scenario.cross_tenant_capability
                or tenant == tenants[0]
            ):
                graph.add_edge(
                    service,
                    resource,
                    "read",
                    tenant_id=tenant,
                    capability="read_document",
                )

        # --------------------------------------------------------
        # Deliberately introduce one cross-tenant capability.
        # --------------------------------------------------------

        if scenario.cross_tenant_capability:
            source_tenant = tenants[0]
            target_tenant = tenants[-1]

            if source_tenant != target_tenant:
                graph.add_edge(
                    service,
                    f"resource-{target_tenant}",
                    "read",
                    tenant_id=target_tenant,
                    capability="read_document",
                )

    return graph