from app.agent import Agent
from app.audit import clear_events, get_events
from app.graph import PermissionGraph


def build_graph():
    graph = PermissionGraph()

    # ============================================================
    # Tenant A
    # ============================================================

    graph.add_node("agent-a", "agent")
    graph.add_node("tool-a", "tool")
    graph.add_node("tenant-a", "tenant")

    graph.add_edge(
        "agent-a",
        "tool-a",
        "invoke",
        tenant_id="tenant-a",
        capability="read_document",
    )

    graph.add_edge(
        "tool-a",
        "tenant-a",
        "access",
        tenant_id="tenant-a",
        capability="read_document",
    )

    # ============================================================
    # Tenant B
    # ============================================================

    graph.add_node("tenant-b", "tenant")
    graph.add_node("resource-b", "resource")

    graph.add_edge(
        "tenant-b",
        "resource-b",
        "owns",
        tenant_id="tenant-b",
    )

    # ============================================================
    # Shared service
    # ============================================================

    graph.add_node(
        "shared-document-service",
        "shared_service",
    )

    # Tenant A delegates to the shared service.
    graph.add_edge(
        "tool-a",
        "shared-document-service",
        "delegates",
        tenant_id="tenant-a",
        capability="read_document",
    )

    # The shared service has a capability associated
    # with Tenant B's resource.
    graph.add_edge(
        "shared-document-service",
        "resource-b",
        "read",
        tenant_id="tenant-b",
        capability="read_document",
    )

    return graph


def print_audit_events():
    print("\nAudit trail:")
    print("-" * 70)

    for event in get_events():
        print(
            f"actor={event['actor']} | "
            f"tool={event['tool']} | "
            f"tenant={event['tenant_id']} | "
            f"resource={event['resource']} | "
            f"result={event['result']}"
        )

        if event["metadata"]:
            print(
                f"  metadata={event['metadata']}"
            )


def main():
    graph = build_graph()

    agent = Agent(
        tenant_id="tenant-a",
        graph=graph,
    )

    print("=" * 70)
    print("CONTROLLED CONFUSED-DEPUTY DIFFERENTIAL TEST")
    print("=" * 70)

    print("\nCaller:")
    print(f"  {agent.actor}")

    print("\nTarget:")
    print("  Service: shared-document-service")
    print("  Resource: resource-b")
    print("  Resource tenant: tenant-b")
    print("  Caller tenant: tenant-a")

    # ============================================================
    # Strict model
    # ============================================================

    clear_events()

    strict_result = agent.request_shared_service_access(
        service="shared-document-service",
        resource="resource-b",
        capability="read_document",
    )

    print("\n" + "-" * 70)
    print("STRICT AUTHORIZATION")
    print("-" * 70)

    print(f"Allowed: {strict_result['allowed']}")
    print(
        f"Effective tenant: "
        f"{strict_result['effective_tenant']}"
    )
    print(f"Reason: {strict_result['reason']}")

    # ============================================================
    # Weak model
    # ============================================================

    clear_events()

    weak_result = agent.request_shared_service_access_weak(
        service="shared-document-service",
        resource="resource-b",
        capability="read_document",
    )

    print("\n" + "-" * 70)
    print("WEAK AUTHORIZATION")
    print("-" * 70)

    print(f"Allowed: {weak_result['allowed']}")
    print(
        f"Effective tenant: "
        f"{weak_result['effective_tenant']}"
    )
    print(f"Reason: {weak_result['reason']}")

    print_audit_events()

    # ============================================================
    # Differential result
    # ============================================================

    print("\n" + "=" * 70)
    print("DIFFERENTIAL SECURITY RESULT")
    print("=" * 70)

    strict_cross_tenant = (
        strict_result["allowed"]
        and strict_result["effective_tenant"]
        != agent.tenant_id
    )

    weak_cross_tenant = (
        weak_result["allowed"]
        and weak_result["effective_tenant"]
        != agent.tenant_id
    )

    if not strict_cross_tenant and weak_cross_tenant:
        print("\nCONTROLLED AUTHORIZATION FAILURE REPRODUCED")

        print(
            "\nStrict model:"
            "\n  Tenant A → Tenant B = DENIED"
        )

        print(
            "\nWeak model:"
            "\n  Tenant A → Shared Service → Tenant B = ALLOWED"
        )

        print(
            "\nThis demonstrates a confused-deputy-style "
            "authorization failure in the local model."
        )

        print(
            "\nIt does NOT establish that a real cloud "
            "provider or third-party product has this flaw."
        )

    else:
        print("\nNO DIFFERENTIAL SECURITY FAILURE")


if __name__ == "__main__":
    main()