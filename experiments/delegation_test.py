from app.graph import PermissionGraph
from app.pathfinder import find_paths


def build_graph():
    graph = PermissionGraph()

    # ============================================================
    # Tenant A
    # ============================================================

    graph.add_node("agent-a", "agent")
    graph.add_node("tool-a", "tool")
    graph.add_node("tenant-a", "tenant")
    graph.add_node("resource-a", "resource")

    graph.add_edge(
        "agent-a",
        "tool-a",
        "invoke",
        tenant_id="tenant-a",
    )

    graph.add_edge(
        "tool-a",
        "tenant-a",
        "access",
        tenant_id="tenant-a",
    )

    graph.add_edge(
        "tenant-a",
        "resource-a",
        "owns",
        tenant_id="tenant-a",
    )

    # ============================================================
    # Tenant B
    # ============================================================

    graph.add_node("agent-b", "agent")
    graph.add_node("tool-b", "tool")
    graph.add_node("tenant-b", "tenant")
    graph.add_node("resource-b", "resource")

    graph.add_edge(
        "agent-b",
        "tool-b",
        "invoke",
        tenant_id="tenant-b",
    )

    graph.add_edge(
        "tool-b",
        "tenant-b",
        "access",
        tenant_id="tenant-b",
    )

    graph.add_edge(
        "tenant-b",
        "resource-b",
        "owns",
        tenant_id="tenant-b",
    )

    # ============================================================
    # Shared service
    # ============================================================

    graph.add_node("shared-service", "shared_service")

    graph.add_edge(
        "tool-a",
        "shared-service",
        "invoke",
        tenant_id="tenant-a",
    )

    graph.add_edge(
        "tool-b",
        "shared-service",
        "invoke",
        tenant_id="tenant-b",
    )

    return graph


def print_paths(
    graph: PermissionGraph,
    source: str,
    target: str,
):
    paths = find_paths(
        graph,
        source,
        target,
    )

    print(f"\n{source} → {target}")

    if not paths:
        print("  No path found")
        return

    for path in paths:
        print("  " + " → ".join(path))


def main():
    graph = build_graph()

    print("=" * 70)
    print("SHARED SERVICE AUTHORIZATION EXPERIMENT")
    print("=" * 70)

    print_paths(
        graph,
        "agent-a",
        "resource-a",
    )

    print_paths(
        graph,
        "agent-b",
        "resource-b",
    )

    print_paths(
        graph,
        "agent-a",
        "resource-b",
    )

    print("\nExperiment complete.")


if __name__ == "__main__":
    main()