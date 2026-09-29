from app.graph import PermissionGraph
from app.pathfinder import find_paths


def build_graph():
    graph = PermissionGraph()

    graph.add_node("agent-a", "agent")
    graph.add_node("role-a", "role")
    graph.add_node("tenant-a", "tenant")
    graph.add_node("resource-a", "resource")

    graph.add_node("agent-b", "agent")
    graph.add_node("role-b", "role")
    graph.add_node("tenant-b", "tenant")
    graph.add_node("resource-b", "resource")

    graph.add_edge("agent-a", "role-a", "assumes")
    graph.add_edge("role-a", "tenant-a", "belongs_to")
    graph.add_edge("tenant-a", "resource-a", "owns")

    graph.add_edge("agent-b", "role-b", "assumes")
    graph.add_edge("role-b", "tenant-b", "belongs_to")
    graph.add_edge("tenant-b", "resource-b", "owns")

    return graph


def test_cross_tenant_isolation():
    graph = build_graph()

    paths = find_paths(
        graph,
        "agent-a",
        "resource-b",
    )

    assert not paths, (
        "SECURITY FAILURE: "
        "Tenant A can reach Tenant B resource"
    )


if __name__ == "__main__":
    test_cross_tenant_isolation()
    print("PASS: cross-tenant isolation holds")