from app.graph import PermissionGraph
from app.pathfinder import find_paths


def build_graph():
    graph = PermissionGraph()

    # Tenant A
    graph.add_node("agent-a", "agent")
    graph.add_node("role-a-reader", "role")
    graph.add_node("tenant-a", "tenant")
    graph.add_node("doc-a-1", "document")

    graph.add_edge("agent-a", "role-a-reader", "assumes")
    graph.add_edge("role-a-reader", "tenant-a", "belongs_to")
    graph.add_edge("tenant-a", "doc-a-1", "owns")

    # Tenant B
    graph.add_node("agent-b", "agent")
    graph.add_node("role-b-reader", "role")
    graph.add_node("tenant-b", "tenant")
    graph.add_node("doc-b-1", "document")

    graph.add_edge("agent-b", "role-b-reader", "assumes")
    graph.add_edge("role-b-reader", "tenant-b", "belongs_to")
    graph.add_edge("tenant-b", "doc-b-1", "owns")

    return graph


if __name__ == "__main__":
    graph = build_graph()

    print("Tenant A → Tenant A resource:")
    paths = find_paths(graph, "agent-a", "doc-a-1")

    for path in paths:
        print("  " + " → ".join(path))

    print("\nTenant A → Tenant B resource:")
    paths = find_paths(graph, "agent-a", "doc-b-1")

    if not paths:
        print("  PASS: no reachable path")
    else:
        for path in paths:
            print("  WARNING:", " → ".join(path))