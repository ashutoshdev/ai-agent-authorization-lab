from app.graph import PermissionGraph
from app.security_analyzer import find_cross_tenant_paths


def build_safe_graph():
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
        capability="read_document",
    )

    graph.add_edge(
        "tool-a",
        "tenant-a",
        "access",
        tenant_id="tenant-a",
        capability="read_document",
    )

    graph.add_edge(
        "tenant-a",
        "resource-a",
        "owns",
        tenant_id="tenant-a",
    )

    # ============================================================
    # Shared service
    # ============================================================

    graph.add_node(
        "shared-document-service",
        "shared_service",
    )

    # Tenant A delegates access to the shared service.
    graph.add_edge(
        "tool-a",
        "shared-document-service",
        "delegates",
        tenant_id="tenant-a",
        capability="read_document",
    )

    # Shared service receives a Tenant A-scoped capability.
    graph.add_edge(
        "shared-document-service",
        "resource-a",
        "read",
        tenant_id="tenant-a",
        capability="read_document",
    )

    return graph


def build_suspicious_graph():
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
        capability="read_document",
    )

    graph.add_edge(
        "tool-a",
        "tenant-a",
        "access",
        tenant_id="tenant-a",
        capability="read_document",
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

    # ============================================================
    # Suspicious capability crossing
    # ============================================================

    # The shared service now has a capability associated
    # with Tenant B's resource.
    #
    # This does NOT prove exploitation.
    # It creates a condition that we must investigate:
    #
    # Tenant A agent
    #       |
    #       v
    # shared service
    #       |
    #       v
    # Tenant B resource
    #
    graph.add_edge(
        "shared-document-service",
        "resource-b",
        "read",
        tenant_id="tenant-b",
        capability="read_document",
    )

    return graph


def print_findings(title: str, graph: PermissionGraph):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    findings = find_cross_tenant_paths(graph)

    if not findings:
        print("\nPASS")
        print("No cross-tenant resource path detected.")
        return

    print(
        f"\nPotential cross-tenant paths detected: "
        f"{len(findings)}"
    )

    for index, finding in enumerate(findings, start=1):
        print("\n" + "-" * 70)
        print(f"Finding #{index}")
        print(f"Severity: {finding.severity}")
        print(f"Source: {finding.source}")
        print(f"Target: {finding.target}")

        print(
            f"Tenant boundary: "
            f"{finding.source_tenant} → "
            f"{finding.target_tenant}"
        )

        print("Path:")
        print("  " + " → ".join(finding.path))

        print(
            f"Description: "
            f"{finding.description}"
        )


def main():
    safe_graph = build_safe_graph()

    print_findings(
        "SAFE SHARED SERVICE SCENARIO",
        safe_graph,
    )

    suspicious_graph = build_suspicious_graph()

    print_findings(
        "SUSPICIOUS DELEGATION SCENARIO",
        suspicious_graph,
    )


if __name__ == "__main__":
    main()