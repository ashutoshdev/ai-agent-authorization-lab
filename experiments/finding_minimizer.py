from dataclasses import asdict
import json

from app.authorization_engine import (
    authorize_confused_deputy,
    authorize_strict,
)
from app.delegation import AuthorizationRequest
from app.graph import Edge, PermissionGraph


REPORT_PATH = (
    "reports/minimized_authorization_finding.json"
)


AGENT = "agent:tenant-a"
TOOL = "tool:document-reader"
SERVICE = "service:shared-document-service"
RESOURCE = "resource:tenant-b-document"

CALLER_TENANT = "tenant-a"
RESOURCE_TENANT = "tenant-b"

CAPABILITY = "read_document"


def build_controlled_graph() -> PermissionGraph:
    """
    Build the complete controlled attack chain.

    agent
      |
      v
    tool
      |
      v
    shared service
      |
      v
    cross-tenant resource

    The service possesses a capability for tenant-b.
    """

    graph = PermissionGraph()

    graph.add_node(
        AGENT,
        "agent",
    )

    graph.add_node(
        TOOL,
        "tool",
    )

    graph.add_node(
        SERVICE,
        "service",
    )

    graph.add_node(
        RESOURCE,
        "resource",
    )

    graph.add_edge(
        source=AGENT,
        target=TOOL,
        action="invoke",
        tenant_id=CALLER_TENANT,
    )

    graph.add_edge(
        source=TOOL,
        target=SERVICE,
        action="call",
        tenant_id=CALLER_TENANT,
    )

    graph.add_edge(
        source=SERVICE,
        target=RESOURCE,
        action="read",
        tenant_id=RESOURCE_TENANT,
        capability=CAPABILITY,
    )

    graph.add_edge(
        source=RESOURCE,
        target=RESOURCE,
        action="owns",
        tenant_id=RESOURCE_TENANT,
    )

    return graph


def build_request() -> AuthorizationRequest:
    return AuthorizationRequest(
        caller=AGENT,
        caller_tenant=CALLER_TENANT,
        service=SERVICE,
        resource=RESOURCE,
        requested_capability=CAPABILITY,
    )


def has_complete_chain(
    graph: PermissionGraph,
) -> bool:
    """
    Require the complete agent -> tool -> service ->
    resource chain.

    This prevents the minimizer from reducing the
    finding to only the final authorization edge.
    """

    required_edges = [
        (
            AGENT,
            TOOL,
            "invoke",
        ),
        (
            TOOL,
            SERVICE,
            "call",
        ),
        (
            SERVICE,
            RESOURCE,
            "read",
        ),
        (
            RESOURCE,
            RESOURCE,
            "owns",
        ),
    ]

    for source, target, action in required_edges:
        matches = graph.find_edges(
            source=source,
            target=target,
            action=action,
        )

        if not matches:
            return False

    return True


def reproduces_finding(
    graph: PermissionGraph,
) -> bool:
    """
    The minimized graph must reproduce all security
    conditions required for this controlled finding.

    Conditions:

    1. Complete agent -> tool -> service -> resource path.
    2. Strict authorization denies.
    3. Weak authorization allows.
    4. Weak model changes the effective tenant.
    """

    if not has_complete_chain(graph):
        return False

    request = build_request()

    strict = authorize_strict(
        graph,
        request,
    )

    weak = authorize_confused_deputy(
        graph,
        request,
    )

    if strict.allowed:
        return False

    if not weak.allowed:
        return False

    if weak.effective_tenant is None:
        return False

    if weak.effective_tenant == CALLER_TENANT:
        return False

    if weak.effective_tenant != RESOURCE_TENANT:
        return False

    return True


def copy_graph(
    graph: PermissionGraph,
) -> PermissionGraph:
    """
    Create an independent copy of a PermissionGraph.
    """

    copied = PermissionGraph()

    for node in graph.nodes.values():
        copied.add_node(
            name=node.name,
            kind=node.kind,
        )

    for edge in graph.edges:
        copied.add_edge(
            source=edge.source,
            target=edge.target,
            action=edge.action,
            tenant_id=edge.tenant_id,
            capability=edge.capability,
        )

    return copied


def remove_edge(
    graph: PermissionGraph,
    index: int,
) -> PermissionGraph:
    """
    Return a copy with one edge removed.
    """

    minimized = copy_graph(graph)

    minimized.edges.pop(index)

    return minimized


def minimize_graph(
    graph: PermissionGraph,
) -> PermissionGraph:
    """
    Delta-debugging style minimization.

    An edge is removed only if the complete security
    finding still reproduces afterward.
    """

    current = copy_graph(graph)

    changed = True

    while changed:
        changed = False

        index = 0

        while index < len(current.edges):
            candidate = remove_edge(
                current,
                index,
            )

            if reproduces_finding(candidate):
                current = candidate
                changed = True
                continue

            index += 1

    return current


def edge_to_dict(edge: Edge) -> dict:
    return {
        "source": edge.source,
        "target": edge.target,
        "action": edge.action,
        "tenant_id": edge.tenant_id,
        "capability": edge.capability,
    }


def graph_to_dict(
    graph: PermissionGraph,
) -> dict:
    return {
        "nodes": {
            name: {
                "name": node.name,
                "kind": node.kind,
            }
            for name, node in graph.nodes.items()
        },
        "edges": [
            edge_to_dict(edge)
            for edge in graph.edges
        ],
    }


def evaluate_graph(
    graph: PermissionGraph,
) -> dict:
    request = build_request()

    strict = authorize_strict(
        graph,
        request,
    )

    weak = authorize_confused_deputy(
        graph,
        request,
    )

    return {
        "strict": {
            "allowed": strict.allowed,
            "reason": strict.reason,
            "effective_tenant": (
                strict.effective_tenant
            ),
        },
        "weak": {
            "allowed": weak.allowed,
            "reason": weak.reason,
            "effective_tenant": (
                weak.effective_tenant
            ),
        },
        "complete_chain": has_complete_chain(
            graph
        ),
        "reproduces_finding": reproduces_finding(
            graph
        ),
    }


def build_report(
    original: PermissionGraph,
    minimized: PermissionGraph,
) -> dict:
    original_evaluation = evaluate_graph(
        original
    )

    minimized_evaluation = evaluate_graph(
        minimized
    )

    return {
        "experiment": (
            "Authorization Finding Minimizer"
        ),
        "purpose": (
            "Minimize a controlled confused-deputy "
            "authorization finding while preserving "
            "the complete agent-to-resource chain."
        ),
        "threat_model": {
            "caller_tenant": CALLER_TENANT,
            "resource_tenant": RESOURCE_TENANT,
            "agent": AGENT,
            "tool": TOOL,
            "service": SERVICE,
            "resource": RESOURCE,
            "capability": CAPABILITY,
        },
        "security_hypothesis": (
            "A shared service that accepts a capability "
            "without binding it to the original caller "
            "tenant may permit a cross-tenant action."
        ),
        "original": {
            "edge_count": len(
                original.edges
            ),
            "graph": graph_to_dict(
                original
            ),
            "evaluation": original_evaluation,
        },
        "minimized": {
            "edge_count": len(
                minimized.edges
            ),
            "graph": graph_to_dict(
                minimized
            ),
            "evaluation": minimized_evaluation,
        },
        "minimization": {
            "edges_removed": (
                len(original.edges)
                - len(minimized.edges)
            ),
            "complete_chain_preserved": (
                has_complete_chain(
                    minimized
                )
            ),
            "finding_preserved": (
                reproduces_finding(
                    minimized
                )
            ),
        },
        "interpretation": (
            "This is a controlled local reproduction "
            "of an authorization design failure. "
            "It is not evidence of a vulnerability "
            "in a real cloud provider or production "
            "system."
        ),
    }


def save_report(
    report: dict,
    path: str = REPORT_PATH,
):
    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
        )


def main():
    original = build_controlled_graph()

    if not reproduces_finding(original):
        raise RuntimeError(
            "Controlled graph does not reproduce "
            "the expected finding."
        )

    minimized = minimize_graph(
        original
    )

    if not reproduces_finding(minimized):
        raise RuntimeError(
            "Minimization destroyed the finding."
        )

    if not has_complete_chain(minimized):
        raise RuntimeError(
            "Minimization destroyed the complete "
            "agent-to-resource chain."
        )

    report = build_report(
        original,
        minimized,
    )

    save_report(report)

    print(
        "Authorization Finding Minimizer"
    )
    print(
        "================================"
    )
    print(
        f"Original edges  : "
        f"{report['original']['edge_count']}"
    )
    print(
        f"Minimized edges : "
        f"{report['minimized']['edge_count']}"
    )
    print(
        f"Edges removed   : "
        f"{report['minimization']['edges_removed']}"
    )
    print(
        "Complete chain  : "
        f"{report['minimization']['complete_chain_preserved']}"
    )
    print(
        "Finding preserved: "
        f"{report['minimization']['finding_preserved']}"
    )
    print()
    print(
        f"Report saved to: {REPORT_PATH}"
    )


if __name__ == "__main__":
    main()