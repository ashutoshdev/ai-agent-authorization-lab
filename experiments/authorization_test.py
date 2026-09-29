from app.authorization_engine import (
    authorize_confused_deputy,
    authorize_strict,
)
from app.delegation import AuthorizationRequest
from app.graph import PermissionGraph


def build_experiment_graph():
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

    # Tenant A gives the service permission to operate.
    graph.add_edge(
        "tool-a",
        "shared-document-service",
        "delegates",
        tenant_id="tenant-a",
        capability="read_document",
    )

    # The service possesses a capability for Tenant B.
    #
    # This is the critical condition being investigated.
    graph.add_edge(
        "shared-document-service",
        "resource-b",
        "read",
        tenant_id="tenant-b",
        capability="read_document",
    )

    return graph


def print_decision(
    model_name: str,
    decision,
):
    print("\n" + "-" * 70)
    print(model_name)
    print("-" * 70)

    print(f"Allowed: {decision.allowed}")
    print(f"Reason: {decision.reason}")
    print(
        f"Effective tenant: "
        f"{decision.effective_tenant}"
    )


def main():
    graph = build_experiment_graph()

    request = AuthorizationRequest(
        caller="agent-a",
        caller_tenant="tenant-a",
        service="shared-document-service",
        resource="resource-b",
        requested_capability="read_document",
    )

    print("=" * 70)
    print("DELEGATED AUTHORIZATION EXPERIMENT")
    print("=" * 70)

    print("\nRequest:")
    print(f"Caller: {request.caller}")
    print(f"Caller tenant: {request.caller_tenant}")
    print(f"Service: {request.service}")
    print(f"Resource: {request.resource}")
    print(
        f"Capability: "
        f"{request.requested_capability}"
    )

    # ============================================================
    # Model 1: Strict tenant-bound authorization
    # ============================================================

    strict_decision = authorize_strict(
        graph,
        request,
    )

    print_decision(
        "STRICT AUTHORIZATION MODEL",
        strict_decision,
    )

    # ============================================================
    # Model 2: Confused-deputy authorization
    # ============================================================

    weak_decision = authorize_confused_deputy(
        graph,
        request,
    )

    print_decision(
        "WEAK / CONFUSED-DEPUTY MODEL",
        weak_decision,
    )

    # ============================================================
    # Research conclusion
    # ============================================================

    print("\n" + "=" * 70)
    print("RESEARCH RESULT")
    print("=" * 70)

    if (
        not strict_decision.allowed
        and weak_decision.allowed
    ):
        print("\nINTERESTING CONDITION DETECTED")

        print(
            "\nThe same authorization request produces "
            "different outcomes depending on whether "
            "tenant binding is enforced."
        )

        print(
            "\nThis demonstrates the security property "
            "we need to investigate:"
        )

        print(
            "\nCaller tenant context must not be replaced "
            "implicitly by delegated service authority."
        )

    else:
        print("\nNO DIFFERENTIAL DETECTED")


if __name__ == "__main__":
    main()