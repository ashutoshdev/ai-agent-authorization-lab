from app.authorization_engine import (
    authorize_confused_deputy,
    authorize_strict,
)
from app.delegation import AuthorizationRequest
from app.graph import PermissionGraph


def build_vulnerable_graph() -> PermissionGraph:
    graph = PermissionGraph()

    graph.add_node(
        "agent-tenant-a",
        "agent",
    )

    graph.add_node(
        "tool-tenant-a",
        "tool",
    )

    graph.add_node(
        "shared-service-1",
        "shared_service",
    )

    graph.add_node(
        "resource-tenant-b",
        "resource",
    )

    graph.add_node(
        "tenant-a",
        "tenant",
    )

    graph.add_node(
        "tenant-b",
        "tenant",
    )

    graph.add_edge(
        "agent-tenant-a",
        "tool-tenant-a",
        "invoke",
        tenant_id="tenant-a",
        capability="read_document",
    )

    graph.add_edge(
        "tool-tenant-a",
        "shared-service-1",
        "delegates",
        tenant_id="tenant-a",
        capability="read_document",
    )

    graph.add_edge(
        "shared-service-1",
        "resource-tenant-b",
        "read",
        tenant_id="tenant-b",
        capability="read_document",
    )

    graph.add_edge(
        "resource-tenant-b",
        "tenant-b",
        "owns",
        tenant_id="tenant-b",
    )

    return graph


def build_fixed_graph() -> PermissionGraph:
    """
    The graph is unchanged.

    The security fix is enforced by the strict
    authorization model, which binds the decision
    to the caller tenant.
    """

    return build_vulnerable_graph()


def create_request() -> AuthorizationRequest:
    return AuthorizationRequest(
        caller="agent-tenant-a",
        caller_tenant="tenant-a",
        service="shared-service-1",
        resource="resource-tenant-b",
        requested_capability="read_document",
    )


def test_strict_model_blocks_cross_tenant_access():
    graph = build_fixed_graph()

    request = create_request()

    decision = authorize_strict(
        graph,
        request,
    )

    assert decision.allowed is False

    assert (
        decision.effective_tenant
        == "tenant-a"
    )


def test_weak_model_reproduces_controlled_failure():
    """
    This test intentionally demonstrates the
    vulnerable/confused-deputy behavior.

    It proves that the experiment can reproduce
    the security divergence.
    """

    graph = build_vulnerable_graph()

    request = create_request()

    decision = authorize_confused_deputy(
        graph,
        request,
    )

    assert decision.allowed is True

    assert (
        decision.effective_tenant
        == "tenant-b"
    )

    assert (
        decision.effective_tenant
        != request.caller_tenant
    )


def test_security_invariant():
    graph = build_fixed_graph()

    request = create_request()

    decision = authorize_strict(
        graph,
        request,
    )

    if decision.allowed:
        assert (
            decision.effective_tenant
            == request.caller_tenant
        )

    else:
        assert True


def run_test(
    name,
    test,
):
    try:
        test()
        print(
            f"PASS: {name}"
        )
        return True

    except AssertionError as exc:
        print(
            f"FAIL: {name}"
        )

        if str(exc):
            print(
                f"  {exc}"
            )

        return False


def main():
    print(
        "=" * 70
    )

    print(
        "AUTHORIZATION REGRESSION TEST"
    )

    print(
        "=" * 70
    )

    tests = [
        (
            "Strict model blocks cross-tenant access",
            test_strict_model_blocks_cross_tenant_access,
        ),
        (
            "Weak model reproduces controlled failure",
            test_weak_model_reproduces_controlled_failure,
        ),
        (
            "Tenant binding invariant",
            test_security_invariant,
        ),
    ]

    passed = 0

    for name, test in tests:
        print()

        if run_test(
            name,
            test,
        ):
            passed += 1

    print(
        "\n"
        + "=" * 70
    )

    print(
        f"Result: "
        f"{passed}/{len(tests)} tests passed"
    )

    print(
        "=" * 70
    )

    if passed != len(tests):
        raise SystemExit(1)

    print(
        "\nSecurity regression suite passed."
    )


if __name__ == "__main__":
    main()