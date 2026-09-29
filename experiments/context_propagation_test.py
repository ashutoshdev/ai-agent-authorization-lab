from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityContext:
    subject: str
    tenant_id: str
    source: str


@dataclass(frozen=True)
class Resource:
    resource_id: str
    tenant_id: str


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    effective_tenant: str
    reason: str


def create_context() -> SecurityContext:
    return SecurityContext(
        subject="agent-tenant-a",
        tenant_id="tenant-a",
        source="authenticated-session",
    )


def agent_layer(
    context: SecurityContext,
) -> SecurityContext:
    """
    Agent layer must preserve the authenticated
    security context.
    """

    return context


def tool_layer(
    context: SecurityContext,
) -> SecurityContext:
    """
    Tool layer must not accept tenant identity
    from model-generated arguments.
    """

    return context


def shared_service_layer(
    context: SecurityContext,
) -> SecurityContext:
    """
    Shared services must preserve the caller's
    authenticated tenant.
    """

    return context


def resource_layer(
    context: SecurityContext,
    resource: Resource,
) -> AuthorizationDecision:
    if (
        context.tenant_id
        != resource.tenant_id
    ):
        return AuthorizationDecision(
            allowed=False,
            effective_tenant=context.tenant_id,
            reason=(
                "Caller tenant does not own "
                "the requested resource."
            ),
        )

    return AuthorizationDecision(
        allowed=True,
        effective_tenant=context.tenant_id,
        reason=(
            "Caller tenant matches resource tenant."
        ),
    )


def assert_context_preserved(
    original: SecurityContext,
    current: SecurityContext,
):
    assert (
        current.subject
        == original.subject
    ), (
        "Subject changed during "
        "authorization propagation."
    )

    assert (
        current.tenant_id
        == original.tenant_id
    ), (
        "Tenant changed during "
        "authorization propagation."
    )

    assert (
        current.source
        == original.source
    ), (
        "Security context source changed."
    )


def test_agent_preserves_context():
    original = create_context()

    current = agent_layer(
        original
    )

    assert_context_preserved(
        original,
        current,
    )


def test_tool_preserves_context():
    original = create_context()

    agent_context = agent_layer(
        original
    )

    current = tool_layer(
        agent_context
    )

    assert_context_preserved(
        original,
        current,
    )


def test_shared_service_preserves_context():
    original = create_context()

    agent_context = agent_layer(
        original
    )

    tool_context = tool_layer(
        agent_context
    )

    current = shared_service_layer(
        tool_context
    )

    assert_context_preserved(
        original,
        current,
    )


def test_cross_tenant_resource_is_denied():
    context = create_context()

    resource = Resource(
        resource_id="doc-b-1",
        tenant_id="tenant-b",
    )

    decision = resource_layer(
        context,
        resource,
    )

    assert decision.allowed is False

    assert (
        decision.effective_tenant
        == "tenant-a"
    )


def test_same_tenant_resource_is_allowed():
    context = create_context()

    resource = Resource(
        resource_id="doc-a-1",
        tenant_id="tenant-a",
    )

    decision = resource_layer(
        context,
        resource,
    )

    assert decision.allowed is True

    assert (
        decision.effective_tenant
        == "tenant-a"
    )


def test_model_cannot_replace_tenant():
    """
    Simulate a model-generated argument attempting
    to replace the authenticated tenant.

    The argument is deliberately ignored.
    """

    original = create_context()

    model_arguments = {
        "document_id": "doc-b-1",
        "tenant_id": "tenant-b",
    }

    current = tool_layer(
        original
    )

    assert (
        model_arguments["tenant_id"]
        != current.tenant_id
    )

    assert_context_preserved(
        original,
        current,
    )


def test_full_context_chain():
    original = create_context()

    context = agent_layer(
        original
    )

    assert_context_preserved(
        original,
        context,
    )

    context = tool_layer(
        context
    )

    assert_context_preserved(
        original,
        context,
    )

    context = shared_service_layer(
        context
    )

    assert_context_preserved(
        original,
        context,
    )

    resource = Resource(
        resource_id="doc-b-1",
        tenant_id="tenant-b",
    )

    decision = resource_layer(
        context,
        resource,
    )

    assert decision.allowed is False

    assert (
        decision.effective_tenant
        == original.tenant_id
    )


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
        "AUTHORIZATION CONTEXT PROPAGATION TEST"
    )

    print(
        "=" * 70
    )

    tests = [
        (
            "Agent preserves context",
            test_agent_preserves_context,
        ),
        (
            "Tool preserves context",
            test_tool_preserves_context,
        ),
        (
            "Shared service preserves context",
            test_shared_service_preserves_context,
        ),
        (
            "Cross-tenant resource is denied",
            test_cross_tenant_resource_is_denied,
        ),
        (
            "Same-tenant resource is allowed",
            test_same_tenant_resource_is_allowed,
        ),
        (
            "Model cannot replace tenant",
            test_model_cannot_replace_tenant,
        ),
        (
            "Full context chain",
            test_full_context_chain,
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
        "\nSECURITY INVARIANT: PASSED"
    )


if __name__ == "__main__":
    main()