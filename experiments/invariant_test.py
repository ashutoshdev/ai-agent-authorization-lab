from app.security_analyzer import (
    check_tenant_binding_invariant,
    classify_authorization_result,
)


def test_denied_cross_tenant_request():
    result = check_tenant_binding_invariant(
        caller_tenant="tenant-a",
        effective_tenant="tenant-a",
        allowed=False,
    )

    assert result.status == "SAFE"


def test_allowed_same_tenant_request():
    result = check_tenant_binding_invariant(
        caller_tenant="tenant-a",
        effective_tenant="tenant-a",
        allowed=True,
    )

    assert result.status == "SAFE"


def test_allowed_cross_tenant_request():
    result = check_tenant_binding_invariant(
        caller_tenant="tenant-a",
        effective_tenant="tenant-b",
        allowed=True,
    )

    assert result.status == "VIOLATION"


def test_unknown_effective_tenant():
    result = check_tenant_binding_invariant(
        caller_tenant="tenant-a",
        effective_tenant=None,
        allowed=True,
    )

    assert result.status == "SUSPICIOUS"


def main():
    print("=" * 70)
    print("SECURITY INVARIANT TEST")
    print("=" * 70)

    tests = [
        (
            "Denied cross-tenant request",
            test_denied_cross_tenant_request,
        ),
        (
            "Allowed same-tenant request",
            test_allowed_same_tenant_request,
        ),
        (
            "Allowed cross-tenant request",
            test_allowed_cross_tenant_request,
        ),
        (
            "Unknown effective tenant",
            test_unknown_effective_tenant,
        ),
    ]

    passed = 0

    for name, test in tests:
        try:
            test()
            print(f"\nPASS: {name}")
            passed += 1
        except AssertionError:
            print(f"\nFAIL: {name}")

    print("\n" + "=" * 70)
    print(
        f"Result: {passed}/{len(tests)} tests passed"
    )
    print("=" * 70)

    # Demonstrate classification.
    print("\nClassification examples:")

    examples = [
        (
            "Denied",
            "tenant-a",
            "tenant-a",
            False,
        ),
        (
            "Same tenant",
            "tenant-a",
            "tenant-a",
            True,
        ),
        (
            "Cross tenant",
            "tenant-a",
            "tenant-b",
            True,
        ),
        (
            "Unknown tenant",
            "tenant-a",
            None,
            True,
        ),
    ]

    for (
        name,
        caller,
        effective,
        allowed,
    ) in examples:
        classification = classify_authorization_result(
            caller_tenant=caller,
            effective_tenant=effective,
            allowed=allowed,
        )

        print(
            f"  {name}: {classification}"
        )


if __name__ == "__main__":
    main()