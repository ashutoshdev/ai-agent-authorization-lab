from app.models import DOCUMENTS
from app.resource_security import get_document_tenant


def strict_authorize(
    original_tenant: str,
    capability_tenant: str,
    effective_tenant: str,
    resource_tenant: str,
) -> bool:
    """
    Secure authorization invariant.

    The original authenticated tenant must remain authoritative.
    """

    if original_tenant != capability_tenant:
        return False

    if original_tenant != effective_tenant:
        return False

    if original_tenant != resource_tenant:
        return False

    return True


def test_context_drift_is_denied():
    """
    Regression case based on CTX-00005.

    tenant-b legitimately owns the capability.

    The authorization context is then changed to tenant-a.

    The resource belongs to tenant-a.

    The strict authorization model MUST deny the request.
    """

    original_tenant = "tenant-b"
    capability_tenant = "tenant-b"
    effective_tenant = "tenant-a"
    resource_id = "doc-a-1"

    resource_tenant = get_document_tenant(resource_id)

    assert resource_tenant == "tenant-a"

    allowed = strict_authorize(
        original_tenant=original_tenant,
        capability_tenant=capability_tenant,
        effective_tenant=effective_tenant,
        resource_tenant=resource_tenant,
    )

    assert allowed is False, (
        "SECURITY REGRESSION: authorization context drift "
        "was accepted."
    )


def test_same_tenant_is_allowed():
    """
    Control case.

    A legitimate same-tenant request must continue to work.
    """

    original_tenant = "tenant-a"
    capability_tenant = "tenant-a"
    effective_tenant = "tenant-a"
    resource_id = "doc-a-1"

    resource_tenant = get_document_tenant(resource_id)

    allowed = strict_authorize(
        original_tenant=original_tenant,
        capability_tenant=capability_tenant,
        effective_tenant=effective_tenant,
        resource_tenant=resource_tenant,
    )

    assert allowed is True


def test_cross_tenant_without_drift_is_denied():
    """
    Control case.

    Even without context drift, a tenant-a caller must not
    access a tenant-b resource.
    """

    original_tenant = "tenant-a"
    capability_tenant = "tenant-a"
    effective_tenant = "tenant-a"
    resource_id = "doc-b-1"

    resource_tenant = get_document_tenant(resource_id)

    allowed = strict_authorize(
        original_tenant=original_tenant,
        capability_tenant=capability_tenant,
        effective_tenant=effective_tenant,
        resource_tenant=resource_tenant,
    )

    assert allowed is False


def main():
    tests = [
        (
            "context drift must be denied",
            test_context_drift_is_denied,
        ),
        (
            "same tenant must be allowed",
            test_same_tenant_is_allowed,
        ),
        (
            "cross tenant without drift must be denied",
            test_cross_tenant_without_drift_is_denied,
        ),
    ]

    passed = 0

    print("Context Drift Regression Test")
    print("=" * 40)

    for name, test in tests:
        try:
            test()
            print(f"PASS: {name}")
            passed += 1
        except AssertionError as exc:
            print(f"FAIL: {name}")
            print(f"      {exc}")

    print()
    print(f"Result: {passed}/{len(tests)} passed")

    if passed != len(tests):
        raise SystemExit(1)

    print("REGRESSION SUITE PASSED")


if __name__ == "__main__":
    main()