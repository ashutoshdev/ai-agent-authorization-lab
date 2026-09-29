from app.permissions import Capability, READ_DOCUMENT
from app.roles import Role


def test_tenant_isolation():
    role_a = Role("tenant-a-reader")

    role_a.add(
        Capability(
            name=READ_DOCUMENT,
            tenant_id="tenant-a",
        )
    )

    assert role_a.can(
        READ_DOCUMENT,
        "tenant-a",
    )

    assert not role_a.can(
        READ_DOCUMENT,
        "tenant-b",
    )


if __name__ == "__main__":
    test_tenant_isolation()
    print("PASS: tenant isolation invariant holds")