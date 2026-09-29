from app.permissions import Capability, READ_DOCUMENT
from app.roles import Role


def main():
    role_a = Role("tenant-a-reader")

    role_a.add(
        Capability(
            name=READ_DOCUMENT,
            tenant_id="tenant-a",
        )
    )

    print(
        "Tenant A access:",
        role_a.can(READ_DOCUMENT, "tenant-a"),
    )

    print(
        "Tenant B access:",
        role_a.can(READ_DOCUMENT, "tenant-b"),
    )


if __name__ == "__main__":
    main()