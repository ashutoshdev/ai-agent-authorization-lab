from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationContext:
    original_tenant: str
    effective_tenant: str


@dataclass(frozen=True)
class CapabilityContext:
    capability: str
    tenant_id: str


@dataclass(frozen=True)
class Resource:
    resource_id: str
    tenant_id: str


def authorize_strict(
    context: AuthorizationContext,
    capability: CapabilityContext,
    resource: Resource,
) -> tuple[bool, str]:
    if context.original_tenant != context.effective_tenant:
        return False, "Authorization context drift detected."

    if capability.tenant_id != context.original_tenant:
        return False, "Capability is not bound to original caller."

    if resource.tenant_id != context.original_tenant:
        return False, "Resource belongs to another tenant."

    return True, "Authorization allowed."


def authorize_context_consuming(
    context: AuthorizationContext,
    capability: CapabilityContext,
    resource: Resource,
) -> tuple[bool, str]:
    if capability.capability != "read_document":
        return False, "Requested capability is not available."

    if resource.tenant_id != context.effective_tenant:
        return False, "Resource does not match effective tenant."

    return (
        True,
        "Authorization trusted effective tenant without "
        "binding it to the original caller.",
    )


def main():
    context = AuthorizationContext(
        original_tenant="tenant-b",
        effective_tenant="tenant-a",
    )

    capability = CapabilityContext(
        capability="read_document",
        tenant_id="tenant-b",
    )

    resource = Resource(
        resource_id="doc-a-1",
        tenant_id="tenant-a",
    )

    context_drift = (
        context.original_tenant != context.effective_tenant
    )

    strict_allowed, strict_reason = authorize_strict(
        context,
        capability,
        resource,
    )

    weak_allowed, weak_reason = authorize_context_consuming(
        context,
        capability,
        resource,
    )

    violation = (
        context_drift
        and capability.tenant_id == context.original_tenant
        and resource.tenant_id != context.original_tenant
        and not strict_allowed
        and weak_allowed
    )

    print("Context Drift Minimal Reproduction")
    print("=" * 40)
    print()
    print("Case: CTX-00005")
    print()
    print(f"Original tenant:      {context.original_tenant}")
    print(f"Capability tenant:    {capability.tenant_id}")
    print(f"Resource tenant:      {resource.tenant_id}")
    print(f"Resource:             {resource.resource_id}")
    print(f"Effective tenant:     {context.effective_tenant}")
    print(f"Context drift:        {context_drift}")
    print(f"Capability legitimate: {capability.tenant_id == context.original_tenant}")
    print()
    print(f"Strict authorization: {'ALLOW' if strict_allowed else 'DENY'}")
    print(f"  Reason: {strict_reason}")
    print()
    print(
        "Weak authorization:   "
        f"{'ALLOW' if weak_allowed else 'DENY'}"
    )
    print(f"  Reason: {weak_reason}")
    print()
    print(
        "RESULT: "
        + (
            "CONTROLLED CONTEXT-DRIFT FINDING"
            if violation
            else "NO FINDING"
        )
    )


if __name__ == "__main__":
    main()