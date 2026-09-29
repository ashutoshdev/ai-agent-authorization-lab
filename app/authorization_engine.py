from app.delegation import (
    AuthorizationDecision,
    AuthorizationRequest,
)
from app.graph import PermissionGraph


def authorize_strict(
    graph: PermissionGraph,
    request: AuthorizationRequest,
) -> AuthorizationDecision:
    """
    Strict authorization model.

    The caller's tenant remains authoritative.

    A delegated capability cannot silently change
    the caller's tenant context.
    """

    resource_edges = graph.find_edges(
        source=request.service,
        target=request.resource,
        action="read",
    )

    if not resource_edges:
        return AuthorizationDecision(
            allowed=False,
            reason="Service has no capability for resource.",
            effective_tenant=None,
        )

    for edge in resource_edges:
        if edge.capability != request.requested_capability:
            continue

        if edge.tenant_id != request.caller_tenant:
            continue

        return AuthorizationDecision(
            allowed=True,
            reason=(
                "Capability matches requested action "
                "and caller tenant."
            ),
            effective_tenant=request.caller_tenant,
        )

    return AuthorizationDecision(
        allowed=False,
        reason=(
            "Resource capability exists, but its tenant "
            "does not match the caller tenant."
        ),
        effective_tenant=request.caller_tenant,
    )


def authorize_confused_deputy(
    graph: PermissionGraph,
    request: AuthorizationRequest,
) -> AuthorizationDecision:
    """
    Intentionally weak authorization model.

    This exists only for the local security experiment.

    It demonstrates what happens when a shared service
    treats possession of a capability as sufficient,
    without binding the capability to the original
    caller tenant.
    """

    resource_edges = graph.find_edges(
        source=request.service,
        target=request.resource,
        action="read",
    )

    if not resource_edges:
        return AuthorizationDecision(
            allowed=False,
            reason="Service has no capability for resource.",
            effective_tenant=None,
        )

    for edge in resource_edges:
        if edge.capability != request.requested_capability:
            continue

        return AuthorizationDecision(
            allowed=True,
            reason=(
                "Capability accepted without binding it "
                "to the caller tenant."
            ),
            effective_tenant=edge.tenant_id,
        )

    return AuthorizationDecision(
        allowed=False,
        reason="Requested capability is not available.",
        effective_tenant=None,
    )