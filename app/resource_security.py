from app.models import DOCUMENTS


def get_document_tenant(
    document_id: str,
) -> str | None:
    """
    Return the tenant that owns a document.

    Returns None when the document does not exist.
    """

    document = next(
        (
            document
            for document in DOCUMENTS
            if document.document_id == document_id
        ),
        None,
    )

    if document is None:
        return None

    return document.tenant_id


def document_exists(
    document_id: str,
) -> bool:
    return get_document_tenant(
        document_id
    ) is not None


def is_cross_tenant_document_request(
    requester_tenant: str,
    document_id: str,
) -> bool:
    """
    Determine whether a document request crosses
    the tenant boundary.

    Unknown resources are NOT classified as
    cross-tenant because ownership cannot be
    established.
    """

    resource_tenant = get_document_tenant(
        document_id
    )

    if resource_tenant is None:
        return False

    return resource_tenant != requester_tenant


def classify_document_request(
    requester_tenant: str,
    document_id: str,
) -> str:
    """
    Return:

        SAME_TENANT
        CROSS_TENANT
        UNKNOWN_RESOURCE
    """

    resource_tenant = get_document_tenant(
        document_id
    )

    if resource_tenant is None:
        return "UNKNOWN_RESOURCE"

    if resource_tenant == requester_tenant:
        return "SAME_TENANT"

    return "CROSS_TENANT"