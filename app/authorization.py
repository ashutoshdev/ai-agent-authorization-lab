from app.models import Document


def can_access_document(
    requester_tenant: str,
    document: Document,
) -> bool:
    return requester_tenant == document.tenant_id