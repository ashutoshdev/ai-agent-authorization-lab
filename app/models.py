from dataclasses import dataclass


@dataclass
class Document:
    document_id: str
    tenant_id: str
    content: str


DOCUMENTS = [
    Document(
        document_id="doc-a-1",
        tenant_id="tenant-a",
        content="Tenant A confidential document",
    ),
    Document(
        document_id="doc-b-1",
        tenant_id="tenant-b",
        content="Tenant B confidential document",
    ),
]