from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    name: str
    tenant_id: str


READ_DOCUMENT = "read_document"
LIST_DOCUMENTS = "list_documents"