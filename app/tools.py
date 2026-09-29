from app.authorization import can_access_document
from app.models import DOCUMENTS


def get_tool_definitions() -> list[dict]:
    """
    Tool definitions exposed to the model.

    These describe what the agent can request.
    They do NOT grant authorization.
    """

    return [
        {
            "type": "function",
            "function": {
                "name": "list_documents",
                "description": (
                    "List documents available to the "
                    "current tenant."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_document",
                "description": (
                    "Read a document belonging to "
                    "the current tenant."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "document_id": {
                            "type": "string",
                            "description": (
                                "The document identifier."
                            ),
                        }
                    },
                    "required": [
                        "document_id"
                    ],
                },
            },
        },
    ]


def read_document(
    tenant_id: str,
    document_id: str,
) -> dict:
    document = next(
        (
            d
            for d in DOCUMENTS
            if d.document_id == document_id
        ),
        None,
    )

    if document is None:
        return {
            "success": False,
            "error": "Document not found",
        }

    if not can_access_document(
        tenant_id,
        document,
    ):
        return {
            "success": False,
            "error": "Access denied",
        }

    return {
        "success": True,
        "document_id": document.document_id,
        "tenant_id": document.tenant_id,
        "content": document.content,
    }


def list_documents(
    tenant_id: str,
) -> dict:
    documents = [
        {
            "document_id": d.document_id,
            "tenant_id": d.tenant_id,
        }
        for d in DOCUMENTS
        if d.tenant_id == tenant_id
    ]

    return {
        "success": True,
        "documents": documents,
    }