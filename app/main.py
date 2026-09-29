from fastapi import FastAPI, HTTPException

from app.authorization import can_access_document
from app.models import DOCUMENTS

app = FastAPI(title="Cloud Security Research Lab")


@app.get("/")
async def root():
    return {
        "project": "Cloud Security Research Lab",
        "status": "running",
    }


@app.get("/documents/{document_id}")
async def get_document(document_id: str, tenant: str):
    document = next(
        (
            item
            for item in DOCUMENTS
            if item.document_id == document_id
        ),
        None,
    )

    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")

    if not can_access_document(tenant, document):
        raise HTTPException(status_code=403, detail="Access denied")

    return {
        "document_id": document.document_id,
        "tenant": document.tenant_id,
        "content": document.content,
    }