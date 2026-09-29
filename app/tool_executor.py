from app.audit import record_event
from app.tools import (
    list_documents,
    read_document,
)


class ToolExecutor:
    """
    Security boundary between the model and application tools.

    The model may request a tool.

    This executor decides whether that request is permitted.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

        self._tools = {
            "list_documents": self._list_documents,
            "read_document": self._read_document,
        }

    def execute(
        self,
        tool_name: str,
        arguments: dict,
    ) -> dict:
        if tool_name not in self._tools:
            record_event(
                actor=f"agent:{self.tenant_id}",
                tool=tool_name,
                tenant_id=self.tenant_id,
                resource="unknown",
                result="denied",
                metadata={
                    "reason": "Unknown tool",
                    "arguments": arguments,
                },
            )

            return {
                "success": False,
                "error": "Unknown tool",
            }

        return self._tools[tool_name](
            arguments
        )

    def _list_documents(
        self,
        arguments: dict,
    ) -> dict:
        result = list_documents(
            tenant_id=self.tenant_id,
        )

        record_event(
            actor=f"agent:{self.tenant_id}",
            tool="list_documents",
            tenant_id=self.tenant_id,
            resource="documents",
            result=(
                "success"
                if result["success"]
                else "denied"
            ),
            metadata={
                "arguments": arguments,
            },
        )

        return result

    def _read_document(
        self,
        arguments: dict,
    ) -> dict:
        document_id = arguments.get(
            "document_id"
        )

        if not document_id:
            record_event(
                actor=f"agent:{self.tenant_id}",
                tool="read_document",
                tenant_id=self.tenant_id,
                resource="unknown",
                result="denied",
                metadata={
                    "reason": (
                        "Missing document_id"
                    ),
                    "arguments": arguments,
                },
            )

            return {
                "success": False,
                "error": (
                    "document_id is required"
                ),
            }

        result = read_document(
            tenant_id=self.tenant_id,
            document_id=document_id,
        )

        record_event(
            actor=f"agent:{self.tenant_id}",
            tool="read_document",
            tenant_id=self.tenant_id,
            resource=document_id,
            result=(
                "success"
                if result["success"]
                else "denied"
            ),
            metadata={
                "arguments": arguments,
            },
        )

        return result