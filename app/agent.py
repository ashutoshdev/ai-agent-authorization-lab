from app.audit import record_event
from app.authorization_engine import (
    authorize_confused_deputy,
    authorize_strict,
)
from app.delegation import AuthorizationRequest
from app.graph import PermissionGraph
from app.tools import list_documents, read_document


class Agent:
    def __init__(
        self,
        tenant_id: str,
        graph: PermissionGraph | None = None,
    ):
        self.tenant_id = tenant_id
        self.actor = f"agent:{tenant_id}"
        self.graph = graph

    def list_documents(self):
        result = list_documents(self.tenant_id)

        record_event(
            actor=self.actor,
            tool="list_documents",
            tenant_id=self.tenant_id,
            resource="documents",
            result="success",
        )

        return result

    def read_document(self, document_id: str):
        result = read_document(
            tenant_id=self.tenant_id,
            document_id=document_id,
        )

        record_event(
            actor=self.actor,
            tool="read_document",
            tenant_id=self.tenant_id,
            resource=document_id,
            result=(
                "success"
                if result["success"]
                else "denied"
            ),
        )

        return result

    def _build_request(
        self,
        service: str,
        resource: str,
        capability: str,
    ) -> AuthorizationRequest:
        return AuthorizationRequest(
            caller=self.actor,
            caller_tenant=self.tenant_id,
            service=service,
            resource=resource,
            requested_capability=capability,
        )

    def request_shared_service_access(
        self,
        service: str,
        resource: str,
        capability: str,
    ):
        if self.graph is None:
            raise RuntimeError(
                "Agent requires a PermissionGraph "
                "for delegated authorization."
            )

        request = self._build_request(
            service=service,
            resource=resource,
            capability=capability,
        )

        decision = authorize_strict(
            self.graph,
            request,
        )

        self._record_shared_service_event(
            request=request,
            decision=decision,
            model="strict",
        )

        return {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "effective_tenant": decision.effective_tenant,
        }

    def request_shared_service_access_weak(
        self,
        service: str,
        resource: str,
        capability: str,
    ):
        if self.graph is None:
            raise RuntimeError(
                "Agent requires a PermissionGraph "
                "for delegated authorization."
            )

        request = self._build_request(
            service=service,
            resource=resource,
            capability=capability,
        )

        decision = authorize_confused_deputy(
            self.graph,
            request,
        )

        self._record_shared_service_event(
            request=request,
            decision=decision,
            model="weak",
        )

        return {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "effective_tenant": decision.effective_tenant,
        }

    def _record_shared_service_event(
        self,
        request: AuthorizationRequest,
        decision,
        model: str,
    ):
        record_event(
            actor=self.actor,
            tool="shared_service",
            tenant_id=self.tenant_id,
            resource=request.resource,
            result=(
                "allowed"
                if decision.allowed
                else "denied"
            ),
            metadata={
                "model": model,
                "service": request.service,
                "capability": request.requested_capability,
                "effective_tenant": (
                    decision.effective_tenant
                ),
                "reason": decision.reason,
            },
        )