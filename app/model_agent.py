from app.audit import record_event
from app.model_provider import (
    ModelProvider,
    ModelResponse,
)


class ModelAgent:
    """
    Model-independent AI agent.

    The model provider generates decisions.
    Authorization remains outside the model.
    """

    def __init__(
        self,
        tenant_id: str,
        provider: ModelProvider,
    ):
        self.tenant_id = tenant_id
        self.actor = f"agent:{tenant_id}"
        self.provider = provider

    def run(
        self,
        prompt: str,
        tools: list[dict] | None = None,
    ) -> ModelResponse:
        response = self.provider.generate(
            prompt=prompt,
            tools=tools,
        )

        record_event(
            actor=self.actor,
            tool="model.generate",
            tenant_id=self.tenant_id,
            resource="model",
            result="success",
            metadata={
                "provider": response.provider,
                "model": response.model,
                "tool_call_count": len(
                    response.tool_calls
                ),
            },
        )

        return response