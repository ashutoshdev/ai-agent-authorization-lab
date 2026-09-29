from app.config import ModelConfig
from app.model_provider import (
    ModelProvider,
    MockModelProvider,
    OllamaModelProvider,
    OpenAICompatibleProvider,
)


def create_model_provider(
    config: ModelConfig,
) -> ModelProvider:
    provider = config.provider.lower()

    if provider == "mock":
        return MockModelProvider(
            model=config.model,
        )

    if provider == "ollama":
        return OllamaModelProvider(
            model=config.model,
            base_url=config.base_url,
        )

    if provider in {
        "openai",
        "openai-compatible",
    }:
        if not config.api_key:
            raise RuntimeError(
                "MODEL_API_KEY is required for "
                "OpenAI-compatible providers."
            )

        return OpenAICompatibleProvider(
            model=config.model,
            base_url=config.base_url,
            api_key=config.api_key,
        )

    raise ValueError(
        f"Unsupported model provider: "
        f"{config.provider}"
    )