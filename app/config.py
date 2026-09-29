import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    model: str
    base_url: str
    api_key: str


def load_model_config() -> ModelConfig:
    provider = os.getenv(
        "MODEL_PROVIDER",
        "ollama",
    )

    model = os.getenv(
        "MODEL_NAME",
        "llama3.2",
    )

    base_url = os.getenv(
        "MODEL_BASE_URL",
        "http://127.0.0.1:11434",
    )

    api_key = os.getenv(
        "MODEL_API_KEY",
        "",
    )

    return ModelConfig(
        provider=provider,
        model=model,
        base_url=base_url,
        api_key=api_key,
    )