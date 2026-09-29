from dataclasses import dataclass
import json
import urllib.error
import urllib.request
from typing import Protocol


@dataclass(frozen=True)
class ModelResponse:
    provider: str
    model: str
    text: str
    tool_calls: list[dict]


class ModelProvider(Protocol):
    def generate(
        self,
        prompt: str,
        tools: list[dict] | None = None,
    ) -> ModelResponse:
        ...


class MockModelProvider:
    """
    Deterministic provider for controlled experiments.
    """

    def __init__(
        self,
        model: str = "mock-security-model",
    ):
        self.model = model

    def generate(
        self,
        prompt: str,
        tools: list[dict] | None = None,
    ) -> ModelResponse:
        return ModelResponse(
            provider="mock",
            model=self.model,
            text=(
                "Mock model response for controlled "
                "security research."
            ),
            tool_calls=[],
        )


class OllamaModelProvider:
    """
    Native Ollama API provider.
    """

    def __init__(
        self,
        model: str,
        base_url: str = (
            "http://127.0.0.1:11434"
        ),
        timeout: int = 120,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def generate(
        self,
        prompt: str,
        tools: list[dict] | None = None,
    ) -> ModelResponse:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "stream": False,
        }

        if tools:
            payload["tools"] = tools

        body = json.dumps(
            payload
        ).encode("utf-8")

        request = urllib.request.Request(
            url=(
                f"{self.base_url}"
                "/api/chat"
            ),
            data=body,
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                response_body = response.read()

        except urllib.error.URLError as exc:
            raise RuntimeError(
                "Could not connect to Ollama at "
                f"{self.base_url}."
            ) from exc

        data = json.loads(
            response_body.decode("utf-8")
        )

        message = data.get(
            "message",
            {},
        )

        return ModelResponse(
            provider="ollama",
            model=self.model,
            text=message.get(
                "content",
                "",
            ),
            tool_calls=message.get(
                "tool_calls",
                [],
            ),
        )


class OpenAICompatibleProvider:
    """
    Provider for APIs implementing the OpenAI-compatible
    chat-completions interface.

    Examples of compatible infrastructure include many
    local inference servers and hosted model gateways.

    Authentication is supplied through the api_key argument.
    """

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str,
        timeout: int = 120,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def generate(
        self,
        prompt: str,
        tools: list[dict] | None = None,
    ) -> ModelResponse:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        if tools:
            payload["tools"] = tools

        body = json.dumps(
            payload
        ).encode("utf-8")

        request = urllib.request.Request(
            url=(
                f"{self.base_url}"
                "/chat/completions"
            ),
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": (
                    f"Bearer {self.api_key}"
                ),
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                response_body = response.read()

        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            raise RuntimeError(
                "OpenAI-compatible API returned "
                f"HTTP {exc.code}: {error_body}"
            ) from exc

        except urllib.error.URLError as exc:
            raise RuntimeError(
                "Could not connect to the "
                "OpenAI-compatible endpoint at "
                f"{self.base_url}."
            ) from exc

        data = json.loads(
            response_body.decode("utf-8")
        )

        choices = data.get(
            "choices",
            [],
        )

        if not choices:
            raise RuntimeError(
                "OpenAI-compatible API returned "
                "no choices."
            )

        message = choices[0].get(
            "message",
            {},
        )

        return ModelResponse(
            provider="openai-compatible",
            model=self.model,
            text=message.get(
                "content",
                "",
            ) or "",
            tool_calls=message.get(
                "tool_calls",
                [],
            ) or [],
        )