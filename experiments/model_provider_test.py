from app.model_agent import ModelAgent
from app.model_provider import MockModelProvider


def main():
    print("=" * 70)
    print("MODEL PROVIDER ABSTRACTION TEST")
    print("=" * 70)

    provider = MockModelProvider(
        model="mock-security-model"
    )

    agent = ModelAgent(
        tenant_id="tenant-a",
        provider=provider,
    )

    response = agent.run(
        prompt=(
            "Analyze the available tools and determine "
            "which operation should be performed."
        ),
        tools=[
            {
                "name": "read_document",
                "description": (
                    "Read a document belonging to "
                    "the caller's tenant."
                ),
            }
        ],
    )

    print("\nProvider:")
    print(f"  {response.provider}")

    print("\nModel:")
    print(f"  {response.model}")

    print("\nResponse:")
    print(f"  {response.text}")

    print("\nTool calls:")
    print(f"  {response.tool_calls}")

    print("\nPASS")


if __name__ == "__main__":
    main()