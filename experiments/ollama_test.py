from app.audit import clear_events, get_events
from app.model_agent import ModelAgent
from app.model_provider import OllamaModelProvider


def main():
    clear_events()

    provider = OllamaModelProvider(
        model="llama3.2",
    )

    agent = ModelAgent(
        tenant_id="tenant-a",
        provider=provider,
    )

    print("=" * 70)
    print("REAL MODEL → MODEL AGENT TEST")
    print("=" * 70)

    print("\nAgent:")
    print(f"  {agent.actor}")

    print("\nProvider:")
    print(f"  {provider.model}")

    response = agent.run(
        prompt=(
            "You are an AI agent operating inside a "
            "controlled multi-tenant security research lab. "
            "Explain briefly why tenant authorization should "
            "be enforced by the application rather than "
            "trusted to the language model."
        )
    )

    print("\nModel response:")
    print("-" * 70)
    print(response.text)

    print("\nProvider:")
    print(f"  {response.provider}")

    print("\nModel:")
    print(f"  {response.model}")

    print("\nTool calls:")
    print(f"  {response.tool_calls}")

    print("\nAudit events:")
    print("-" * 70)

    for event in get_events():
        print(
            f"actor={event['actor']} | "
            f"tool={event['tool']} | "
            f"tenant={event['tenant_id']} | "
            f"result={event['result']} | "
            f"metadata={event['metadata']}"
        )

    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()