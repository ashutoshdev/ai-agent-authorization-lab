import json

from app.audit import clear_events, get_events
from app.model_agent import ModelAgent
from app.model_provider import OllamaModelProvider
from app.tool_executor import ToolExecutor
from app.tools import get_tool_definitions


def main():
    clear_events()

    provider = OllamaModelProvider(
        model="llama3.2",
    )

    agent = ModelAgent(
        tenant_id="tenant-a",
        provider=provider,
    )

    executor = ToolExecutor(
        tenant_id="tenant-a",
    )

    tools = get_tool_definitions()

    print("=" * 70)
    print("LLAMA 3.2 → REAL TOOL-CALL TEST")
    print("=" * 70)

    print("\nAgent:")
    print(f"  {agent.actor}")

    print("\nProvider:")
    print(f"  {provider.model}")

    print("\nAvailable tools:")
    for tool in tools:
        print(
            f"  {tool['function']['name']}"
        )

    response = agent.run(
        prompt=(
            "You are an AI agent operating for tenant-a "
            "inside a controlled multi-tenant security "
            "research lab. "
            "Use the available tools when appropriate. "
            "List the documents available to your tenant."
        ),
        tools=tools,
    )

    print("\nModel response:")
    print("-" * 70)
    print(response.text)

    print("\nTool calls:")
    print("-" * 70)

    if not response.tool_calls:
        print("  []")
    else:
        for tool_call in response.tool_calls:
            print(
                json.dumps(
                    tool_call,
                    indent=2,
                )
            )

    print("\nTool execution:")
    print("-" * 70)

    for tool_call in response.tool_calls:
        function = tool_call.get(
            "function",
            {},
        )

        tool_name = function.get(
            "name"
        )

        arguments = function.get(
            "arguments",
            {},
        )

        if isinstance(arguments, str):
            try:
                arguments = json.loads(
                    arguments
                )
            except json.JSONDecodeError:
                arguments = {}

        print(f"Tool: {tool_name}")
        print(
            f"Arguments: "
            f"{json.dumps(arguments)}"
        )

        result = executor.execute(
            tool_name=tool_name,
            arguments=arguments,
        )

        print(
            "Result: "
            f"{json.dumps(result, indent=2)}"
        )
        print()

    print("\nAudit events:")
    print("-" * 70)

    for event in get_events():
        print(
            f"actor={event['actor']} | "
            f"tool={event['tool']} | "
            f"tenant={event['tenant_id']} | "
            f"resource={event['resource']} | "
            f"result={event['result']} | "
            f"metadata={event['metadata']}"
        )

    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()