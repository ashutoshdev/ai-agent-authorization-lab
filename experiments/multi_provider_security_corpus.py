import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from app.config import load_model_config
from app.model_provider import ModelProvider
from app.provider_factory import create_model_provider
from experiments.scenarios import SCENARIOS
from experiments.security_corpus import (
    ScenarioResult,
    execute_scenario,
)


@dataclass
class ProviderSummary:
    provider: str
    model: str
    scenario_count: int
    total_tool_requests: int
    total_cross_tenant_requests: int
    total_denied_cross_tenant_requests: int
    total_successful_cross_tenant_access: int
    total_unknown_tool_requests: int
    violations: int
    protected_attempts: int
    passes: int


def create_providers() -> list[ModelProvider]:
    """
    Build the providers that are available for this experiment.

    Mock is always available.

    Ollama is included when MODEL_PROVIDER=ollama
    or when the environment explicitly enables it.

    OpenAI-compatible providers are included when
    MODEL_API_KEY is configured.
    """

    providers: list[ModelProvider] = []

    providers.append(
        create_model_provider(
            load_model_config()
        )
    )

    return providers


def run_provider(
    provider: ModelProvider,
) -> list[ScenarioResult]:
    results = []

    print(
        "\n"
        + "=" * 70
    )

    print(
        "PROVIDER"
    )

    print(
        f"Provider: "
        f"{getattr(provider, 'model', 'unknown')}"
    )

    print(
        "=" * 70
    )

    for scenario in SCENARIOS:
        print(
            f"\nRunning "
            f"{scenario.scenario_id}..."
        )

        result = execute_scenario(
            provider=provider,
            scenario=scenario,
        )

        results.append(result)

        print(
            f"  Tool requests: "
            f"{result.tool_requests}"
        )

        print(
            f"  Cross-tenant requests: "
            f"{result.cross_tenant_requests}"
        )

        print(
            f"  Successful cross-tenant access: "
            f"{result.successful_cross_tenant_access}"
        )

        print(
            f"  Unknown tool requests: "
            f"{result.unknown_tool_requests}"
        )

        print(
            f"  Status: "
            f"{result.invariant_status}"
        )

    return results


def summarize_provider(
    results: list[ScenarioResult],
) -> ProviderSummary:
    if not results:
        raise ValueError(
            "Cannot summarize an empty provider result set."
        )

    first = results[0]

    violations = sum(
        result.invariant_status == "VIOLATION"
        for result in results
    )

    protected_attempts = sum(
        result.invariant_status == "PROTECTED"
        for result in results
    )

    passes = sum(
        result.invariant_status == "PASS"
        for result in results
    )

    return ProviderSummary(
        provider=first.provider,
        model=first.model,
        scenario_count=len(results),
        total_tool_requests=sum(
            result.tool_requests
            for result in results
        ),
        total_cross_tenant_requests=sum(
            result.cross_tenant_requests
            for result in results
        ),
        total_denied_cross_tenant_requests=sum(
            result.denied_cross_tenant_requests
            for result in results
        ),
        total_successful_cross_tenant_access=sum(
            result.successful_cross_tenant_access
            for result in results
        ),
        total_unknown_tool_requests=sum(
            result.unknown_tool_requests
            for result in results
        ),
        violations=violations,
        protected_attempts=protected_attempts,
        passes=passes,
    )


def print_comparison(
    summaries: list[ProviderSummary],
):
    print(
        "\n"
        + "=" * 70
    )

    print(
        "MODEL / SECURITY COMPARISON"
    )

    print(
        "=" * 70
    )

    headers = [
        "Provider",
        "Model",
        "Tool Requests",
        "Cross-Tenant",
        "Denied",
        "Successful",
        "Unknown",
        "Violations",
        "Protected",
    ]

    print(
        "\n"
        + " | ".join(headers)
    )

    print(
        "-" * 140
    )

    for summary in summaries:
        print(
            " | ".join(
                [
                    summary.provider,
                    summary.model,
                    str(
                        summary.total_tool_requests
                    ),
                    str(
                        summary.total_cross_tenant_requests
                    ),
                    str(
                        summary.total_denied_cross_tenant_requests
                    ),
                    str(
                        summary.total_successful_cross_tenant_access
                    ),
                    str(
                        summary.total_unknown_tool_requests
                    ),
                    str(
                        summary.violations
                    ),
                    str(
                        summary.protected_attempts
                    ),
                ]
            )
        )

    print(
        "\nSecurity interpretation:"
    )

    print(
        "  Successful cross-tenant access must remain 0."
    )

    print(
        "  A model requesting a forbidden operation is "
        "not itself an authorization violation."
    )

    print(
        "  The ToolExecutor is the security boundary."
    )


def print_scenario_matrix(
    all_results: list[ScenarioResult],
):
    print(
        "\n"
        + "=" * 70
    )

    print(
        "SCENARIO MATRIX"
    )

    print(
        "=" * 70
    )

    grouped: dict[str, list[ScenarioResult]] = {}

    for result in all_results:
        grouped.setdefault(
            result.scenario_id,
            [],
        ).append(result)

    for scenario_id, results in grouped.items():
        print(
            f"\n{scenario_id}"
        )

        print(
            "-" * 70
        )

        for result in results:
            print(
                f"{result.provider}/"
                f"{result.model}: "
                f"cross={result.cross_tenant_requests}, "
                f"denied={result.denied_cross_tenant_requests}, "
                f"successful="
                f"{result.successful_cross_tenant_access}, "
                f"status="
                f"{result.invariant_status}"
            )


def save_report(
    summaries: list[ProviderSummary],
    results: list[ScenarioResult],
):
    os.makedirs(
        "reports",
        exist_ok=True,
    )

    report = {
        "experiment": (
            "multi_provider_security_corpus"
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "security_invariant": (
            "successful_cross_tenant_access == 0"
        ),
        "interpretation": {
            "model_behavior": (
                "Tool requests show model behavior "
                "under the supplied security scenarios."
            ),
            "authorization_security": (
                "Security is evaluated by whether "
                "the application permits unauthorized "
                "cross-tenant access."
            ),
            "important_distinction": (
                "A cross-tenant tool request is not "
                "automatically a vulnerability."
            ),
        },
        "providers": [
            asdict(summary)
            for summary in summaries
        ],
        "scenario_results": [
            asdict(result)
            for result in results
        ],
    }

    with open(
        "reports/multi_provider_security.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
        )


def main():
    print(
        "=" * 70
    )

    print(
        "MULTI-PROVIDER SECURITY CORPUS"
    )

    print(
        "=" * 70
    )

    print(
        "\nSecurity invariant:"
    )

    print(
        "successful_cross_tenant_access == 0"
    )

    providers = create_providers()

    print(
        f"\nProviders configured: "
        f"{len(providers)}"
    )

    all_results = []
    summaries = []

    for provider in providers:
        results = run_provider(
            provider
        )

        all_results.extend(
            results
        )

        summaries.append(
            summarize_provider(
                results
            )
        )

    print_comparison(
        summaries
    )

    print_scenario_matrix(
        all_results
    )

    save_report(
        summaries=summaries,
        results=all_results,
    )

    total_violations = sum(
        summary.violations
        for summary in summaries
    )

    total_successful_cross_tenant = sum(
        summary.total_successful_cross_tenant_access
        for summary in summaries
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "EXPERIMENT COMPLETE"
    )

    print(
        "=" * 70
    )

    print(
        f"\nTotal provider/scenario results: "
        f"{len(all_results)}"
    )

    print(
        f"Total violations: "
        f"{total_violations}"
    )

    print(
        f"Total successful cross-tenant access: "
        f"{total_successful_cross_tenant}"
    )

    if total_successful_cross_tenant == 0:
        print(
            "\nRESULT: Security invariant held."
        )
    else:
        print(
            "\nRESULT: Security invariant violated."
        )

    print(
        "\nReport:"
    )

    print(
        "  reports/multi_provider_security.json"
    )


if __name__ == "__main__":
    main()