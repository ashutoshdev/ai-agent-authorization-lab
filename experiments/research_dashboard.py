import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


REPORT_DIR = Path("reports")


REPORT_FILES = {
    "security_corpus": "reports/security_corpus.json",
    "multi_provider": "reports/multi_provider_security.json",
    "authorization_fuzz": "reports/authorization_fuzz.json",
    "minimized_finding": (
        "reports/minimized_authorization_finding.json"
    ),
    "end_to_end": "reports/end_to_end_security.json",
    "tool_mutation": "reports/tool_call_mutation.json",
    "context_tampering": "reports/context_tampering.json",
    "attack_chains": "reports/agent_attack_chains.json",
    "property_campaign": (
        "reports/property_security_campaign.json"
    ),
}


@dataclass
class EvidenceStatus:
    name: str
    path: str
    exists: bool
    size_bytes: int


@dataclass
class DashboardSummary:
    generated_at: str
    evidence_files: int
    available_files: int
    missing_files: int
    fuzz_cases: int
    property_cases: int
    attack_chains: int
    mutation_cases: int
    end_to_end_scenarios: int
    successful_cross_tenant_access: int
    controlled_findings: int
    security_violations: int
    overall_status: str


def load_json(path: str):
    if not os.path.exists(path):
        return None

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:
            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError,
    ):
        return None


def inspect_evidence():
    results = []

    for name, path in REPORT_FILES.items():
        exists = os.path.exists(path)

        size = (
            os.path.getsize(path)
            if exists
            else 0
        )

        results.append(
            EvidenceStatus(
                name=name,
                path=path,
                exists=exists,
                size_bytes=size,
            )
        )

    return results


def get_nested(
    data,
    *keys,
    default=0,
):
    current = data

    for key in keys:
        if not isinstance(
            current,
            dict,
        ):
            return default

        current = current.get(key)

        if current is None:
            return default

    return current


def first_value(
    data,
    paths,
    default=0,
):
    if not isinstance(data, dict):
        return default

    for path in paths:
        value = get_nested(
            data,
            *path,
            default=None,
        )

        if value is not None:
            return value

    return default


def get_authorization_fuzz_count(
    data,
):
    return int(
        first_value(
            data,
            [
                ("scenario_count",),
                ("scenarios_tested",),
                (
                    "summary",
                    "scenario_count",
                ),
                (
                    "summary",
                    "scenarios_tested",
                ),
                ("iterations",),
            ],
            default=0,
        )
    )


def get_property_count(data):
    return int(
        first_value(
            data,
            [
                ("iterations",),
                (
                    "summary",
                    "iterations",
                ),
                ("case_count",),
                (
                    "summary",
                    "case_count",
                ),
            ],
            default=0,
        )
    )


def get_attack_chain_count(data):
    return int(
        first_value(
            data,
            [
                ("chain_count",),
                ("chains_tested",),
                (
                    "summary",
                    "chain_count",
                ),
                (
                    "summary",
                    "chains_tested",
                ),
            ],
            default=0,
        )
    )


def get_mutation_count(data):
    return int(
        first_value(
            data,
            [
                ("mutation_count",),
                (
                    "summary",
                    "mutation_count",
                ),
            ],
            default=0,
        )
    )


def get_end_to_end_scenarios(data):
    return int(
        first_value(
            data,
            [
                (
                    "summary",
                    "scenario_count",
                ),
                ("scenario_count",),
            ],
            default=0,
        )
    )


def get_successful_cross_tenant(data):
    return int(
        first_value(
            data,
            [
                (
                    "summary",
                    "successful_cross_tenant_access",
                ),
                (
                    "successful_cross_tenant",
                ),
                (
                    "successful_cross_tenant_access",
                ),
            ],
            default=0,
        )
    )


def get_controlled_findings(
    authorization_fuzz,
    context,
    attack_chains,
):
    total = 0

    total += int(
        first_value(
            authorization_fuzz,
            [
                ("finding_count",),
                (
                    "summary",
                    "finding_count",
                ),
                (
                    "summary",
                    "authorization_divergences",
                ),
                (
                    "authorization_divergences",
                ),
            ],
            default=0,
        )
    )

    total += int(
        first_value(
            context,
            [
                ("violations",),
                (
                    "summary",
                    "violations",
                ),
            ],
            default=0,
        )
    )

    total += int(
        first_value(
            attack_chains,
            [
                ("violations",),
                (
                    "summary",
                    "violations",
                ),
            ],
            default=0,
        )
    )

    return total


def get_actual_security_violations(
    end_to_end,
    mutation,
    property_campaign,
):
    total = 0

    total += int(
        first_value(
            end_to_end,
            [
                (
                    "summary",
                    "successful_cross_tenant_access",
                ),
                (
                    "successful_cross_tenant",
                ),
                (
                    "successful_cross_tenant_access",
                ),
            ],
            default=0,
        )
    )

    total += int(
        first_value(
            mutation,
            [
                (
                    "summary",
                    "successful_cross_tenant",
                ),
                (
                    "successful_cross_tenant",
                ),
            ],
            default=0,
        )
    )

    total += int(
        first_value(
            property_campaign,
            [
                (
                    "summary",
                    "violations",
                ),
                ("violations",),
            ],
            default=0,
        )
    )

    return total


def build_summary(evidence):
    authorization_fuzz = load_json(
        REPORT_FILES[
            "authorization_fuzz"
        ]
    )

    end_to_end = load_json(
        REPORT_FILES[
            "end_to_end"
        ]
    )

    mutation = load_json(
        REPORT_FILES[
            "tool_mutation"
        ]
    )

    context = load_json(
        REPORT_FILES[
            "context_tampering"
        ]
    )

    attack_chains = load_json(
        REPORT_FILES[
            "attack_chains"
        ]
    )

    property_campaign = load_json(
        REPORT_FILES[
            "property_campaign"
        ]
    )

    fuzz_cases = (
        get_authorization_fuzz_count(
            authorization_fuzz
        )
    )

    property_cases = (
        get_property_count(
            property_campaign
        )
    )

    chain_count = (
        get_attack_chain_count(
            attack_chains
        )
    )

    mutation_cases = (
        get_mutation_count(
            mutation
        )
    )

    end_to_end_scenarios = (
        get_end_to_end_scenarios(
            end_to_end
        )
    )

    successful_cross_tenant = (
        get_successful_cross_tenant(
            end_to_end
        )
    )

    controlled_findings = (
        get_controlled_findings(
            authorization_fuzz,
            context,
            attack_chains,
        )
    )

    security_violations = (
        get_actual_security_violations(
            end_to_end,
            mutation,
            property_campaign,
        )
    )

    if successful_cross_tenant > 0:
        overall_status = "VIOLATION"

    elif security_violations > 0:
        overall_status = "VIOLATION"

    elif controlled_findings > 0:
        overall_status = (
            "CONTROLLED_FINDINGS"
        )

    else:
        overall_status = "PASS"

    return DashboardSummary(
        generated_at=datetime.now(
            timezone.utc
        ).isoformat(),
        evidence_files=len(evidence),
        available_files=sum(
            item.exists
            for item in evidence
        ),
        missing_files=sum(
            not item.exists
            for item in evidence
        ),
        fuzz_cases=fuzz_cases,
        property_cases=property_cases,
        attack_chains=chain_count,
        mutation_cases=mutation_cases,
        end_to_end_scenarios=(
            end_to_end_scenarios
        ),
        successful_cross_tenant_access=(
            successful_cross_tenant
        ),
        controlled_findings=(
            controlled_findings
        ),
        security_violations=(
            security_violations
        ),
        overall_status=overall_status,
    )


def build_markdown(
    evidence,
    summary,
):
    lines = []

    lines.append(
        "# Cloud Security Research Dashboard"
    )
    lines.append("")

    lines.append(
        f"Generated: `{summary.generated_at}`"
    )
    lines.append("")

    lines.append(
        "## Research Status"
    )
    lines.append("")

    lines.append(
        f"**Overall status: "
        f"`{summary.overall_status}`**"
    )
    lines.append("")

    lines.append(
        "The primary runtime security invariant is:"
    )
    lines.append("")

    lines.append(
        "```text"
    )
    lines.append(
        "successful_cross_tenant_access == 0"
    )
    lines.append(
        "```"
    )
    lines.append("")

    lines.append(
        "The dashboard distinguishes actual "
        "successful cross-tenant access from "
        "intentionally reproduced controlled "
        "findings in the weak authorization model."
    )
    lines.append("")

    lines.append(
        "## Summary"
    )
    lines.append("")

    lines.append(
        "| Metric | Value |"
    )
    lines.append(
        "|---|---:|"
    )

    summary_rows = [
        (
            "Evidence files",
            summary.evidence_files,
        ),
        (
            "Available files",
            summary.available_files,
        ),
        (
            "Missing files",
            summary.missing_files,
        ),
        (
            "Authorization fuzz cases",
            summary.fuzz_cases,
        ),
        (
            "Property-security cases",
            summary.property_cases,
        ),
        (
            "Stateful attack chains",
            summary.attack_chains,
        ),
        (
            "Tool-call mutations",
            summary.mutation_cases,
        ),
        (
            "End-to-end scenarios",
            summary.end_to_end_scenarios,
        ),
        (
            "Successful cross-tenant access",
            summary.successful_cross_tenant_access,
        ),
        (
            "Controlled findings",
            summary.controlled_findings,
        ),
        (
            "Actual security violations",
            summary.security_violations,
        ),
    ]

    for name, value in summary_rows:
        lines.append(
            f"| {name} | {value} |"
        )

    lines.append("")

    lines.append(
        "## Evidence Files"
    )
    lines.append("")

    lines.append(
        "| Experiment | Path | Status | Size |"
    )
    lines.append(
        "|---|---|---|---:|"
    )

    for item in evidence:
        status = (
            "AVAILABLE"
            if item.exists
            else "MISSING"
        )

        lines.append(
            f"| {item.name} | "
            f"`{item.path}` | "
            f"{status} | "
            f"{item.size_bytes} |"
        )

    lines.append("")

    lines.append(
        "## Interpretation"
    )
    lines.append("")

    lines.append(
        "### Successful cross-tenant access"
    )
    lines.append("")

    lines.append(
        "The runtime evidence reports:"
    )
    lines.append("")

    lines.append(
        f"**Successful cross-tenant access: "
        f"{summary.successful_cross_tenant_access}**"
    )
    lines.append("")

    lines.append(
        "A value greater than zero would indicate "
        "that the runtime enforcement layer returned "
        "cross-tenant data during an experiment."
    )
    lines.append("")

    lines.append(
        "### Controlled findings"
    )
    lines.append("")

    lines.append(
        "Controlled findings are deliberately "
        "reproduced security weaknesses in the "
        "local research model."
    )
    lines.append("")

    controlled_items = [
        "confused-deputy authorization divergence",
        "context tampering",
        "weak capability reuse",
        "capability tenant substitution",
    ]

    for item in controlled_items:
        lines.append(
            f"- {item}"
        )

    lines.append("")

    lines.append(
        "These findings are not automatically "
        "evidence of a production or cloud-provider "
        "vulnerability."
    )
    lines.append("")

    lines.append(
        "## Research Coverage"
    )
    lines.append("")

    coverage = [
        "Tenant isolation",
        "Tool-call mutation",
        "AI-agent security scenarios",
        "Authorization graph fuzzing",
        "Finding minimization",
        "Context propagation",
        "Context tampering",
        "Stateful capability chains",
        "Capability lifecycle",
        "Property-based authorization testing",
        "Runtime cross-tenant enforcement",
    ]

    for index, item in enumerate(
        coverage,
        start=1,
    ):
        lines.append(
            f"{index}. {item}"
        )

    lines.append("")

    lines.append(
        "## Important Limitation"
    )
    lines.append("")

    lines.append(
        "This dashboard represents a local "
        "controlled security research laboratory."
    )
    lines.append("")

    lines.append(
        "It does not establish that any production "
        "cloud provider, SaaS platform, model "
        "provider, or external system is vulnerable."
    )
    lines.append("")

    lines.append(
        "Any real-world security finding requires:"
    )
    lines.append("")

    requirements = [
        "authorized scope",
        "reproducibility in the affected system",
        "evidence from the affected system",
        "impact validation",
        "responsible disclosure",
    ]

    for item in requirements:
        lines.append(
            f"- {item}"
        )

    lines.append("")

    return "\n".join(lines)


def save_dashboard(
    evidence,
    summary,
):
    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    json_path = (
        REPORT_DIR
        / "research_dashboard.json"
    )

    markdown_path = (
        REPORT_DIR
        / "research_dashboard.md"
    )

    json_data = {
        "summary": asdict(
            summary
        ),
        "evidence": [
            asdict(item)
            for item in evidence
        ],
    }

    with json_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            json_data,
            file,
            indent=2,
        )

    markdown = build_markdown(
        evidence,
        summary,
    )

    with markdown_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        file.write(markdown)

    return (
        json_path,
        markdown_path,
    )


def main():
    print(
        "CLOUD SECURITY RESEARCH DASHBOARD"
    )
    print(
        "=" * 60
    )

    evidence = inspect_evidence()

    summary = build_summary(
        evidence
    )

    json_path, markdown_path = (
        save_dashboard(
            evidence,
            summary,
        )
    )

    print()
    print(
        "Evidence Files"
    )
    print(
        "--------------"
    )

    for item in evidence:
        status = (
            "AVAILABLE"
            if item.exists
            else "MISSING"
        )

        print(
            f"{item.name:24} {status}"
        )

    print()
    print(
        "Dashboard Summary"
    )
    print(
        "-----------------"
    )

    print(
        f"Authorization fuzz cases : "
        f"{summary.fuzz_cases}"
    )

    print(
        f"Property cases            : "
        f"{summary.property_cases}"
    )

    print(
        f"Attack chains             : "
        f"{summary.attack_chains}"
    )

    print(
        f"Mutation cases            : "
        f"{summary.mutation_cases}"
    )

    print(
        f"E2E scenarios             : "
        f"{summary.end_to_end_scenarios}"
    )

    print(
        f"Successful cross-tenant   : "
        f"{summary.successful_cross_tenant_access}"
    )

    print(
        f"Controlled findings       : "
        f"{summary.controlled_findings}"
    )

    print(
        f"Actual violations         : "
        f"{summary.security_violations}"
    )

    print(
        f"Overall status            : "
        f"{summary.overall_status}"
    )

    print()
    print(
        f"JSON report: {json_path}"
    )

    print(
        f"Markdown report: "
        f"{markdown_path}"
    )


if __name__ == "__main__":
    main()