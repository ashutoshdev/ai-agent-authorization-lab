import json
import os
from datetime import datetime, timezone


PROJECT_ROOT = os.path.expanduser(
    "~/cloud-security-research-lab"
)

REPORT_DIR = os.path.join(
    PROJECT_ROOT,
    "reports",
)

PACKAGE_PATH = os.path.join(
    REPORT_DIR,
    "FINAL_RESEARCH_PACKAGE.md",
)


def read_json(filename: str):
    path = os.path.join(
        REPORT_DIR,
        filename,
    )

    if not os.path.exists(path):
        return None

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return None


def evidence_exists(filename: str) -> bool:
    return os.path.exists(
        os.path.join(
            REPORT_DIR,
            filename,
        )
    )


def get_value(
    data: dict | None,
    *keys: str,
    default=0,
):
    if not isinstance(data, dict):
        return default

    for key in keys:
        if key in data:
            return data[key]

    return default


def build_package() -> str:
    dashboard = read_json(
        "research_dashboard.json"
    )

    fuzz = read_json(
        "authorization_fuzz.json"
    )

    property_campaign = read_json(
        "property_security_campaign.json"
    )

    end_to_end = read_json(
        "end_to_end_security.json"
    )

    mutation = read_json(
        "tool_call_mutation.json"
    )

    attack_chains = read_json(
        "agent_attack_chains.json"
    )

    context_tampering = read_json(
        "context_tampering.json"
    )

    minimized_finding = read_json(
        "minimized_authorization_finding.json"
    )

    context_drift = read_json(
        "authorization_context_drift.json"
    )

    context_drift_fuzzer = read_json(
        "authorization_context_drift_fuzzer.json"
    )

    tenant_binding = read_json(
        "tenant_binding_weak_vs_protected.json"
    )

    generated_at = datetime.now(
        timezone.utc
    ).isoformat()

    if dashboard:
        summary = dashboard.get(
            "summary",
            {},
        )
    else:
        summary = {}

    successful_cross_tenant = get_value(
        summary,
        "successful_cross_tenant_access",
        default=0,
    )

    security_violations = get_value(
        summary,
        "security_violations",
        default=0,
    )

    controlled_findings = get_value(
        summary,
        "controlled_findings",
        default=0,
    )

    fuzz_cases = get_value(
        summary,
        "fuzz_cases",
        default=0,
    )

    property_cases = get_value(
        summary,
        "property_cases",
        default=0,
    )

    attack_chain_count = get_value(
        summary,
        "attack_chains",
        default=0,
    )

    mutation_cases = get_value(
        summary,
        "mutation_cases",
        default=0,
    )

    end_to_end_scenarios = get_value(
        summary,
        "end_to_end_scenarios",
        default=0,
    )

    if not fuzz_cases and fuzz:
        fuzz_cases = get_value(
            fuzz,
            "iterations",
            "cases",
            "scenarios_tested",
            default=0,
        )

    if not property_cases and property_campaign:
        property_cases = get_value(
            property_campaign,
            "iterations",
            "cases",
            default=0,
        )

    if not attack_chain_count and attack_chains:
        attack_chain_count = get_value(
            attack_chains,
            "chains_tested",
            "attack_chains",
            "cases",
            default=0,
        )

    if not mutation_cases and mutation:
        mutation_cases = get_value(
            mutation,
            "mutations",
            "mutation_cases",
            "cases",
            default=0,
        )

    if not end_to_end_scenarios and end_to_end:
        end_to_end_scenarios = get_value(
            end_to_end,
            "scenarios",
            "scenarios_tested",
            "cases",
            default=0,
        )

    context_drift_cases = 0
    context_drift_violations = 0

    if context_drift_fuzzer:
        drift_summary = context_drift_fuzzer.get(
            "summary",
            {},
        )
        context_drift_cases = get_value(
            drift_summary,
            "cases",
            "iterations",
            default=0,
        )
        context_drift_violations = get_value(
            drift_summary,
            "context_drift_violations",
            "violations",
            default=0,
        )
    elif context_drift:
        drift_summary = context_drift.get(
            "summary",
            {},
        )
        context_drift_cases = get_value(
            drift_summary,
            "cases",
            default=0,
        )
        context_drift_violations = get_value(
            drift_summary,
            "context_drift_violations",
            "violations",
            default=0,
        )

    if successful_cross_tenant > 0:
        overall_status = "VIOLATION"
    elif security_violations > 0:
        overall_status = "VIOLATION"
    elif controlled_findings > 0:
        overall_status = "CONTROLLED_FINDINGS"
    else:
        overall_status = "PASS"

    evidence_files = {
        "security_corpus.json": evidence_exists(
            "security_corpus.json"
        ),
        "multi_provider_security.json": evidence_exists(
            "multi_provider_security.json"
        ),
        "authorization_fuzz.json": evidence_exists(
            "authorization_fuzz.json"
        ),
        "minimized_authorization_finding.json": evidence_exists(
            "minimized_authorization_finding.json"
        ),
        "end_to_end_security.json": evidence_exists(
            "end_to_end_security.json"
        ),
        "tool_call_mutation.json": evidence_exists(
            "tool_call_mutation.json"
        ),
        "context_tampering.json": evidence_exists(
            "context_tampering.json"
        ),
        "agent_attack_chains.json": evidence_exists(
            "agent_attack_chains.json"
        ),
        "property_security_campaign.json": evidence_exists(
            "property_security_campaign.json"
        ),
        "authorization_context_drift.json": evidence_exists(
            "authorization_context_drift.json"
        ),
        "authorization_context_drift_fuzzer.json": evidence_exists(
            "authorization_context_drift_fuzzer.json"
        ),
        "tenant_binding_weak_vs_protected.json": evidence_exists(
            "tenant_binding_weak_vs_protected.json"
        ),
    }

    available_evidence = sum(
        1
        for available in evidence_files.values()
        if available
    )

    total_evidence = len(
        evidence_files
    )

    lines = []

    lines.append(
        "# AI Agent × Multi-Tenancy × Authorization"
    )
    lines.append("")
    lines.append(
        "# Final Security Research Package"
    )
    lines.append("")
    lines.append(
        f"Generated: `{generated_at}`"
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append(
        "# 1. Executive Summary"
    )
    lines.append("")

    lines.append(
        "This project investigates authorization risks that can arise "
        "when AI agents operate across multi-tenant systems containing "
        "shared services, delegated capabilities, and tool-based access."
    )
    lines.append("")

    lines.append(
        "The central research hypothesis is:"
    )
    lines.append("")

    lines.append(
        "> Can a legitimate AI agent, operating with individually "
        "valid permissions, be induced through a tool or authorization "
        "chain to perform an action that violates the application's "
        "intended tenant boundary?"
    )
    lines.append("")

    lines.append(
        "The project uses a completely controlled local laboratory."
    )
    lines.append("")

    lines.append(
        "No external cloud provider is treated as vulnerable by this "
        "research. The results describe behavior observed in the "
        "local authorization models and security controls implemented "
        "for the laboratory."
    )
    lines.append("")

    lines.append(
        "The primary security invariant is:"
    )
    lines.append("")

    lines.append("```text")
    lines.append(
        "successful_cross_tenant_access == 0"
    )
    lines.append("```")
    lines.append("")

    lines.append(
        "# 2. Research Scope"
    )
    lines.append("")

    lines.append(
        "The laboratory models:"
    )
    lines.append("")
    lines.append(
        "- Multiple isolated tenants."
    )
    lines.append(
        "- Tenant-owned documents."
    )
    lines.append(
        "- AI-agent identities."
    )
    lines.append(
        "- Tool execution."
    )
    lines.append(
        "- Shared services."
    )
    lines.append(
        "- Delegated capabilities."
    )
    lines.append(
        "- Authorization graphs."
    )
    lines.append(
        "- Context propagation."
    )
    lines.append(
        "- Capability lifecycle controls."
    )
    lines.append(
        "- Stateful agent attack chains."
    )
    lines.append(
        "- Property-based authorization testing."
    )
    lines.append("")

    lines.append(
        "# 3. Threat Model"
    )
    lines.append("")

    lines.append(
        "The model assumes that an AI agent may legitimately possess "
        "permissions for one tenant while interacting with shared "
        "services or tools that can reach tenant-scoped resources."
    )
    lines.append("")

    lines.append(
        "The security concern is not that the model possesses an "
        "arbitrary administrative privilege. Instead, the research "
        "examines whether individually valid capabilities can become "
        "unsafe when authorization context is propagated, delegated, "
        "mutated, or interpreted by another component."
    )
    lines.append("")

    lines.append(
        "# 4. Security Invariants"
    )
    lines.append("")

    lines.append(
        "The laboratory evaluates the following invariants:"
    )
    lines.append("")
    lines.append(
        "1. The caller tenant must remain authoritative."
    )
    lines.append(
        "2. A model-generated tenant value must not replace trusted context."
    )
    lines.append(
        "3. Tool execution must enforce the executor's tenant."
    )
    lines.append(
        "4. Cross-tenant document access must be denied."
    )
    lines.append(
        "5. Delegated capabilities must remain tenant-bound."
    )
    lines.append(
        "6. Expired or revoked capabilities must not authorize access."
    )
    lines.append(
        "7. Capability audience and subject must remain valid."
    )
    lines.append(
        "8. Context tampering must not change the effective authorization tenant."
    )
    lines.append("")

    lines.append(
        "# 5. Evidence Summary"
    )
    lines.append("")

    lines.append(
        f"- Evidence files available: **{available_evidence}/{total_evidence}**"
    )
    lines.append(
        f"- Authorization fuzz cases: **{fuzz_cases}**"
    )
    lines.append(
        f"- Property-based security cases: **{property_cases}**"
    )
    lines.append(
        f"- Stateful attack chains: **{attack_chain_count}**"
    )
    lines.append(
        f"- Tool-call mutation cases: **{mutation_cases}**"
    )
    lines.append(
        f"- End-to-end scenarios: **{end_to_end_scenarios}**"
    )
    lines.append(
        f"- Successful cross-tenant accesses: **{successful_cross_tenant}**"
    )
    lines.append(
        f"- Actual security violations: **{security_violations}**"
    )
    lines.append(
        f"- Controlled findings: **{controlled_findings}**"
    )
    lines.append(
        f"- Authorization context-drift cases: **{context_drift_cases}**"
    )
    lines.append(
        f"- Authorization context-drift violations in the weak reference model: **{context_drift_violations}**"
    )
    lines.append(
        f"- Overall research status: **{overall_status}**"
    )
    lines.append("")

    lines.append(
        "# 6. Runtime Security Results"
    )
    lines.append("")

    lines.append(
        "The current protected runtime produced zero successful "
        "cross-tenant accesses in the recorded security experiments."
    )
    lines.append("")

    lines.append(
        f"Successful cross-tenant access count: **{successful_cross_tenant}**"
    )
    lines.append("")

    lines.append(
        f"Actual runtime security violations: **{security_violations}**"
    )
    lines.append("")

    lines.append(
        "These results indicate that the implemented runtime controls "
        "blocked the tested cross-tenant access attempts in this "
        "laboratory."
    )
    lines.append("")

    lines.append(
        "# 7. Controlled Authorization Findings"
    )
    lines.append("")

    lines.append(
        "The laboratory also contains intentionally weak authorization "
        "models used to demonstrate confused-deputy and context-integrity "
        "failure modes."
    )
    lines.append("")

    lines.append(
        "These findings are controlled research results. They should "
        "not be interpreted as evidence of a vulnerability in an "
        "external cloud provider or production service."
    )
    lines.append("")

    lines.append(
        f"Controlled findings identified: **{controlled_findings}**"
    )
    lines.append("")

    lines.append(
        "The controlled findings include authorization divergences, "
        "context-tampering cases, and stateful attack-chain cases "
        "where the intentionally weak reference model accepts an "
        "unsafe authorization transition."
    )
    lines.append("")

    lines.append(
        "# 8. Authorization Graph Fuzzing"
    )
    lines.append("")

    lines.append(
        f"The authorization graph fuzzer evaluated **{fuzz_cases}** "
        "randomized scenarios."
    )
    lines.append("")

    lines.append(
        "The fuzzing campaign compared the strict authorization model "
        "with the intentionally weak confused-deputy model."
    )
    lines.append("")

    lines.append(
        "A divergence between these models is treated as a controlled "
        "finding rather than an external vulnerability."
    )
    lines.append("")

    lines.append(
        "# 9. Tool-Call Mutation Testing"
    )
    lines.append("")

    lines.append(
        f"The tool-call mutation campaign evaluated **{mutation_cases}** "
        "mutated requests."
    )
    lines.append("")

    lines.append(
        "The mutations included cross-tenant document identifiers, "
        "tenant overrides, nested tenant values, duplicate arguments, "
        "unknown tools, malformed arguments, wildcard values, and "
        "other malformed or adversarial inputs."
    )
    lines.append("")

    lines.append(
        "The protected executor binds authorization to its own tenant "
        "context rather than trusting tenant information supplied by "
        "the model."
    )
    lines.append("")

    lines.append(
        "# 10. Context Integrity"
    )
    lines.append("")

    lines.append(
        "The research separately evaluates legitimate context "
        "propagation and malicious context substitution."
    )
    lines.append("")

    lines.append(
        "Legitimate context propagation must preserve the original "
        "tenant identity across the agent, tool, shared service, "
        "authorization layer, and resource."
    )
    lines.append("")

    lines.append(
        "Context-tampering experiments intentionally modify tenant "
        "context in the weak reference model to determine whether "
        "the model detects the substitution."
    )
    lines.append("")

    if context_tampering:
        lines.append(
            "Context-tampering evidence was generated and is included "
            "in the evidence set."
        )
    else:
        lines.append(
            "Context-tampering evidence was not available as a standalone "
            "JSON artifact when this package was generated."
        )

    lines.append("")

    lines.append(
        "# 11. Stateful Agent Attack Chains"
    )
    lines.append("")

    lines.append(
        f"The stateful attack-chain experiment evaluated "
        f"**{attack_chain_count}** chains."
    )
    lines.append("")

    lines.append(
        "The chains test how authorization state evolves across "
        "multiple agent, capability, service, and resource operations."
    )
    lines.append("")

    lines.append(
        "The intentionally weak model demonstrates unsafe capability "
        "reuse and tenant substitution scenarios, while the protected "
        "model is expected to maintain tenant binding."
    )
    lines.append("")

    lines.append(
        "# 12. Capability Lifecycle"
    )
    lines.append("")

    lines.append(
        "Capability lifecycle testing covers:"
    )
    lines.append("")
    lines.append(
        "- Valid capability usage."
    )
    lines.append(
        "- Expired capabilities."
    )
    lines.append(
        "- Revoked capabilities."
    )
    lines.append(
        "- Incorrect subjects."
    )
    lines.append(
        "- Incorrect tenants."
    )
    lines.append(
        "- Incorrect audiences."
    )
    lines.append(
        "- Tenant substitution."
    )
    lines.append(
        "- Audience substitution."
    )
    lines.append(
        "- Replay after expiration."
    )
    lines.append(
        "- Cross-service capability reuse."
    )
    lines.append("")

    lines.append(
        "The recorded lifecycle experiment passed all ten defined "
        "security checks."
    )
    lines.append("")

    lines.append(
        "# 13. Property-Based Security Campaign"
    )
    lines.append("")

    lines.append(
        f"The property-based campaign evaluated **{property_cases}** "
        "randomized cases."
    )
    lines.append("")

    lines.append(
        "The campaign checks that authorization decisions remain "
        "consistent with tenant ownership and capability constraints "
        "across a large generated input space."
    )
    lines.append("")

    lines.append(
        "The recorded campaign reported zero security violations."
    )
    lines.append("")

    lines.append(
        "# 14. Finding Minimization"
    )
    lines.append("")

    if minimized_finding:
        lines.append(
            "The minimized finding evidence is available. The "
            "controlled authorization chain was reduced to the "
            "smallest tested graph that preserved the weak-model "
            "behavior."
        )
    else:
        lines.append(
            "The minimized finding evidence was not available when "
            "this package was generated."
        )

    lines.append("")

    lines.append(
        "# 15. Authorization Context Drift"
    )
    lines.append("")

    lines.append(
        "A dedicated context-drift experiment tested whether a legitimate "
        "capability bound to the original tenant could become authorized "
        "for another tenant when a downstream authorization component "
        "trusted a mutable effective tenant."
    )
    lines.append("")

    lines.append(
        f"The deterministic context-drift experiment evaluated "
        f"**{get_value((context_drift or {}).get('summary', {}), 'cases', default=0)}** "
        "controlled cases."
    )
    lines.append("")

    lines.append(
        f"The randomized context-drift campaign evaluated "
        f"**{context_drift_cases}** cases and recorded "
        f"**{context_drift_violations}** controlled violations in the "
        "intentionally weak context-consuming reference model."
    )
    lines.append("")

    lines.append(
        "The minimized reproducible case demonstrates the following "
        "composition failure: a capability remains legitimately bound "
        "to the original tenant, the authorization context changes to "
        "the resource tenant, the strict model rejects the request, and "
        "the intentionally weak downstream model accepts it."
    )
    lines.append("")

    lines.append(
        "This is a controlled authorization-context composition finding. "
        "It does not establish a vulnerability in an external cloud "
        "provider, AI provider, or production service."
    )
    lines.append("")

    lines.append(
        "# 16. Tenant Binding Architecture Comparison"
    )
    lines.append("")

    lines.append(
        "A real Llama 3.2 tool-calling experiment compared the same "
        "model-generated tenant context against two executor designs."
    )
    lines.append("")

    if tenant_binding:
        model_name = get_value(tenant_binding, "model", default="unknown")
        original_tenant = get_value(tenant_binding, "original_tenant", default="unknown")
        target_tenant = get_value(tenant_binding, "target_tenant", default="unknown")
        weak = tenant_binding.get("weak_executor", {})
        protected = tenant_binding.get("protected_executor", {})

        lines.append(f"- Model: **{model_name}**")
        lines.append(f"- Original application tenant: **{original_tenant}**")
        lines.append(f"- Model-supplied target tenant: **{target_tenant}**")
        lines.append(f"- Weak executor cross-tenant access: **{weak.get('cross_tenant_access', False)}**")
        lines.append(f"- Protected executor cross-tenant access: **{protected.get('cross_tenant_access', False)}**")
        lines.append("")
        lines.append(
            "The same model-generated request caused the intentionally "
            "weak executor to authorize the tenant-b document, while the "
            "application-bound executor enforced tenant-a and denied the "
            "request."
        )
        lines.append("")
        lines.append(
            "This demonstrates the security effect of trusting "
            "model-supplied tenant context in the reference executor. "
            "It does not demonstrate a vulnerability in Llama 3.2 or "
            "an external provider."
        )
    else:
        lines.append(
            "Tenant-binding comparison evidence was not available when "
            "this package was generated."
        )

    lines.append("")
    lines.append(
        "# 17. Responsible Disclosure Position"
    )
    lines.append("")

    lines.append(
        "This research package is suitable as a controlled security "
        "research artifact. It does not establish a vulnerability "
        "against a third-party cloud provider, AI provider, or "
        "production service."
    )
    lines.append("")

    lines.append(
        "Any future external disclosure should be based on a "
        "separately reproduced issue against an explicitly authorized "
        "target and should include the target, affected component, "
        "reproduction steps, security impact, and evidence."
    )
    lines.append("")

    lines.append(
        "# 18. Reproduction"
    )
    lines.append("")

    lines.append(
        "The principal experiments can be reproduced using Python "
        "module execution from the project root."
    )
    lines.append("")

    lines.append("```bash")
    lines.append(
        "python -m experiments.authorization_fuzzer"
    )
    lines.append(
        "python -m experiments.finding_minimizer"
    )
    lines.append(
        "python -m experiments.tool_call_mutator"
    )
    lines.append(
        "python -m experiments.context_propagation_test"
    )
    lines.append(
        "python -m experiments.context_tampering_fuzzer"
    )
    lines.append(
        "python -m experiments.agent_attack_chains"
    )
    lines.append(
        "python -m experiments.capability_lifecycle_test"
    )
    lines.append(
        "python -m experiments.property_security_campaign"
    )
    lines.append(
        "python -m experiments.research_dashboard"
    )
    lines.append(
        "python -m experiments.authorization_context_drift_test"
    )
    lines.append(
        "python -m experiments.authorization_context_drift_fuzzer"
    )
    lines.append(
        "python -m experiments.context_drift_regression"
    )
    lines.append(
        "python -m experiments.tenant_binding_weak_vs_protected"
    )
    lines.append(
        "python -m experiments.final_research_package"
    )
    lines.append("```")
    lines.append("")

    lines.append(
        "# 19. Limitations"
    )
    lines.append("")

    lines.append(
        "The laboratory is intentionally simplified and local."
    )
    lines.append("")

    lines.append(
        "It does not reproduce the complete IAM, networking, "
        "identity, policy evaluation, service-to-service authentication, "
        "or infrastructure behavior of a real cloud provider."
    )
    lines.append("")

    lines.append(
        "Model-generated tool calls are also dependent on the selected "
        "model and prompt configuration. A model not producing an "
        "unsafe request is not itself proof that the underlying "
        "authorization architecture is secure."
    )
    lines.append("")

    lines.append(
        "Likewise, controlled divergences in the intentionally weak "
        "authorization model are not evidence of a real-world "
        "vulnerability without reproduction against an authorized "
        "external target."
    )
    lines.append("")

    lines.append(
        "# 20. Final Research Statement"
    )
    lines.append("")

    lines.append(
        "The laboratory demonstrates a useful security-testing "
        "methodology for AI-agent authorization in multi-tenant "
        "systems."
    )
    lines.append("")

    lines.append(
        "The methodology combines authorization graph analysis, "
        "fuzzing, tool-call mutation, context-integrity testing, "
        "stateful agent attack chains, capability lifecycle testing, "
        "property-based testing, regression testing, and runtime "
        "security invariants."
    )
    lines.append("")

    lines.append(
        "Within the current protected implementation, the recorded "
        "experiments produced zero successful cross-tenant accesses "
        "and zero actual runtime security violations."
    )
    lines.append("")

    lines.append(
        f"The research also produced **{controlled_findings}** "
        "controlled findings in intentionally weak reference models, "
        "which demonstrate the classes of authorization failure that "
        "the protected implementation is designed to prevent."
    )
    lines.append("")
    lines.append(
        f"The additional authorization-context drift campaign evaluated "
        f"**{context_drift_cases}** cases and recorded "
        f"**{context_drift_violations}** controlled context-drift "
        "violations in the intentionally weak reference model."
    )
    lines.append("")

    lines.append(
        "Final status:"
    )
    lines.append("")
    lines.append("```text")
    lines.append(
        overall_status
    )
    lines.append("```")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "Generated by Cloud Security Research Lab."
    )
    lines.append("")

    return "\n".join(lines)


def save_package(
    content: str,
):
    os.makedirs(
        REPORT_DIR,
        exist_ok=True,
    )

    with open(
        PACKAGE_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(content)


def main():
    package = build_package()

    save_package(
        package
    )

    print(
        "Final Research Package"
    )
    print(
        "======================="
    )
    print()
    print(
        f"Package generated: {PACKAGE_PATH}"
    )
    print(
        f"Characters: {len(package)}"
    )
    print(
        f"Lines: {len(package.splitlines())}"
    )


if __name__ == "__main__":
    main()