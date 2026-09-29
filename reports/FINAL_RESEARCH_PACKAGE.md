# AI Agent × Multi-Tenancy × Authorization

# Final Security Research Package

Generated: `2026-09-28T23:37:15.698914+00:00`

---

# 1. Executive Summary

This project investigates authorization risks that can arise when AI agents operate across multi-tenant systems containing shared services, delegated capabilities, and tool-based access.

The central research hypothesis is:

> Can a legitimate AI agent, operating with individually valid permissions, be induced through a tool or authorization chain to perform an action that violates the application's intended tenant boundary?

The project uses a completely controlled local laboratory.

No external cloud provider is treated as vulnerable by this research. The results describe behavior observed in the local authorization models and security controls implemented for the laboratory.

The primary security invariant is:

```text
successful_cross_tenant_access == 0
```

# 2. Research Scope

The laboratory models:

- Multiple isolated tenants.
- Tenant-owned documents.
- AI-agent identities.
- Tool execution.
- Shared services.
- Delegated capabilities.
- Authorization graphs.
- Context propagation.
- Capability lifecycle controls.
- Stateful agent attack chains.
- Property-based authorization testing.

# 3. Threat Model

The model assumes that an AI agent may legitimately possess permissions for one tenant while interacting with shared services or tools that can reach tenant-scoped resources.

The security concern is not that the model possesses an arbitrary administrative privilege. Instead, the research examines whether individually valid capabilities can become unsafe when authorization context is propagated, delegated, mutated, or interpreted by another component.

# 4. Security Invariants

The laboratory evaluates the following invariants:

1. The caller tenant must remain authoritative.
2. A model-generated tenant value must not replace trusted context.
3. Tool execution must enforce the executor's tenant.
4. Cross-tenant document access must be denied.
5. Delegated capabilities must remain tenant-bound.
6. Expired or revoked capabilities must not authorize access.
7. Capability audience and subject must remain valid.
8. Context tampering must not change the effective authorization tenant.

# 5. Evidence Summary

- Evidence files available: **11/11**
- Authorization fuzz cases: **1000**
- Property-based security cases: **5000**
- Stateful attack chains: **4**
- Tool-call mutation cases: **75**
- End-to-end scenarios: **5**
- Successful cross-tenant accesses: **0**
- Actual security violations: **0**
- Controlled findings: **188**
- Authorization context-drift cases: **5000**
- Authorization context-drift violations in the weak reference model: **650**
- Overall research status: **CONTROLLED_FINDINGS**

# 6. Runtime Security Results

The current protected runtime produced zero successful cross-tenant accesses in the recorded security experiments.

Successful cross-tenant access count: **0**

Actual runtime security violations: **0**

These results indicate that the implemented runtime controls blocked the tested cross-tenant access attempts in this laboratory.

# 7. Controlled Authorization Findings

The laboratory also contains intentionally weak authorization models used to demonstrate confused-deputy and context-integrity failure modes.

These findings are controlled research results. They should not be interpreted as evidence of a vulnerability in an external cloud provider or production service.

Controlled findings identified: **188**

The controlled findings include authorization divergences, context-tampering cases, and stateful attack-chain cases where the intentionally weak reference model accepts an unsafe authorization transition.

# 8. Authorization Graph Fuzzing

The authorization graph fuzzer evaluated **1000** randomized scenarios.

The fuzzing campaign compared the strict authorization model with the intentionally weak confused-deputy model.

A divergence between these models is treated as a controlled finding rather than an external vulnerability.

# 9. Tool-Call Mutation Testing

The tool-call mutation campaign evaluated **75** mutated requests.

The mutations included cross-tenant document identifiers, tenant overrides, nested tenant values, duplicate arguments, unknown tools, malformed arguments, wildcard values, and other malformed or adversarial inputs.

The protected executor binds authorization to its own tenant context rather than trusting tenant information supplied by the model.

# 10. Context Integrity

The research separately evaluates legitimate context propagation and malicious context substitution.

Legitimate context propagation must preserve the original tenant identity across the agent, tool, shared service, authorization layer, and resource.

Context-tampering experiments intentionally modify tenant context in the weak reference model to determine whether the model detects the substitution.

Context-tampering evidence was generated and is included in the evidence set.

# 11. Stateful Agent Attack Chains

The stateful attack-chain experiment evaluated **4** chains.

The chains test how authorization state evolves across multiple agent, capability, service, and resource operations.

The intentionally weak model demonstrates unsafe capability reuse and tenant substitution scenarios, while the protected model is expected to maintain tenant binding.

# 12. Capability Lifecycle

Capability lifecycle testing covers:

- Valid capability usage.
- Expired capabilities.
- Revoked capabilities.
- Incorrect subjects.
- Incorrect tenants.
- Incorrect audiences.
- Tenant substitution.
- Audience substitution.
- Replay after expiration.
- Cross-service capability reuse.

The recorded lifecycle experiment passed all ten defined security checks.

# 13. Property-Based Security Campaign

The property-based campaign evaluated **5000** randomized cases.

The campaign checks that authorization decisions remain consistent with tenant ownership and capability constraints across a large generated input space.

The recorded campaign reported zero security violations.

# 14. Finding Minimization

The minimized finding evidence is available. The controlled authorization chain was reduced to the smallest tested graph that preserved the weak-model behavior.

# 15. Authorization Context Drift

A dedicated context-drift experiment tested whether a legitimate capability bound to the original tenant could become authorized for another tenant when a downstream authorization component trusted a mutable effective tenant.

The deterministic context-drift experiment evaluated **5** controlled cases.

The randomized context-drift campaign evaluated **5000** cases and recorded **650** controlled violations in the intentionally weak context-consuming reference model.

The minimized reproducible case demonstrates the following composition failure: a capability remains legitimately bound to the original tenant, the authorization context changes to the resource tenant, the strict model rejects the request, and the intentionally weak downstream model accepts it.

This is a controlled authorization-context composition finding. It does not establish a vulnerability in an external cloud provider, AI provider, or production service.

# 16. Responsible Disclosure Position

This research package is suitable as a controlled security research artifact. It does not establish a vulnerability against a third-party cloud provider, AI provider, or production service.

Any future external disclosure should be based on a separately reproduced issue against an explicitly authorized target and should include the target, affected component, reproduction steps, security impact, and evidence.

# 17. Reproduction

The principal experiments can be reproduced using Python module execution from the project root.

```bash
python -m experiments.authorization_fuzzer
python -m experiments.finding_minimizer
python -m experiments.tool_call_mutator
python -m experiments.context_propagation_test
python -m experiments.context_tampering_fuzzer
python -m experiments.agent_attack_chains
python -m experiments.capability_lifecycle_test
python -m experiments.property_security_campaign
python -m experiments.research_dashboard
python -m experiments.authorization_context_drift_test
python -m experiments.authorization_context_drift_fuzzer
python -m experiments.context_drift_regression
python -m experiments.final_research_package
```

# 18. Limitations

The laboratory is intentionally simplified and local.

It does not reproduce the complete IAM, networking, identity, policy evaluation, service-to-service authentication, or infrastructure behavior of a real cloud provider.

Model-generated tool calls are also dependent on the selected model and prompt configuration. A model not producing an unsafe request is not itself proof that the underlying authorization architecture is secure.

Likewise, controlled divergences in the intentionally weak authorization model are not evidence of a real-world vulnerability without reproduction against an authorized external target.

# 19. Final Research Statement

The laboratory demonstrates a useful security-testing methodology for AI-agent authorization in multi-tenant systems.

The methodology combines authorization graph analysis, fuzzing, tool-call mutation, context-integrity testing, stateful agent attack chains, capability lifecycle testing, property-based testing, regression testing, and runtime security invariants.

Within the current protected implementation, the recorded experiments produced zero successful cross-tenant accesses and zero actual runtime security violations.

The research also produced **188** controlled findings in intentionally weak reference models, which demonstrate the classes of authorization failure that the protected implementation is designed to prevent.

The additional authorization-context drift campaign evaluated **5000** cases and recorded **650** controlled context-drift violations in the intentionally weak reference model.

Final status:

```text
CONTROLLED_FINDINGS
```

---

Generated by Cloud Security Research Lab.
