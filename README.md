# AI Agent × Multi-Tenancy × Authorization

## Security Research Lab

A controlled security research laboratory for studying authorization risks in AI-agent systems operating across multi-tenant environments.

This project investigates what happens when an AI agent interacts with tools, shared services, delegated capabilities, authorization layers, and tenant-scoped resources.

> **Research question**
>
> Can a legitimate AI agent, operating with individually valid permissions, be induced through a tool or authorization chain to perform an action that violates the application's intended tenant boundary?

---

## ⚠️ Research Scope

This is a **completely controlled local security research laboratory**.

The experiments in this repository do **not** establish a vulnerability in:

- Llama 3.2
- Ollama
- Any cloud provider
- Any external AI provider
- Any production service

The intentionally weak authorization models are laboratory constructs used to demonstrate authorization failure modes under controlled conditions.

The protected implementation is designed to keep the application's trusted tenant context authoritative.

---

# Research Focus

The laboratory studies the security boundary between:

```text
┌──────────────────────┐
│      AI Agent        │
│                      │
│ Tenant: tenant-a     │
└──────────┬───────────┘
           │
           │ Tool Call
           ▼
┌──────────────────────┐
│     Tool Layer       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   Shared Service     │
│                      │
│   Authorization      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Tenant-Scoped        │
│ Resource             │
└──────────────────────┘
```

The primary security concern is whether tenant identity or authorization context can become confused, substituted, mutated, or incorrectly trusted as a request moves through these components.

---

# Research Question

The central research question is:

> Can a legitimate AI agent, with individually valid permissions, cross an intended tenant boundary because authorization context is incorrectly propagated, delegated, mutated, or interpreted by another component?

The research does not assume that the AI model itself is malicious.

Instead, it examines what happens when **model-generated actions interact with authorization architecture**.

---

# Security Invariants

The laboratory evaluates the following security properties.

### 1. Caller tenant remains authoritative

The authenticated application's tenant must remain authoritative for authorization decisions.

### 2. Model-generated tenant values are untrusted

A tenant identifier supplied by an LLM must not replace trusted application authorization context.

### 3. Tool execution enforces application context

Tool execution must authorize requests using trusted executor context rather than model-supplied identity fields.

### 4. Cross-tenant document access is denied

A tenant must not be able to access another tenant's resources.

### 5. Delegated capabilities remain tenant-bound

Delegated capabilities must remain bound to the appropriate tenant and authorization context.

### 6. Capability lifecycle is enforced

Expired, revoked, invalid, incorrectly scoped, or otherwise unauthorized capabilities must not authorize access.

### 7. Capability audience and subject remain valid

Authorization must continue to respect capability subject and audience constraints.

### 8. Context integrity is preserved

Authorization context must not be changed between components without explicit and trusted authorization semantics.

---

# Threat Model

The laboratory assumes an AI agent may legitimately possess permissions for one tenant while interacting with shared services or tools capable of reaching tenant-scoped resources.

The research does **not** assume that the model has arbitrary administrative privileges.

Instead, the laboratory examines whether individually valid permissions can become unsafe when:

- authorization context is propagated
- authorization context is delegated
- tenant metadata is mutated
- tool arguments contain identity information
- capabilities are reused
- services interpret authorization context differently
- downstream components trust mutable context
- multiple authorization decisions are composed

The core concern is an authorization composition failure.

---

# Architecture

The laboratory models multiple tenants and shared authorization components.

```text
                       ┌───────────────────────┐
                       │       AI Agent        │
                       │                       │
                       │   Tenant: tenant-a    │
                       └───────────┬───────────┘
                                   │
                                   │ Tool Call
                                   ▼
                       ┌───────────────────────┐
                       │      Tool Layer       │
                       │                       │
                       │ list_documents        │
                       │ read_document         │
                       └───────────┬───────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │   Shared Service      │
                       │                       │
                       │   Authorization       │
                       └───────────┬───────────┘
                                   │
                     ┌─────────────┴─────────────┐
                     │                           │
                     ▼                           ▼
             ┌────────────────┐         ┌────────────────┐
             │    Tenant A    │         │    Tenant B    │
             │                │         │                │
             │    doc-a-1     │         │    doc-b-1     │
             │                │         │                │
             │  Confidential  │         │  Confidential  │
             └────────────────┘         └────────────────┘
```

The intended security boundary is:

```text
Authenticated Application Context
              │
              ▼
       Authorization Layer
              │
              ▼
        Tool Executor
              │
              ▼
      Tenant-Scoped Resource
```

rather than:

```text
LLM Output
    │
    ▼
Model-Supplied tenantId
    │
    ▼
Authorization
```

---

# Core Authorization Models

The laboratory contains both protected and intentionally weak reference models.

## Strict Authorization

The strict model keeps the caller's tenant authoritative.

Conceptually:

```text
caller tenant
     │
     ▼
authorization
     │
     ├── capability tenant matches?
     │
     ├── resource tenant matches?
     │
     └── context integrity preserved?
             │
             ▼
          ALLOW / DENY
```

A delegated capability cannot silently change the caller's tenant context.

---

## Intentionally Weak Authorization

The weak reference model demonstrates what can happen when a shared service accepts capability or effective-tenant information without properly binding it to the original caller.

Conceptually:

```text
model / downstream context
          │
          ▼
    effective tenant
          │
          ▼
    authorization
          │
          ▼
       resource
```

This model is deliberately weak and exists only for controlled security experiments.

A finding in this model is therefore classified as a:

> **Controlled finding**

rather than an external vulnerability.

---

# Research Methodology

The laboratory combines several testing techniques.

### Authorization Graph Analysis

Models relationships between:

- agents
- tools
- services
- resources
- tenants
- capabilities

### Authorization Fuzzing

Generates randomized authorization scenarios and compares strict and intentionally weak authorization behavior.

### Tool-Call Mutation

Mutates AI-generated or representative tool requests with inputs such as:

- cross-tenant document identifiers
- tenant overrides
- nested tenant values
- duplicate arguments
- unknown tools
- malformed arguments
- wildcard values
- adversarial inputs

### Context Propagation Testing

Checks whether tenant context remains consistent across:

```text
Agent → Tool → Service → Authorization → Resource
```

### Context Tampering

Intentionally modifies authorization context in the weak reference model to test whether the security boundary survives the mutation.

### Context-Drift Fuzzing

Generates large numbers of authorization-context combinations to identify cases where:

```text
original tenant ≠ effective tenant
```

while a downstream component incorrectly trusts the changed effective tenant.

### Stateful Agent Attack Chains

Tests authorization state across multiple operations involving:

- agents
- capabilities
- services
- resources
- tenant context

### Capability Lifecycle Testing

Tests:

- valid capabilities
- expired capabilities
- revoked capabilities
- incorrect subjects
- incorrect tenants
- incorrect audiences
- tenant substitution
- audience substitution
- replay after expiration
- cross-service capability reuse

### Property-Based Testing

Generates large randomized input spaces and checks authorization security properties.

### Finding Minimization

Reduces controlled findings to smaller authorization graphs or deterministic cases that preserve the observed weak-model behavior.

### Regression Testing

Minimized findings are converted into deterministic regression tests to ensure protected authorization behavior remains intact.

### Real LLM Tool-Calling

The laboratory also evaluates real Llama 3.2 tool-call behavior against protected and intentionally weak executor architectures.

---

# Experimental Results

The current research package contains **12 evidence artifacts**.

| Experiment | Cases / Checks | Result |
|---|---:|---|
| Authorization fuzzing | 1,000 | Controlled model divergences |
| Tool-call mutation | 75 | Protected |
| End-to-end scenarios | 5 | Protected |
| Stateful attack chains | 4 | Controlled findings |
| Capability lifecycle | 10 checks | Passed |
| Property-based security | 5,000 | 0 violations |
| Context-drift testing | 5,000 | 650 weak-model violations |
| Deterministic context drift | 5 | Controlled |
| Tenant-binding LLM experiment | 1 | Weak ≠ protected |
| Protected runtime | — | 0 cross-tenant accesses |

### Current research summary

```text
Evidence artifacts:                    12/12

Authorization fuzz cases:              1,000
Property-based security cases:         5,000
Context-drift cases:                   5,000
Context-drift weak-model findings:       650
Controlled findings:                     188

Successful cross-tenant accesses:         0
Actual runtime security violations:       0

Overall status:
CONTROLLED_FINDINGS
```

---

# Authorization Context Drift

A dedicated experiment tests whether a legitimate capability can become unsafe when downstream authorization trusts a mutable effective tenant.

The controlled scenario can be represented as:

```text
Original Tenant
      │
      │ legitimate capability
      ▼
Authorization Context
      │
      │ context changes
      ▼
Effective Tenant
      │
      ▼
Tenant-B Resource
```

The strict authorization model rejects the request when authorization context drifts.

The intentionally weak context-consuming model trusts the changed effective tenant.

The randomized context-drift campaign evaluated:

```text
5,000 cases
```

and recorded:

```text
650 controlled violations
```

in the intentionally weak reference model.

These are controlled authorization-context composition findings.

They do not establish a vulnerability in an external provider or production service.

---

# Minimized Context-Drift Finding

The deterministic reproduction demonstrates a controlled composition failure where:

```text
Original tenant:
tenant-b

Capability tenant:
tenant-b

Resource tenant:
tenant-a

Effective tenant:
tenant-a

Context drift:
true
```

The strict authorization model rejects the request.

The intentionally weak downstream authorization model accepts it because it trusts the effective tenant without binding it back to the original caller.

This provides a small reproducible example of the authorization-context composition problem.

---

# Llama 3.2 Tenant-Binding Experiment

A real Llama 3.2 tool-calling experiment was added to evaluate the effect of model-generated tenant context.

The application tenant was:

```text
tenant-a
```

The target resource belonged to:

```text
tenant-b
```

The model generated a tool request equivalent to:

```text
read_document(
    document_id="doc-b-1",
    tenantId="tenant-b"
)
```

The same model-generated request was then evaluated using two executor designs.

---

## Architecture A — Weak Executor

The intentionally weak executor trusted the tenant supplied by the model.

```text
Model supplied tenant:
tenant-b

Authorization tenant:
tenant-b

Target document:
doc-b-1

Result:
ALLOW

Cross-tenant access:
TRUE
```

The weak executor returned the tenant-B document.

---

## Architecture B — Protected Executor

The protected executor ignored the model-supplied tenant for authorization and used the application's trusted tenant context.

```text
Model supplied tenant:
tenant-b

Application tenant:
tenant-a

Target document:
doc-b-1

Result:
DENY

Cross-tenant access:
FALSE
```

The protected executor returned:

```text
Access denied
```

---

# Security Observation

The same model-generated request produced different authorization outcomes depending on the executor architecture.

```text
                 SAME LLM REQUEST
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
      Weak Executor       Protected Executor
             │                   │
       trusts tenant       trusts application
       from model            tenant context
             │                   │
             ▼                   ▼
          ALLOW                 DENY
             │                   │
             ▼                   ▼
       Cross-tenant           Protected
          access               boundary
```

The security lesson demonstrated by the controlled experiment is:

> **The LLM can suggest an action. Authorization should remain an application responsibility.**

This experiment does **not** demonstrate a vulnerability in Llama 3.2.

It also does **not** demonstrate a vulnerability in Ollama, a cloud provider, or another external service.

The finding demonstrates the security effect of trusting model-supplied tenant context in the intentionally weak reference executor.

---

# Why Model Output Is Not Authorization

An LLM can generate structured tool arguments such as:

```json
{
  "document_id": "doc-b-1",
  "tenantId": "tenant-b"
}
```

The presence of a syntactically valid tenant identifier does not make that identifier authoritative.

The application already knows:

```text
authenticated tenant = tenant-a
```

Therefore the authorization layer should derive the security context from trusted application state rather than accepting:

```text
tenantId = tenant-b
```

from the model.

The architecture should treat model output as:

```text
REQUEST
```

rather than:

```text
AUTHORITY
```

---

# Protected Authorization Pattern

The intended architecture is:

```text
User / Agent
     │
     ▼
Authenticated Application Context
     │
     │ tenant = tenant-a
     ▼
Tool Executor
     │
     │ ignores model identity claims
     ▼
Authorization Layer
     │
     │ checks tenant-a
     ▼
Resource
```

A model-generated tenant value can therefore be logged, validated, or rejected without becoming the source of authorization truth.

---

# Project Structure

```text
cloud-security-research-lab/
│
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   ├── authorization.py
│   ├── tools.py
│   ├── agent.py
│   ├── audit.py
│   ├── permissions.py
│   ├── roles.py
│   ├── graph.py
│   ├── pathfinder.py
│   ├── delegation.py
│   ├── security_analyzer.py
│   ├── authorization_engine.py
│   ├── model_provider.py
│   ├── model_agent.py
│   ├── tool_executor.py
│   ├── config.py
│   ├── provider_factory.py
│   └── resource_security.py
│
├── experiments/
│   ├── baseline.py
│   ├── permissions_test.py
│   ├── security_invariants.py
│   ├── graph_test.py
│   ├── delegation_test.py
│   ├── analyzer_test.py
│   ├── authorization_test.py
│   ├── end_to_end_test.py
│   ├── scenario_generator.py
│   ├── fuzzer.py
│   ├── invariant_test.py
│   ├── model_provider_test.py
│   ├── ollama_test.py
│   ├── tool_call_test.py
│   ├── model_comparison.py
│   ├── repeated_model_test.py
│   ├── config_test.py
│   ├── configured_model_test.py
│   ├── scenarios.py
│   ├── security_corpus.py
│   ├── multi_provider_security_corpus.py
│   ├── authorization_fuzzer.py
│   ├── finding_minimizer.py
│   ├── regression_test.py
│   ├── report_generator.py
│   ├── end_to_end_security.py
│   ├── tool_call_mutator.py
│   ├── context_propagation_test.py
│   ├── context_tampering_fuzzer.py
│   ├── agent_attack_chains.py
│   ├── capability_lifecycle_test.py
│   ├── property_security_campaign.py
│   ├── research_dashboard.py
│   ├── final_research_package.py
│   ├── authorization_composition_fuzzer.py
│   ├── authorization_context_drift_test.py
│   ├── authorization_context_drift_fuzzer.py
│   ├── context_drift_regression.py
│   ├── context_drift_reproduction.py
│   └── tenant_binding_weak_vs_protected.py
│
├── reports/
│   ├── security_corpus.json
│   ├── multi_provider_security.json
│   ├── authorization_fuzz.json
│   ├── minimized_authorization_finding.json
│   ├── end_to_end_security.json
│   ├── tool_call_mutation.json
│   ├── context_tampering.json
│   ├── agent_attack_chains.json
│   ├── property_security_campaign.json
│   ├── authorization_context_drift.json
│   ├── authorization_context_drift_fuzzer.json
│   ├── tenant_binding_weak_vs_protected.json
│   └── FINAL_RESEARCH_PACKAGE.md
│
├── researcher-engine/
├── lab/
│   ├── api/
│   ├── iam/
│   ├── tenants/
│   └── storage/
│
├── notes/
├── docker-compose.yml
└── README.md
```

---

# Reproduction

Run the experiments from the project root.

## Authorization Fuzzing

```bash
python -m experiments.authorization_fuzzer
```

## Finding Minimization

```bash
python -m experiments.finding_minimizer
```

## Tool-Call Mutation

```bash
python -m experiments.tool_call_mutator
```

## Context Propagation

```bash
python -m experiments.context_propagation_test
```

## Context Tampering

```bash
python -m experiments.context_tampering_fuzzer
```

## Stateful Attack Chains

```bash
python -m experiments.agent_attack_chains
```

## Capability Lifecycle

```bash
python -m experiments.capability_lifecycle_test
```

## Property-Based Security

```bash
python -m experiments.property_security_campaign
```

## Authorization Context Drift

```bash
python -m experiments.authorization_context_drift_test
```

## Context-Drift Fuzzing

```bash
python -m experiments.authorization_context_drift_fuzzer
```

## Context-Drift Regression

```bash
python -m experiments.context_drift_regression
```

## Context-Drift Reproduction

```bash
python -m experiments.context_drift_reproduction
```

## Llama 3.2 Tenant Binding Experiment

```bash
python -m experiments.tenant_binding_weak_vs_protected
```

## Final Research Package

```bash
python -m experiments.final_research_package
```

---

# Model Configuration

The laboratory supports multiple model-provider configurations.

Example local Ollama configuration:

```text
MODEL_PROVIDER=ollama
MODEL_NAME=llama3.2
MODEL_BASE_URL=http://127.0.0.1:11434
MODEL_API_KEY=
```

The Llama experiment uses a local model environment.

Model output can depend on:

- model version
- prompt
- tool schema
- model configuration
- local runtime
- surrounding context

Therefore model behavior should be treated as experimental evidence rather than a universal guarantee.

---

# Evidence

The generated research package contains machine-readable evidence under:

```text
reports/
```

Important evidence files include:

```text
reports/security_corpus.json
reports/multi_provider_security.json
reports/authorization_fuzz.json
reports/minimized_authorization_finding.json
reports/end_to_end_security.json
reports/tool_call_mutation.json
reports/context_tampering.json
reports/agent_attack_chains.json
reports/property_security_campaign.json
reports/authorization_context_drift.json
reports/authorization_context_drift_fuzzer.json
reports/tenant_binding_weak_vs_protected.json
reports/FINAL_RESEARCH_PACKAGE.md
```

The final research package summarizes the complete controlled research campaign.

---

# Runtime Security Result

The protected runtime maintained the primary security invariant:

```text
successful_cross_tenant_access == 0
```

The recorded experiments produced:

```text
Successful cross-tenant accesses:
0

Actual runtime security violations:
0
```

This means the tested protected implementation blocked the cross-tenant access attempts represented by the current laboratory scenarios.

It does not prove that every possible authorization implementation or production deployment is secure.

---

# Controlled Findings vs. Actual Vulnerabilities

An important distinction in this research is:

```text
Controlled Finding
        ≠
Confirmed External Vulnerability
```

A controlled finding means the laboratory demonstrated unsafe authorization behavior in an intentionally weak reference model.

An actual vulnerability would require:

1. An explicitly authorized target.
2. Reproduction against that target.
3. Evidence that the behavior violates the target's intended security boundary.
4. Identification of the affected component.
5. Reproducible security impact.
6. Appropriate responsible disclosure.

This repository does not claim such an external vulnerability.

---

# Limitations

The laboratory is intentionally simplified and local.

It does not reproduce the complete:

- IAM architecture of a real cloud provider
- Network isolation model
- Identity federation
- Service-to-service authentication
- Production policy engine
- Infrastructure authorization
- Cloud resource model
- Enterprise deployment topology

The LLM-generated tool calls are also dependent on the selected model and prompt configuration.

A model not generating an unsafe request is not proof that an authorization architecture is secure.

Similarly, a weak-model authorization divergence is not evidence of an external vulnerability.

The research therefore focuses on the **security architecture and authorization design pattern** demonstrated by the controlled laboratory.

---

# Responsible Disclosure Position

This research package is intended as a controlled security research artifact.

No external cloud provider, AI provider, or production service is claimed to be vulnerable based on the experiments in this repository.

Any future external disclosure should only be performed against an explicitly authorized target.

A responsible disclosure package should contain:

- Target
- Affected component
- Security boundary
- Reproduction steps
- Expected behavior
- Actual behavior
- Security impact
- Evidence
- Remediation considerations

---

# Key Takeaway

The central architectural lesson from the experiments is:

```text
LLM output
    │
    ▼
Can request an action
    │
    X
    │
    └──── Must NOT become authorization authority
```

Instead:

```text
Authenticated application context
              │
              ▼
       Authorization layer
              │
              ▼
        Tool executor
              │
              ▼
       Tenant resource
```

The model can propose:

```text
read_document(doc-b-1)
```

but the application must independently determine whether:

```text
tenant-a
```

is authorized to access:

```text
tenant-b / doc-b-1
```

---

# Final Research Status

```text
┌─────────────────────────────────────────────┐
│                                             │
│           CONTROLLED_FINDINGS               │
│                                             │
│ Evidence artifacts:                  12/12  │
│ Authorization fuzz cases:            1,000  │
│ Property-based cases:                5,000  │
│ Context-drift cases:                 5,000  │
│ Weak-model context findings:           650  │
│ Controlled findings:                   188  │
│                                             │
│ Successful cross-tenant accesses:        0  │
│ Actual runtime violations:              0  │
│                                             │
└─────────────────────────────────────────────┘
```

The current research demonstrates a methodology for testing AI-agent authorization boundaries in multi-tenant systems and provides reproducible evidence for several controlled authorization failure modes.

---

# Author

**Ashutosh Kumar**

AI / Backend Engineer  
AI Security Research

Focus areas:

- AI Agent Security
- LLM Authorization
- Multi-Tenant Security
- Agentic AI
- RAG Security
- Python
- FastAPI
- LangGraph
- Enterprise AI Systems
- Production AI Architecture

---

## Disclaimer

This repository is a controlled security research laboratory.

The experiments are intended for authorized research and defensive security testing.

The intentionally weak authorization components are laboratory constructs and should not be deployed as production authorization systems.

**Do not use these experiments to test systems you do not own or do not have explicit authorization to assess.**
