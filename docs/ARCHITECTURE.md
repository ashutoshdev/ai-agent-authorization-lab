# AI Agent × Multi-Tenancy × Authorization

## Security Architecture

This document describes the architecture of the controlled security research laboratory used to study authorization boundaries in AI-agent systems operating across multiple tenants.

The laboratory focuses on the interaction between AI agents, tool calls, tool executors, shared services, authorization context, delegated capabilities, and tenant-scoped resources.

The architecture is intentionally simplified and local.

---

## 1. Research Architecture

The high-level architecture is:

```text
                    ┌───────────────────────┐
                    │       AI Agent        │
                    │                       │
                    │    tenant-a           │
                    └───────────┬───────────┘
                                │
                                │ Tool Call
                                ▼
                    ┌───────────────────────┐
                    │     Tool Layer        │
                    │                       │
                    │ list_documents        │
                    │ read_document         │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │    Tool Executor      │
                    │                       │
                    │ Authorization Context │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Authorization       │
                    │       Layer           │
                    └───────────┬───────────┘
                                │
                     ┌──────────┴──────────┐
                     │                     │
                     ▼                     ▼
             ┌───────────────┐     ┌───────────────┐
             │   Tenant A    │     │   Tenant B    │
             │               │     │               │
             │   doc-a-1     │     │   doc-b-1     │
             │               │     │               │
             │ Confidential  │     │ Confidential  │
             └───────────────┘     └───────────────┘
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

## 2. Research Question

The architecture supports the following research question:

> Can a legitimate AI agent, operating with individually valid permissions, be induced through a tool or authorization chain to perform an action that violates the application's intended tenant boundary?

The laboratory does not assume that the AI model has arbitrary administrative privileges.

Instead, it studies whether valid permissions can become unsafe when authorization context is propagated, delegated, mutated, or interpreted differently by another component.

---

## 3. Trust Boundaries

The laboratory distinguishes between trusted application state and model-generated data.

### Trusted application state

```text
Authenticated caller
       │
       ▼
Original tenant
       │
       ▼
Tool executor context
       │
       ▼
Authorization decision
       │
       ▼
Tenant-scoped resource
```

### Model-generated data

```text
LLM
 │
 ▼
Tool arguments
 │
 ├── document_id
 ├── tenantId
 └── other parameters
```

Model-generated values are treated as requests.

They are not automatically treated as authorization authority.

---

## 4. Tenant Context

The original tenant is established by the application.

Example:

```text
Original application tenant:

tenant-a
```

The protected architecture preserves that value throughout authorization.

```text
tenant-a
   │
   ▼
Tool Executor
   │
   ▼
Authorization
   │
   ▼
Resource Check
```

The model may generate:

```text
tenant-b
```

but the protected authorization layer does not use that value to replace:

```text
tenant-a
```

as the authorization tenant.

---

## 5. Tool Layer

The laboratory exposes tools representing operations available to the AI agent.

Current document operations include:

```text
list_documents
read_document
```

A normal tool request can be represented as:

```json
{
  "document_id": "doc-a-1"
}
```

A model may also produce additional fields, for example:

```json
{
  "document_id": "doc-b-1",
  "tenantId": "tenant-b"
}
```

The security question is whether the executor treats the model-generated `tenantId` as authoritative.

The protected architecture does not.

---

## 6. Protected Executor

The protected executor receives an application-bound tenant.

Conceptually:

```text
ToolExecutor(
    tenant_id="tenant-a"
)
```

When executing:

```text
read_document("doc-b-1")
```

the executor performs authorization using:

```text
application tenant = tenant-a
```

rather than:

```text
model supplied tenant = tenant-b
```

The expected result is:

```text
Access denied
```

because the resource belongs to another tenant.

---

## 7. Weak Reference Executor

The laboratory also contains an intentionally weak executor.

The weak model can use tenant information supplied by the request:

```text
Tool arguments
      │
      ▼
tenantId = tenant-b
      │
      ▼
Authorization
      │
      ▼
tenant-b resource
```

This model exists specifically to demonstrate the consequences of trusting model-controlled tenant context.

It is not intended to represent a production authorization system.

A result produced by this model is classified as a controlled finding.

---

## 8. Authorization Models

The laboratory compares two conceptual authorization approaches.

### Strict authorization model

The strict model keeps the caller tenant authoritative.

```text
Caller Tenant
     │
     ▼
Capability
     │
     ▼
Resource
```

Authorization succeeds only when relevant tenant constraints remain consistent.

Conceptually:

```text
caller tenant == capability tenant
caller tenant == resource tenant
context integrity == valid
```

Otherwise:

```text
DENY
```

A delegated capability cannot silently change the caller's tenant context.

### Context-consuming weak model

The weak context-consuming model can trust a downstream effective tenant.

```text
Original Tenant
      │
      ▼
Mutable Context
      │
      ▼
Effective Tenant
      │
      ▼
Authorization
      │
      ▼
Resource
```

If the effective tenant becomes the resource tenant, the weak model may authorize the request even though the original caller belongs to another tenant.

This is intentionally modeled as a controlled failure mode.

---

## 9. Authorization Context

The authorization context represents the tenant information available to an authorization decision.

The controlled model distinguishes:

```text
original_tenant
effective_tenant
```

The security property is that the original tenant remains authoritative unless an explicitly trusted authorization mechanism changes the security context.

The protected model therefore treats unexpected context changes as authorization failures.

---

## 10. Authorization Context Drift

Context drift is one of the primary research areas.

The intended invariant is:

```text
original_tenant == effective_tenant
```

unless an explicitly authorized operation changes the authorization context.

A controlled failure scenario can be represented as:

```text
original_tenant  = tenant-b
capability_tenant = tenant-b
resource_tenant   = tenant-a
effective_tenant  = tenant-a
```

This produces:

```text
context drift = true
```

The strict authorization model rejects the request.

The intentionally weak context-consuming model can accept it because it trusts the effective tenant without binding it back to the original caller.

---

## 11. Context Drift Data Flow

The controlled failure path is:

```text
              Original Context
                     │
                     ▼
                  tenant-b
                     │
                     │ legitimate capability
                     ▼
            Authorization Context
                     │
                     │ context mutation
                     ▼
                  tenant-a
                     │
                     ▼
              Resource tenant-a
```

The important security property is that the original caller context remains authoritative.

The weak model violates this property by allowing downstream mutable context to become the authorization source.

---

## 12. Context Drift Fuzzer

The context-drift fuzzer generates combinations of:

```text
original tenant
capability tenant
resource tenant
effective tenant
drift type
```

The strict and context-consuming models are compared.

A critical controlled case requires:

```text
cross-tenant request
+
context drift
+
legitimate capability for original tenant
+
effective tenant equals resource tenant
+
strict model denies
+
weak model allows
```

The randomized campaign evaluated:

```text
5,000 cases
```

and recorded:

```text
650 controlled violations
```

in the intentionally weak context-consuming reference model.

These are controlled authorization-context composition findings.

They do not establish a vulnerability in an external provider or production service.

---

## 13. Minimized Context-Drift Finding

A deterministic reproduction demonstrates a controlled composition failure.

The representative case is:

```text
Original tenant:
tenant-b

Capability tenant:
tenant-b

Resource tenant:
tenant-a

Resource:
doc-a-1

Effective tenant:
tenant-a

Context drift:
true
```

The strict authorization model rejects the request.

The intentionally weak downstream authorization model accepts it because it trusts the effective tenant without binding it back to the original caller.

This provides a small reproducible example of the authorization-context composition problem.

---

## 14. Authorization Graph

Authorization relationships can be represented as a graph.

Example:

```text
agent:tenant-a
      │
      │ invoke
      ▼
tool:document-reader
      │
      │ call
      ▼
shared-document-service
      │
      │ read
      ▼
resource:tenant-b-document
```

Graph edges can contain authorization metadata such as:

```text
source
target
action
tenant_id
capability
```

The graph is used by the authorization experiments and finding minimization logic.

---

## 15. Finding Minimization

The research includes a minimized controlled authorization chain.

The minimized chain contains four important relationships:

```text
agent:tenant-a
      │
      │ invoke
      ▼
tool:document-reader
      │
      │ call
      ▼
shared-document-service
      │
      │ read
      ▼
resource:tenant-b-document
```

The resource is associated with tenant-B while the initiating agent is associated with tenant-A.

The minimization process reduces the graph while preserving the observed weak-model behavior.

The minimized finding is useful because it separates the essential authorization composition from unrelated system complexity.

---

## 16. Capability Model

The laboratory models capabilities with tenant association.

Conceptually:

```text
Capability
├── name
└── tenant_id
```

Example:

```text
Capability:
    name = read_document
    tenant_id = tenant-a
```

The authorization model must ensure that the capability remains associated with the correct tenant.

A capability should not become valid for another tenant simply because downstream context changes.

---

## 17. Delegation

The laboratory models delegation relationships containing:

```text
source
target
capability
tenant_id
```

The security property is that delegation must not silently change the tenant boundary.

A delegated capability must remain appropriately bound to:

- tenant
- subject
- capability
- intended service
- authorization context

Delegation is therefore evaluated as part of the authorization composition rather than being treated as an independent trust boundary.

---

## 18. Capability Lifecycle

Authorization is also tested across capability state transitions.

The lifecycle tests include:

```text
Valid capability
       │
       ├── Expired
       ├── Revoked
       ├── Wrong subject
       ├── Wrong tenant
       ├── Wrong audience
       ├── Tenant substitution
       ├── Audience substitution
       ├── Replay after expiration
       └── Cross-service reuse
```

The recorded lifecycle experiment passed all ten defined security checks.

---

## 19. Tool-Call Mutation

Tool-call mutation tests whether authorization remains safe when requests are modified.

Mutation categories include:

- cross-tenant document identifiers
- tenant overrides
- nested tenant values
- duplicate arguments
- unknown tools
- malformed arguments
- wildcard values
- adversarial inputs

Example:

```text
read_document(doc-b-1)
```

and:

```text
read_document(
    doc-b-1,
    tenantId=tenant-b
)
```

The protected executor is expected to maintain its application-bound tenant regardless of model-generated tenant metadata.

The recorded mutation campaign evaluated:

```text
75 mutations
```

with the protected security boundary maintained.

---

## 20. Stateful Agent Attack Chains

The stateful attack-chain experiment evaluates multiple operations rather than a single request.

A simplified chain is:

```text
Agent
  │
  ▼
Capability
  │
  ▼
Tool
  │
  ▼
Shared Service
  │
  ▼
Resource
```

The research examines whether authorization state becomes weaker as the chain progresses.

The experiment evaluated:

```text
4 attack chains
```

and included controlled scenarios involving capability reuse and tenant substitution.

These results are controlled research findings rather than evidence of an external vulnerability.

---

## 21. Property-Based Security

The property-based campaign generates large numbers of authorization scenarios.

The main objective is to verify that authorization decisions remain consistent with:

```text
tenant ownership
capability constraints
resource ownership
authorization context
```

The recorded campaign evaluated:

```text
5,000 cases
```

and reported:

```text
0 security violations
```

in the protected implementation.

---

## 22. Authorization Fuzzing

The authorization fuzzer evaluates randomized combinations of authorization relationships.

The compared models include:

```text
Strict authorization
        versus
Intentionally weak authorization
```

The campaign evaluated:

```text
1,000 randomized scenarios
```

and identified controlled divergences between the models.

A model divergence is treated as a controlled finding rather than an external vulnerability.

---

## 23. Real Llama 3.2 Experiment

The laboratory includes a real Llama 3.2 tool-calling experiment.

The application starts with:

```text
application tenant = tenant-a
```

The target resource is:

```text
document = doc-b-1
resource tenant = tenant-b
```

The model generated a request equivalent to:

```text
read_document(
    document_id="doc-b-1",
    tenantId="tenant-b"
)
```

The same model-generated request was evaluated using two executor architectures.

---

## 24. Weak Executor Path

The intentionally weak executor trusts the model-supplied tenant:

```text
                    Llama 3.2
                        │
                        ▼
              tenantId = tenant-b
                        │
                        ▼
               Weak Executor
                        │
                        │ trusts model tenant
                        ▼
               Authorization
                        │
                        ▼
                 doc-b-1
                        │
                        ▼
                     ALLOW
```

Observed controlled result:

```text
Model supplied tenant: tenant-b
Application tenant:    tenant-a
Authorization tenant:  tenant-b
Cross-tenant access:   TRUE
```

The weak executor returned the tenant-B document.

---

## 25. Protected Executor Path

The protected executor keeps the application tenant authoritative:

```text
                    Llama 3.2
                        │
                        ▼
              tenantId = tenant-b
                        │
                        X
                        │
                        │ not trusted
                        ▼
             Application Context
                        │
                        ▼
                     tenant-a
                        │
                        ▼
                Authorization
                        │
                        ▼
                   doc-b-1
                        │
                        ▼
                     DENY
```

Observed result:

```text
Model supplied tenant: tenant-b
Application tenant:    tenant-a
Authorization tenant:  tenant-a
Cross-tenant access:   FALSE
```

The protected executor returned:

```text
Access denied
```

---

## 26. Same Request, Different Security Boundary

The experiment can be summarized as:

```text
                    SAME MODEL REQUEST
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
       Weak Executor             Protected Executor
              │                         │
       trusts tenantId           trusts application
         from model                tenant context
              │                         │
              ▼                         ▼
           tenant-b                  tenant-a
              │                         │
              ▼                         ▼
          doc-b-1                   doc-b-1
              │                         │
              ▼                         ▼
            ALLOW                     DENY
```

The experiment demonstrates the security effect of executor architecture.

It does not demonstrate that Llama 3.2 itself is vulnerable.

It also does not demonstrate a vulnerability in Ollama, a cloud provider, or another external service.

---

## 27. Why Model Output Is Not Authorization

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

Therefore the authorization layer should derive security context from trusted application state rather than accepting:

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

## 28. Protected Authorization Pattern

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
Tenant Resource
```

A model-generated tenant value can therefore be logged, validated, or rejected without becoming the source of authorization truth.

---

## 29. Security Principle

The central architectural principle demonstrated by the research is:

> **The LLM can suggest an action. Authorization must remain an application responsibility.**

The model can request:

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

## 30. Runtime Security Boundary

The primary runtime security invariant is:

```text
successful_cross_tenant_access == 0
```

The protected runtime recorded:

```text
Successful cross-tenant accesses:
0

Actual runtime security violations:
0
```

These results apply to the controlled laboratory scenarios tested.

They do not establish that every possible authorization implementation or production deployment is secure.

---

## 31. Research Evidence

The generated evidence is stored under:

```text
reports/
```

Important evidence artifacts include:

```text
security_corpus.json
multi_provider_security.json
authorization_fuzz.json
minimized_authorization_finding.json
end_to_end_security.json
tool_call_mutation.json
context_tampering.json
agent_attack_chains.json
property_security_campaign.json
authorization_context_drift.json
authorization_context_drift_fuzzer.json
tenant_binding_weak_vs_protected.json
FINAL_RESEARCH_PACKAGE.md
```

The final research package contains:

```text
12/12 evidence artifacts
```

The final report also records:

```text
Authorization fuzz cases:                    1,000
Property-based security cases:               5,000
Context-drift cases:                         5,000
Weak-model context-drift findings:             650
Controlled findings:                           188
Successful cross-tenant accesses:               0
Actual runtime security violations:             0
Overall status:                   CONTROLLED_FINDINGS
```

---

## 32. Reproduction

All experiments are executed using Python module execution from the repository root.

### Authorization fuzzing

```bash
python -m experiments.authorization_fuzzer
```

### Finding minimization

```bash
python -m experiments.finding_minimizer
```

### Tool-call mutation

```bash
python -m experiments.tool_call_mutator
```

### Context propagation

```bash
python -m experiments.context_propagation_test
```

### Context tampering

```bash
python -m experiments.context_tampering_fuzzer
```

### Stateful attack chains

```bash
python -m experiments.agent_attack_chains
```

### Capability lifecycle

```bash
python -m experiments.capability_lifecycle_test
```

### Property-based security

```bash
python -m experiments.property_security_campaign
```

### Authorization context drift

```bash
python -m experiments.authorization_context_drift_test
```

### Context-drift fuzzing

```bash
python -m experiments.authorization_context_drift_fuzzer
```

### Context-drift regression

```bash
python -m experiments.context_drift_regression
```

### Context-drift reproduction

```bash
python -m experiments.context_drift_reproduction
```

### Llama 3.2 tenant-binding experiment

```bash
python -m experiments.tenant_binding_weak_vs_protected
```

### Final research package

```bash
python -m experiments.final_research_package
```

---

## 33. Model Configuration

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

## 34. Project Component Responsibilities

### `app/models.py`

Defines the tenant-scoped document model and local document data.

### `app/authorization.py`

Contains direct document authorization checks.

### `app/tools.py`

Defines and executes document-related tools.

### `app/audit.py`

Records security-relevant tool execution events.

### `app/permissions.py`

Defines capability concepts used by the authorization experiments.

### `app/roles.py`

Provides role and capability association logic.

### `app/graph.py`

Represents authorization relationships as a graph.

### `app/pathfinder.py`

Finds paths through authorization graphs.

### `app/delegation.py`

Models delegation and authorization request/decision structures.

### `app/authorization_engine.py`

Contains strict and intentionally weak authorization models.

### `app/resource_security.py`

Provides resource ownership and tenant classification helpers.

### `app/model_provider.py`

Defines model-provider abstractions.

### `app/model_agent.py`

Connects model interaction with the application security model and audit behavior.

### `app/tool_executor.py`

Provides application-bound tool execution.

### `experiments/`

Contains the reproducible security experiments.

### `reports/`

Contains generated machine-readable evidence and the final research package.

---

## 35. Controlled Findings vs. Actual Vulnerabilities

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

## 36. Limitations

The laboratory is intentionally simplified and local.

It does not reproduce the complete:

- IAM architecture of a real cloud provider
- network isolation model
- identity federation
- service-to-service authentication
- production policy engine
- infrastructure authorization
- cloud provider resource model
- enterprise deployment topology

The LLM-generated tool calls are also dependent on the selected model and prompt configuration.

Therefore:

```text
No unsafe model output
        ≠
Authorization architecture is proven secure
```

Likewise:

```text
Weak-model divergence
        ≠
Confirmed external vulnerability
```

External vulnerability claims would require reproduction against an explicitly authorized target.

---

## 37. Responsible Disclosure

This laboratory is intended for controlled security research.

The current experiments do not claim a vulnerability in:

- Llama 3.2
- Ollama
- a cloud provider
- an external AI provider
- a production service

Future external testing should only be performed against explicitly authorized targets.

A responsible disclosure package should contain:

```text
Target
Affected component
Security boundary
Reproduction
Expected behavior
Actual behavior
Security impact
Evidence
Remediation
```

---

## 38. Security Review Checklist

When applying the research methodology to another authorized system, the following architectural questions are relevant:

```text
[ ] Is the authenticated tenant established outside the LLM?
[ ] Is the original tenant preserved throughout tool execution?
[ ] Can model-generated tenant fields affect authorization?
[ ] Does the executor have its own trusted tenant context?
[ ] Are resource ownership checks performed independently?
[ ] Are delegated capabilities tenant-bound?
[ ] Are capability subjects validated?
[ ] Are capability audiences validated?
[ ] Are expired capabilities rejected?
[ ] Are revoked capabilities rejected?
[ ] Can authorization context drift between services?
[ ] Does downstream authorization trust mutable effective context?
[ ] Are cross-tenant requests explicitly denied?
[ ] Are security decisions audited?
[ ] Are minimized findings converted into regression tests?
```

This checklist is a research methodology, not a claim that any particular external system has these properties.

---

## 39. Architectural Failure Pattern

The controlled weak pattern can be summarized as:

```text
                 LLM
                  │
                  ▼
          Model-generated tenant
                  │
                  ▼
            Mutable context
                  │
                  ▼
        Downstream authorization
                  │
                  ▼
             Resource
```

The security risk arises when the downstream authorization component treats mutable model-influenced context as equivalent to trusted authentication context.

---

## 40. Protected Pattern

The protected pattern is:

```text
                 LLM
                  │
                  │ request
                  ▼
             Tool Layer
                  │
                  ▼
          Tool Executor
                  │
                  │ trusted tenant
                  ▼
          Authorization Layer
                  │
                  │ resource ownership
                  ▼
          Tenant-Scoped Resource
```

The LLM can influence the requested operation but cannot independently redefine the authorization boundary.

---

## 41. Final Architecture Summary

The complete protected flow is:

```text
┌────────────────────┐
│     AI Agent       │
└─────────┬──────────┘
          │
          │ Request
          ▼
┌────────────────────┐
│    Tool Layer      │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│  Tool Executor     │
│                    │
│ Trusted tenant     │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│  Authorization     │
│                    │
│ Tenant binding     │
│ Capability checks  │
│ Context integrity  │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Tenant Resource    │
└────────────────────┘
```

The model remains capable of requesting actions, but authorization remains outside the model's control.

---

## 42. Final Research Position

The laboratory demonstrates a reproducible methodology for studying AI-agent authorization boundaries in multi-tenant systems.

The research combines:

- authorization graph analysis
- authorization fuzzing
- tool-call mutation
- context propagation testing
- context tampering
- context-drift fuzzing
- stateful attack chains
- capability lifecycle testing
- property-based security testing
- regression testing
- real LLM tool-calling

The current protected implementation recorded:

```text
Successful cross-tenant accesses: 0
Actual runtime security violations: 0
```

The intentionally weak reference models produced controlled findings that demonstrate authorization failure classes.

The results should therefore be interpreted as:

```text
Controlled Security Research
```

rather than as evidence of an external production vulnerability.

---

## Status

```text
CONTROLLED_FINDINGS
```

---

## Disclaimer

This repository is a controlled security research laboratory.

The experiments are intended for authorized research and defensive security testing.

The intentionally weak authorization components are laboratory constructs and should not be deployed as production authorization systems.

Do not use these experiments to test systems you do not own or do not have explicit authorization to assess.
