# Cloud Security Research Dashboard

Generated: `2026-09-28T23:12:42.995144+00:00`

## Research Status

**Overall status: `CONTROLLED_FINDINGS`**

The primary runtime security invariant is:

```text
successful_cross_tenant_access == 0
```

The dashboard distinguishes actual successful cross-tenant access from intentionally reproduced controlled findings in the weak authorization model.

## Summary

| Metric | Value |
|---|---:|
| Evidence files | 9 |
| Available files | 9 |
| Missing files | 0 |
| Authorization fuzz cases | 1000 |
| Property-security cases | 5000 |
| Stateful attack chains | 4 |
| Tool-call mutations | 75 |
| End-to-end scenarios | 5 |
| Successful cross-tenant access | 0 |
| Controlled findings | 188 |
| Actual security violations | 0 |

## Evidence Files

| Experiment | Path | Status | Size |
|---|---|---|---:|
| security_corpus | `reports/security_corpus.json` | AVAILABLE | 5935 |
| multi_provider | `reports/multi_provider_security.json` | AVAILABLE | 2936 |
| authorization_fuzz | `reports/authorization_fuzz.json` | AVAILABLE | 93209 |
| minimized_finding | `reports/minimized_authorization_finding.json` | AVAILABLE | 4714 |
| end_to_end | `reports/end_to_end_security.json` | AVAILABLE | 2672 |
| tool_mutation | `reports/tool_call_mutation.json` | AVAILABLE | 76593 |
| context_tampering | `reports/context_tampering.json` | AVAILABLE | 1625 |
| attack_chains | `reports/agent_attack_chains.json` | AVAILABLE | 3997 |
| property_campaign | `reports/property_security_campaign.json` | AVAILABLE | 386 |

## Interpretation

### Successful cross-tenant access

The runtime evidence reports:

**Successful cross-tenant access: 0**

A value greater than zero would indicate that the runtime enforcement layer returned cross-tenant data during an experiment.

### Controlled findings

Controlled findings are deliberately reproduced security weaknesses in the local research model.

- confused-deputy authorization divergence
- context tampering
- weak capability reuse
- capability tenant substitution

These findings are not automatically evidence of a production or cloud-provider vulnerability.

## Research Coverage

1. Tenant isolation
2. Tool-call mutation
3. AI-agent security scenarios
4. Authorization graph fuzzing
5. Finding minimization
6. Context propagation
7. Context tampering
8. Stateful capability chains
9. Capability lifecycle
10. Property-based authorization testing
11. Runtime cross-tenant enforcement

## Important Limitation

This dashboard represents a local controlled security research laboratory.

It does not establish that any production cloud provider, SaaS platform, model provider, or external system is vulnerable.

Any real-world security finding requires:

- authorized scope
- reproducibility in the affected system
- evidence from the affected system
- impact validation
- responsible disclosure
