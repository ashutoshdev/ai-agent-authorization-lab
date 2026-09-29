import json
import os
from datetime import datetime, timezone


REPORT_PATH = (
    "reports/security_research_finding.md"
)


def load_minimized_finding():
    path = (
        "reports/"
        "minimized_authorization_finding.json"
    )

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Missing required report: {path}\n"
            "Run finding_minimizer first."
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def build_report(
    data: dict,
) -> str:
    finding = data["finding"]

    generated_at = datetime.now(
        timezone.utc
    ).isoformat()

    caller_tenant = finding[
        "caller_tenant"
    ]

    resource_tenant = finding[
        "resource_tenant"
    ]

    service = finding[
        "service"
    ]

    capability = finding[
        "capability"
    ]

    strict_allowed = finding[
        "strict_allowed"
    ]

    weak_allowed = finding[
        "weak_allowed"
    ]

    weak_effective_tenant = finding[
        "weak_effective_tenant"
    ]

    original_edges = finding[
        "original_edge_count"
    ]

    minimized_edges = finding[
        "minimized_edge_count"
    ]

    edges = finding[
        "edges"
    ]

    edge_lines = []

    for index, edge in enumerate(
        edges,
        start=1,
    ):
        edge_lines.append(
            (
                f"{index}. "
                f"`{edge['source']}` "
                f"--[{edge['action']}]--> "
                f"`{edge['target']}` "
                f"(tenant="
                f"`{edge['tenant_id']}`, "
                f"capability="
                f"`{edge['capability']}`)"
            )
        )

    edge_text = "\n".join(
        edge_lines
    )

    return f"""# Security Research Finding

## Finding ID

`AUTHORIZATION-DIVERGENCE-001`

## Title

Cross-Tenant Authorization Divergence in a Shared-Service Delegation Model

## Status

Controlled laboratory finding.

This report describes behavior reproduced in a local security
research environment. It is **not a claim about any external
cloud provider or production service**.

## Generated

{generated_at}

---

## 1. Executive Summary

The controlled experiment demonstrates an authorization divergence
between two authorization models operating over the same permission
graph.

The strict model binds authorization to the caller tenant.

The intentionally weak model accepts possession of a capability
without preserving the caller's tenant binding.

For the reproduced scenario:

- Caller tenant: `{caller_tenant}`
- Resource tenant: `{resource_tenant}`
- Shared service: `{service}`
- Requested capability: `{capability}`

The strict model returned:

`{"ALLOWED" if strict_allowed else "DENIED"}`

The weak model returned:

`{"ALLOWED" if weak_allowed else "DENIED"}`

The weak model produced effective tenant:

`{weak_effective_tenant}`

This demonstrates the security property that must be preserved in
multi-tenant delegated authorization:

> Authorization must not allow a caller to acquire an effective
> tenant context different from its authenticated tenant merely
> because a shared service possesses a capability.

---

## 2. Security Hypothesis

The experiment investigates:

> Can an AI agent operating with individually valid permissions
> reach a shared service whose delegated capability causes the
> authorization context to cross a tenant boundary?

This is a research hypothesis rather than an assertion of a
real-world vulnerability.

---

## 3. Threat Model

### Attacker

A tenant-controlled agent or workflow operating with valid
permissions inside its own tenant.

### Trusted Components

- Tenant identity
- Authorization engine
- Shared service
- Resource ownership metadata

### Potentially Untrusted Components

- Model-generated tool requests
- User-provided instructions
- Delegated capability chains
- Service-to-service authorization context

### Security Boundary

The authorization decision performed immediately before access
to the protected resource.

---

## 4. Security Invariant

The primary invariant is:

```text
if authorization == ALLOWED:
    effective_tenant == caller_tenant
"""    