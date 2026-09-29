from datetime import datetime, timezone


EVENTS = []


def record_event(
    actor: str,
    tool: str,
    tenant_id: str,
    resource: str,
    result: str,
    metadata: dict | None = None,
):
    EVENTS.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "tool": tool,
            "tenant_id": tenant_id,
            "resource": resource,
            "result": result,
            "metadata": metadata or {},
        }
    )


def get_events():
    return EVENTS


def clear_events():
    EVENTS.clear()