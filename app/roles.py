from app.permissions import Capability


class Role:
    def __init__(self, name: str):
        self.name = name
        self.capabilities: list[Capability] = []

    def add(self, capability: Capability):
        self.capabilities.append(capability)

    def can(self, capability_name: str, tenant_id: str) -> bool:
        return any(
            capability.name == capability_name
            and capability.tenant_id == tenant_id
            for capability in self.capabilities
        )