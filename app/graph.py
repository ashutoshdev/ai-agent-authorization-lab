from dataclasses import dataclass, field


@dataclass
class Node:
    name: str
    kind: str


@dataclass
class Edge:
    source: str
    target: str
    action: str
    tenant_id: str | None = None
    capability: str | None = None


@dataclass
class PermissionGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, name: str, kind: str):
        self.nodes[name] = Node(
            name=name,
            kind=kind,
        )

    def add_edge(
        self,
        source: str,
        target: str,
        action: str,
        tenant_id: str | None = None,
        capability: str | None = None,
    ):
        self.edges.append(
            Edge(
                source=source,
                target=target,
                action=action,
                tenant_id=tenant_id,
                capability=capability,
            )
        )

    def neighbors(self, node: str):
        return [
            edge
            for edge in self.edges
            if edge.source == node
        ]

    def incoming(self, node: str):
        return [
            edge
            for edge in self.edges
            if edge.target == node
        ]

    def find_edges(
        self,
        source: str | None = None,
        target: str | None = None,
        action: str | None = None,
    ):
        results = self.edges

        if source is not None:
            results = [
                edge
                for edge in results
                if edge.source == source
            ]

        if target is not None:
            results = [
                edge
                for edge in results
                if edge.target == target
            ]

        if action is not None:
            results = [
                edge
                for edge in results
                if edge.action == action
            ]

        return results