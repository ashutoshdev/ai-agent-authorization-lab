from collections import deque

from app.graph import PermissionGraph


def find_paths(
    graph: PermissionGraph,
    start: str,
    target: str,
    max_depth: int = 6,
):
    queue = deque([(start, [start])])
    paths = []

    while queue:
        current, path = queue.popleft()

        if current == target:
            paths.append(path)
            continue

        if len(path) > max_depth:
            continue

        for edge in graph.neighbors(current):
            if edge.target not in path:
                queue.append(
                    (
                        edge.target,
                        path + [edge.target],
                    )
                )

    return paths