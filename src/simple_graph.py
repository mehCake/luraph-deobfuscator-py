"""Minimal drop-in replacements for subset of networkx API used in tests."""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, Iterable, Iterator, Set


class Graph:
    """Undirected graph storing adjacency sets."""

    def __init__(self) -> None:
        self._adj: Dict[Any, Set[Any]] = {}

    def add_node(self, node: Any) -> None:
        if node not in self._adj:
            self._adj[node] = set()

    def add_edge(self, left: Any, right: Any) -> None:
        self.add_node(left)
        self.add_node(right)
        self._adj[left].add(right)
        self._adj[right].add(left)

    def neighbors(self, node: Any) -> Iterable[Any]:
        return self._adj.get(node, ())

    @property
    def nodes(self) -> Set[Any]:
        return set(self._adj.keys())


class DiGraph:
    """Directed graph storing adjacency sets."""

    def __init__(self) -> None:
        self._succ: Dict[Any, Set[Any]] = {}

    def add_node(self, node: Any) -> None:
        if node not in self._succ:
            self._succ[node] = set()

    def add_edge(self, left: Any, right: Any) -> None:
        self.add_node(left)
        self.add_node(right)
        self._succ[left].add(right)

    def successors(self, node: Any) -> Iterable[Any]:
        return self._succ.get(node, ())

    @property
    def nodes(self) -> Set[Any]:
        return set(self._succ.keys())


def connected_components(graph: Graph) -> Iterator[Set[Any]]:
    """Yield connected components of an undirected graph."""

    visited: Set[Any] = set()
    for node in graph.nodes:
        if node in visited:
            continue
        component: Set[Any] = set()
        queue: deque[Any] = deque([node])
        visited.add(node)
        while queue:
            current = queue.popleft()
            component.add(current)
            for neighbor in graph.neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        yield component


__all__ = ["Graph", "DiGraph", "connected_components"]
