"""Tree-sitter helpers for Python source analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

import tree_sitter_language_pack as tslp
from tree_sitter import Node, Parser

_PARSERS: dict[str, Parser] = {}


def get_parser(language: str = "python") -> Parser:
    if language not in _PARSERS:
        _PARSERS[language] = tslp.get_parser(language)
    return _PARSERS[language]


def parse(source: str, language: str = "python") -> tuple[Node, bytes]:
    src = source.encode("utf-8")
    tree = get_parser(language).parse(src)
    return tree.root_node, src


def text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def walk(node: Node) -> Iterator[Node]:
    """Depth-first iterator over all descendants (inclusive)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def find_all(node: Node, node_type: str) -> list[Node]:
    return [n for n in walk(node) if n.type == node_type]


def identifiers(node: Node, src: bytes) -> set[str]:
    """All identifier names appearing in a subtree."""
    return {text(n, src) for n in walk(node) if n.type == "identifier"}


def attribute_chains(node: Node, src: bytes) -> set[str]:
    """Dotted attribute expressions in a subtree, e.g. 'request.args'."""
    return {text(n, src) for n in walk(node) if n.type == "attribute"}


@dataclass
class DecoratedFunc:
    name: str
    func_node: Node
    decorators: list[str] = field(default_factory=list)
    decorator_nodes: list[Node] = field(default_factory=list)
    params: list[str] = field(default_factory=list)


def iter_decorated_functions(root: Node, src: bytes) -> Iterator[DecoratedFunc]:
    """Yield every function definition together with its decorators.

    Handles tree-sitter-python's `decorated_definition` wrapper as well as
    bare `function_definition` nodes.
    """
    for node in walk(root):
        if node.type == "decorated_definition":
            decos, deco_nodes = [], []
            func = None
            for child in node.children:
                if child.type == "decorator":
                    deco_nodes.append(child)
                    decos.append(text(child, src))
                elif child.type == "function_definition":
                    func = child
            if func is not None:
                yield DecoratedFunc(
                    name=_func_name(func, src),
                    func_node=func,
                    decorators=decos,
                    decorator_nodes=deco_nodes,
                    params=_func_params(func, src),
                )


def iter_all_functions(root: Node, src: bytes) -> Iterator[DecoratedFunc]:
    for node in walk(root):
        if node.type == "function_definition":
            yield DecoratedFunc(
                name=_func_name(node, src),
                func_node=node,
                params=_func_params(node, src),
            )


def _func_name(func: Node, src: bytes) -> str:
    name = func.child_by_field_name("name")
    return text(name, src) if name else "<anonymous>"


def _func_params(func: Node, src: bytes) -> list[str]:
    params_node = func.child_by_field_name("parameters")
    if not params_node:
        return []
    out = []
    for child in params_node.children:
        if child.type == "identifier":
            out.append(text(child, src))
        elif child.type in {"typed_parameter", "default_parameter", "typed_default_parameter"}:
            ident = child.child(0)
            if ident and ident.type == "identifier":
                out.append(text(ident, src))
    return out
