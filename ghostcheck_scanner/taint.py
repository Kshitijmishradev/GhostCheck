"""A pragmatic taint engine: track request-derived data to dangerous sinks.

This is intentionally lightweight (intra-procedural, heuristic) rather than a
full data-flow analysis, but it is precise enough to separate real injection
sinks from safely-sanitised code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from tree_sitter import Node

from . import parsing
from .parsing import text, walk, find_all

# Attribute chains that introduce attacker-controlled data.
SOURCE_MARKERS = (
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.get_json",
    "request.data",
    "request.cookies",
    "request.headers",
    "request.files",
    "request.query_params",  # FastAPI/Starlette
)

# Calls that neutralise taint for the purpose of the sink they guard.
SANITIZER_SUFFIXES = (
    "int", "float", "bool",
    "escape", "quote", "basename", "secure_filename",
    "json.dumps", "jsonify",
)

_KEY_RE = re.compile(r"""request\.\w+(?:\.get)?\s*[\(\[]\s*['"]([^'"]+)['"]""")


@dataclass
class TaintState:
    tainted: set[str] = field(default_factory=set)
    sanitized: set[str] = field(default_factory=set)
    built: set[str] = field(default_factory=set)  # vars assembled from tainted strings
    origins: dict[str, str] = field(default_factory=dict)  # var -> source key
    path_params: list[str] = field(default_factory=list)


def _contains_source(node: Node, src: bytes) -> bool:
    t = text(node, src)
    return any(marker in t for marker in SOURCE_MARKERS)


def _source_key(node: Node, src: bytes) -> str | None:
    m = _KEY_RE.search(text(node, src))
    return m.group(1) if m else None


def _rhs_is_sanitized(rhs: Node, src: bytes) -> bool:
    if rhs.type != "call":
        return False
    fn = rhs.child_by_field_name("function")
    if fn is None:
        return False
    name = text(fn, src)
    return any(name.endswith(suf) for suf in SANITIZER_SUFFIXES)


def _assignment_targets(node: Node, src: bytes) -> list[str]:
    left = node.child_by_field_name("left")
    if left is None:
        return []
    if left.type == "identifier":
        return [text(left, src)]
    # tuple / pattern targets
    return [text(n, src) for n in walk(left) if n.type == "identifier"]


def compute_taint(func_node: Node, src: bytes, path_params: list[str]) -> TaintState:
    state = TaintState(path_params=list(path_params))
    # Route path params are attacker-controlled from the start.
    for p in path_params:
        state.tainted.add(p)
        state.origins[p] = p

    body = func_node.child_by_field_name("body")
    if body is None:
        return state

    # Collect assignments (and `with ... as x`) in document order.
    events: list[tuple[int, str, Node]] = []
    for n in walk(body):
        if n.type == "assignment":
            events.append((n.start_byte, "assign", n))
        elif n.type == "with_item":
            events.append((n.start_byte, "with", n))
        elif n.type == "for_statement":
            events.append((n.start_byte, "for", n))
    events.sort(key=lambda e: e[0])

    for _pos, kind, n in events:
        if kind == "assign":
            rhs = n.child_by_field_name("right")
            targets = _assignment_targets(n, src)
            if rhs is None or not targets:
                continue
            tainted_rhs = _contains_source(rhs, src) or _references_tainted(rhs, src, state)
            sanitized = _rhs_is_sanitized(rhs, src)
            key = _source_key(rhs, src)
            built_rhs = tainted_rhs and not sanitized and string_built(rhs, src)
            for tgt in targets:
                if tainted_rhs and not sanitized:
                    state.tainted.add(tgt)
                    state.sanitized.discard(tgt)
                    if built_rhs:
                        state.built.add(tgt)
                    if key:
                        state.origins[tgt] = key
                    elif tgt not in state.origins:
                        state.origins[tgt] = _borrow_origin(rhs, src, state) or tgt
                elif sanitized:
                    state.tainted.discard(tgt)
                    state.sanitized.add(tgt)
        elif kind == "with":
            # with open(...) as fh / with request... as x
            value = n.child(0)
            alias = None
            for c in n.children:
                if c.type == "as_pattern":
                    value = c.child(0)
                    tgt_node = c.child_by_field_name("alias") or c.children[-1]
                    alias = text(tgt_node, src)
            if alias and value is not None:
                if _contains_source(value, src) or _references_tainted(value, src, state):
                    state.tainted.add(alias)
        elif kind == "for":
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if left is not None and right is not None:
                if _contains_source(right, src) or _references_tainted(right, src, state):
                    for ident in walk(left):
                        if ident.type == "identifier":
                            state.tainted.add(text(ident, src))
    return state


def _references_tainted(node: Node, src: bytes, state: TaintState) -> bool:
    names = {text(n, src) for n in walk(node) if n.type == "identifier"}
    return bool(names & state.tainted)


def _borrow_origin(node: Node, src: bytes, state: TaintState) -> str | None:
    for n in walk(node):
        if n.type == "identifier":
            name = text(n, src)
            if name in state.origins:
                return state.origins[name]
    return None


# --------------------------------------------------------------------------
# Argument inspection used by detectors
# --------------------------------------------------------------------------

def arg_is_tainted(arg: Node, src: bytes, state: TaintState) -> bool:
    if _contains_source(arg, src):
        return True
    return _references_tainted(arg, src, state)


def arg_is_sanitized_here(arg: Node, src: bytes) -> bool:
    """The dangerous argument is itself wrapped by a sanitizer call."""
    for n in walk(arg):
        if n.type == "call":
            fn = n.child_by_field_name("function")
            if fn is not None and any(text(fn, src).endswith(s) for s in SANITIZER_SUFFIXES):
                return True
    return False


def string_built(arg: Node, src: bytes) -> bool:
    """True if the argument is assembled from parts (concat/f-string/%/format/join)."""
    if find_all(arg, "interpolation"):  # f-string with substitution
        return True
    for n in walk(arg):
        if n.type == "binary_operator":
            op = _binop(n, src)
            if op in {"+", "%"}:
                return True
        if n.type == "call":
            fn = n.child_by_field_name("function")
            if fn is not None:
                fname = text(fn, src)
                if fname.endswith(".format") or fname.endswith(".join"):
                    return True
    return False


def arg_is_string_built(arg: Node, src: bytes, state: TaintState) -> bool:
    """The argument is assembled from tainted parts, either inline or via a
    variable that was itself built from tainted strings (e.g. `q = "..." + x`)."""
    if string_built(arg, src):
        return True
    names = {text(n, src) for n in walk(arg) if n.type == "identifier"}
    return bool(names & state.built)


def _binop(node: Node, src: bytes) -> str:
    for c in node.children:
        if c.type not in {"identifier", "string", "integer", "float", "call",
                          "attribute", "subscript", "binary_operator",
                          "parenthesized_expression", "tuple"}:
            token = text(c, src).strip()
            if token in {"+", "%", "-", "*", "/"}:
                return token
    return ""


def origin_key_in(arg: Node, src: bytes, state: TaintState) -> str | None:
    key = _source_key(arg, src)
    if key:
        return key
    for n in walk(arg):
        if n.type == "identifier":
            name = text(n, src)
            if name in state.origins:
                return state.origins[name]
    return None


def sanitizer_guard_present(func_node: Node, src: bytes) -> bool:
    """Heuristic: the handler validates input before using it.

    Catches patterns like `.isalnum()`, `abspath(...).startswith(...)`,
    `basename(...)`, `secure_filename(...)`.
    """
    body_text = text(func_node, src)
    guards = ("isalnum", "isdigit", "basename", "secure_filename",
              "abspath", "shlex.quote", "re.fullmatch", "re.match")
    return any(g in body_text for g in guards)
