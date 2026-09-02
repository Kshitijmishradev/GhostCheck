"""JavaScript / TypeScript (Express) analyzer.

Mirrors the Python pipeline — discover routes, taint request input to sinks,
emit findings with a proof-of-concept — but understands Express routing and
JavaScript string building (template literals, `+` concatenation).
"""
from __future__ import annotations

import re

from tree_sitter import Node

from . import parsing
from .parsing import text, walk, find_all
from .discover import Endpoint
from .findings import Finding
from .poc import build_poc

_ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "all", "options", "head"}
_PATH_PARAM_RE = re.compile(r":([A-Za-z_]\w*)")

SOURCE_PROPS = ("query", "params", "body", "headers", "cookies")
SANITIZER_SUFFIXES = ("parseInt", "Number", "basename", "normalize",
                      "encodeURIComponent", "escape", "toString")
SANITIZER_GUARDS = ("basename", "normalize", "parseInt", "Number(",
                    "test(", "isAlphanumeric", "escape(")


def _lang_for(file_label: str) -> str:
    if file_label.endswith((".ts", ".tsx")):
        return "tsx" if file_label.endswith(".tsx") else "typescript"
    return "javascript"


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def _callee_text(call: Node, src: bytes) -> str:
    fn = call.child_by_field_name("function")
    return text(fn, src) if fn is not None else ""


def _args(call: Node) -> list[Node]:
    node = call.child_by_field_name("arguments")
    if node is None:
        return []
    return [c for c in node.children if c.type not in {"(", ")", ",", "comment"}]


def _handler_of(call: Node) -> Node | None:
    for arg in reversed(_args(call)):
        if arg.type in {"arrow_function", "function_expression", "function", "function_declaration"}:
            return arg
    return None


def _first_param_name(func: Node, src: bytes) -> str:
    params = func.child_by_field_name("parameters")
    if params is None:  # arrow with a single bare param: req => ...
        p = func.child_by_field_name("parameter")
        return text(p, src) if p else "req"
    for c in params.children:
        if c.type == "identifier":
            return text(c, src)
        if c.type in {"required_parameter", "optional_parameter"}:
            ident = c.child_by_field_name("pattern") or c.child(0)
            if ident is not None:
                return text(ident, src)
    return "req"


def discover_in_source(source: str, file_label: str) -> list[Endpoint]:
    lang = _lang_for(file_label)
    root, src = parsing.parse(source, lang)
    endpoints: list[Endpoint] = []
    for call in find_all(root, "call_expression"):
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        prop = fn.child_by_field_name("property")
        if prop is None or text(prop, src) not in _ROUTE_METHODS:
            continue
        args = _args(call)
        if not args or args[0].type not in {"string", "template_string"}:
            continue
        path = text(args[0], src).strip("`'\"")
        if not path.startswith("/"):
            continue
        handler = _handler_of(call)
        if handler is None:
            continue
        method = text(prop, src).upper()
        method = "GET" if method == "ALL" else method
        name_node = handler.child_by_field_name("name")
        handler_name = text(name_node, src) if name_node is not None else ""
        endpoints.append(
            Endpoint(
                method=method,
                path=path,
                handler=handler_name,
                file=file_label,
                line=call.start_point[0] + 1,
                func_node=handler,
                src=src,
                path_params=_PATH_PARAM_RE.findall(path),
                framework="express",
                language=lang,
            )
        )
    return endpoints


# --------------------------------------------------------------------------
# Taint
# --------------------------------------------------------------------------

class JsTaint:
    def __init__(self, req_name: str, path_params: list[str]):
        self.req = req_name
        self.tainted: set[str] = set(path_params)
        self.built: set[str] = set()
        self.origins: dict[str, str] = {p: p for p in path_params}
        self.markers = tuple(f"{req_name}.{p}" for p in SOURCE_PROPS) + (f"{req_name}.get",)

    def contains_source(self, node: Node, src: bytes) -> bool:
        t = text(node, src)
        return any(m in t for m in self.markers)

    def references_tainted(self, node: Node, src: bytes) -> bool:
        names = {text(n, src) for n in walk(node) if n.type == "identifier"}
        return bool(names & self.tainted)

    def source_key(self, node: Node, src: bytes) -> str | None:
        t = text(node, src)
        m = re.search(r"\.(?:query|params|body|headers|cookies)\.([A-Za-z_]\w*)", t)
        if m:
            return m.group(1)
        m = re.search(r"""\.(?:query|params|body)\s*\[\s*['"]([^'"]+)['"]""", t)
        if m:
            return m.group(1)
        m = re.search(r"""\.get\(\s*['"]([^'"]+)['"]""", t)
        return m.group(1) if m else None


def _pattern_names(node: Node, src: bytes) -> list[str]:
    return [text(n, src) for n in walk(node)
            if n.type in {"shorthand_property_identifier_pattern", "identifier"}]


def string_built(node: Node, src: bytes) -> bool:
    if find_all(node, "template_substitution"):
        return True
    for n in walk(node):
        if n.type == "binary_expression":
            for c in n.children:
                if c.type not in {"identifier", "string", "number", "member_expression",
                                  "call_expression", "template_string", "binary_expression",
                                  "subscript_expression", "parenthesized_expression"}:
                    if text(c, src).strip() == "+":
                        return True
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn is not None and text(fn, src).endswith(".concat"):
                return True
    return False


def _is_sanitized(value: Node, src: bytes) -> bool:
    if value.type == "call_expression":
        fn = value.child_by_field_name("function")
        if fn is not None and any(text(fn, src).endswith(s) for s in SANITIZER_SUFFIXES):
            return True
    return False


def compute_taint(func: Node, src: bytes, path_params: list[str]) -> JsTaint:
    state = JsTaint(_first_param_name(func, src), path_params)
    body = func.child_by_field_name("body")
    if body is None:
        return state

    events: list[tuple[int, Node]] = []
    for n in walk(body):
        if n.type in {"variable_declarator", "assignment_expression"}:
            events.append((n.start_byte, n))
    events.sort(key=lambda e: e[0])

    for _pos, n in events:
        if n.type == "variable_declarator":
            name_node = n.child_by_field_name("name")
            value = n.child_by_field_name("value")
        else:  # assignment_expression
            name_node = n.child_by_field_name("left")
            value = n.child_by_field_name("right")
        if name_node is None or value is None:
            continue

        targets = _pattern_names(name_node, src)
        tainted = state.contains_source(value, src) or state.references_tainted(value, src)
        sanitized = _is_sanitized(value, src)
        built = tainted and not sanitized and string_built(value, src)
        key = state.source_key(value, src)
        for tgt in targets:
            if tainted and not sanitized:
                state.tainted.add(tgt)
                if built:
                    state.built.add(tgt)
                if key:
                    state.origins[tgt] = key
                elif tgt not in state.origins:
                    borrowed = None
                    for ident in walk(value):
                        if ident.type == "identifier" and text(ident, src) in state.origins:
                            borrowed = state.origins[text(ident, src)]
                            break
                    state.origins[tgt] = borrowed or tgt
            elif sanitized:
                state.tainted.discard(tgt)
                state.built.discard(tgt)
    return state


def arg_tainted(arg: Node, src: bytes, state: JsTaint) -> bool:
    return state.contains_source(arg, src) or state.references_tainted(arg, src)


def arg_built(arg: Node, src: bytes, state: JsTaint) -> bool:
    if string_built(arg, src):
        return True
    names = {text(n, src) for n in walk(arg) if n.type == "identifier"}
    return bool(names & state.built)


def arg_sanitized_here(arg: Node, src: bytes) -> bool:
    for n in walk(arg):
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn is not None and any(text(fn, src).endswith(s) for s in SANITIZER_SUFFIXES):
                return True
    return False


def guard_present(func: Node, src: bytes) -> bool:
    body_text = text(func, src)
    return any(g in body_text for g in SANITIZER_GUARDS)


def origin_key_in(arg: Node, src: bytes, state: JsTaint) -> str | None:
    key = state.source_key(arg, src)
    if key:
        return key
    for n in walk(arg):
        if n.type == "identifier" and text(n, src) in state.origins:
            return state.origins[text(n, src)]
    return None


# --------------------------------------------------------------------------
# Sink detection
# --------------------------------------------------------------------------

SSRF_OBJECTS = ("axios", "http", "https", "got", "superagent", "needle")


def _ends_any(name: str, suffixes: tuple[str, ...]) -> bool:
    return any(name == s or name.endswith("." + s) for s in suffixes)


def _line_text(src: bytes, node: Node) -> str:
    lines = src.split(b"\n")
    i = node.start_point[0]
    if 0 <= i < len(lines):
        return lines[i].decode("utf-8", "replace").strip()
    return text(node, src).strip()


def _has_shell_true(call: Node, src: bytes) -> bool:
    return "shell:true" in text(call, src).replace(" ", "")


def analyze_endpoint(ep: Endpoint) -> list[Finding]:
    src = ep.src
    state = compute_taint(ep.func_node, src, ep.path_params)
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def emit(vuln: str, node: Node, arg: Node, callee: str) -> None:
        key = origin_key_in(arg, src, state) or (ep.path_params[0] if ep.path_params else "input")
        dedup = (vuln, node.start_point[0])
        if dedup in seen:
            return
        seen.add(dedup)
        payload, request = build_poc(ep, vuln, key)
        findings.append(
            Finding(
                vuln=vuln, method=ep.method, path=ep.path, handler=ep.handler,
                file=ep.file, line=node.start_point[0] + 1,
                evidence=_line_text(src, node),
                sink=callee.split(".")[-1] + "()", param=key,
                poc_payload=payload, poc_request=request,
            ).enrich()
        )

    for call in find_all(ep.func_node, "call_expression"):
        callee = _callee_text(call, src)
        args = _args(call)
        if not args:
            continue
        arg0 = args[0]
        tainted = arg_tainted(arg0, src, state)

        # SQL injection
        if _ends_any(callee, ("query", "execute", "raw")):
            if tainted and arg_built(arg0, src, state):
                emit("SQLI", call, arg0, callee)
                continue
        # Command injection
        if callee in {"exec", "execSync"} or _ends_any(callee, ("exec", "execSync")):
            if tainted:
                emit("CMDI", call, arg0, callee)
                continue
        if _ends_any(callee, ("spawn", "execFile")) and _has_shell_true(call, src) and tainted:
            emit("CMDI", call, arg0, callee)
            continue
        # Path traversal
        if _ends_any(callee, ("readFile", "readFileSync", "createReadStream", "sendFile", "download")):
            if tainted and not arg_sanitized_here(arg0, src) and not guard_present(ep.func_node, src):
                emit("PATH", call, arg0, callee)
                continue
        # SSRF
        obj = callee.split(".")[0]
        if callee == "fetch" or obj in SSRF_OBJECTS or _ends_any(callee, ("request",)):
            if tainted:
                emit("SSRF", call, arg0, callee)
                continue
        # Reflected XSS via res.send/.write/.end
        if _ends_any(callee, ("send", "write", "end")):
            if tainted and arg_built(arg0, src, state) and "<" in text(arg0, src):
                emit("XSS", call, arg0, callee)
                continue

    return findings
