"""Apply sink specifications to a handler and emit findings."""
from __future__ import annotations

from tree_sitter import Node

from ..discover import Endpoint
from ..findings import Finding
from ..poc import build_poc
from ..parsing import text, walk, find_all
from .. import taint


def _line_text(src: bytes, node: Node) -> str:
    line_no = node.start_point[0]
    lines = src.split(b"\n")
    if 0 <= line_no < len(lines):
        return lines[line_no].decode("utf-8", "replace").strip()
    return text(node, src).strip()


def _callee(call: Node, src: bytes) -> str:
    fn = call.child_by_field_name("function")
    return text(fn, src) if fn is not None else ""


def _first_arg(call: Node) -> Node | None:
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    for c in args.children:
        if c.type not in {"(", ")", ",", "comment"} and c.type != "keyword_argument":
            return c
    return None


def _has_kwarg(call: Node, src: bytes, key: str, value: str) -> bool:
    args = call.child_by_field_name("arguments")
    if args is None:
        return False
    for c in args.children:
        if c.type == "keyword_argument":
            t = text(c, src).replace(" ", "")
            if t == f"{key}={value}":
                return True
    return False


def _ends_any(name: str, suffixes: tuple[str, ...]) -> bool:
    return any(name == s or name.endswith("." + s) for s in suffixes)


def analyze_endpoint(ep: Endpoint) -> list[Finding]:
    src = ep.src
    state = taint.compute_taint(ep.func_node, src, ep.path_params)
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def emit(vuln: str, node: Node, arg: Node, callee: str) -> None:
        key = taint.origin_key_in(arg, src, state) or (ep.path_params[0] if ep.path_params else "input")
        dedup = (vuln, node.start_point[0])
        if dedup in seen:
            return
        seen.add(dedup)
        payload, request = build_poc(ep, vuln, key)
        findings.append(
            Finding(
                vuln=vuln,
                method=ep.method,
                path=ep.path,
                handler=ep.handler,
                file=ep.file,
                line=node.start_point[0] + 1,
                evidence=_line_text(src, node),
                sink=callee.split(".")[-1] + "()",
                param=key,
                poc_payload=payload,
                poc_request=request,
            ).enrich()
        )

    for call in find_all(ep.func_node, "call"):
        callee = _callee(call, src)
        arg0 = _first_arg(call)
        if arg0 is None:
            continue
        tainted = taint.arg_is_tainted(arg0, src, state)

        # --- SQL injection -------------------------------------------------
        if _ends_any(callee, ("execute", "executescript", "executemany", "raw")):
            if tainted and taint.arg_is_string_built(arg0, src, state):
                emit("SQLI", call, arg0, callee)
                continue

        # --- OS command injection -----------------------------------------
        if _ends_any(callee, ("system", "popen", "getoutput")):
            if tainted:
                emit("CMDI", call, arg0, callee)
                continue
        if "subprocess" in callee or _ends_any(callee, ("call", "run", "Popen", "check_output", "check_call")):
            if _has_kwarg(call, src, "shell", "True") and tainted:
                emit("CMDI", call, arg0, callee)
                continue

        # --- Path traversal ------------------------------------------------
        if _ends_any(callee, ("open", "send_file", "send_from_directory")):
            if tainted and not taint.arg_is_sanitized_here(arg0, src) \
                    and not taint.sanitizer_guard_present(ep.func_node, src):
                emit("PATH", call, arg0, callee)
                continue

        # --- SSRF ----------------------------------------------------------
        if _ends_any(callee, ("urlopen",)) or callee.startswith("requests.") or callee.startswith("httpx."):
            if tainted:
                emit("SSRF", call, arg0, callee)
                continue

    # --- Reflected XSS (return an HTML string built from taint) -----------
    for ret in find_all(ep.func_node, "return_statement"):
        value = None
        for c in ret.children:
            if c.type not in {"return", "comment"}:
                value = c
        if value is None:
            continue
        if value.type == "call":
            fn = value.child_by_field_name("function")
            if fn is not None and text(fn, src).split(".")[-1] in {"jsonify", "escape", "dumps", "render_template"}:
                continue
        if taint.arg_is_tainted(value, src, state) and taint.string_built(value, src) and "<" in text(value, src):
            emit("XSS", ret, value, "response")

    return findings
