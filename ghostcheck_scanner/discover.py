"""Discover HTTP endpoints in a repo and map each to its handler function."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Node

from . import parsing

# Route-defining decorators for the frameworks we support.
# Flask/Blueprint:  @app.route(...) / @bp.route(...)  + method kwarg
# Flask 2 / FastAPI shortcuts:  @app.get / .post / .put / .delete / .patch
_ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}
_ROUTE_ATTR_RE = re.compile(r"\.(route|get|post|put|delete|patch|options|head)\s*\(")
_PATH_ARG_RE = re.compile(r"""\.\w+\(\s*['"]([^'"]+)['"]""")
_METHODS_KW_RE = re.compile(r"methods\s*=\s*\[([^\]]*)\]")
_PATH_PARAM_RE = re.compile(r"[<{]\s*(?:[^:<>{}]+:)?\s*([A-Za-z_]\w*)\s*[>}]")


@dataclass
class Endpoint:
    method: str
    path: str
    handler: str
    file: str
    line: int
    func_node: Node
    src: bytes
    path_params: list[str] = field(default_factory=list)
    framework: str = "flask"
    language: str = "python"


def _extract_methods(decorator_text: str, verb: str) -> list[str]:
    if verb in _ROUTE_METHODS:
        return [verb.upper()]
    m = _METHODS_KW_RE.search(decorator_text)
    if m:
        methods = re.findall(r"['\"](\w+)['\"]", m.group(1))
        if methods:
            return [x.upper() for x in methods]
    return ["GET"]


def discover_in_source(source: str, file_label: str) -> list[Endpoint]:
    root, src = parsing.parse(source)
    endpoints: list[Endpoint] = []
    for fn in parsing.iter_decorated_functions(root, src):
        for deco_text, deco_node in zip(fn.decorators, fn.decorator_nodes):
            m = _ROUTE_ATTR_RE.search(deco_text)
            if not m:
                continue
            verb = m.group(1)
            path_m = _PATH_ARG_RE.search(deco_text)
            if not path_m:
                continue
            path = path_m.group(1)
            methods = _extract_methods(deco_text, verb)
            path_params = _PATH_PARAM_RE.findall(path)
            for method in methods:
                endpoints.append(
                    Endpoint(
                        method=method,
                        path=path,
                        handler=fn.name,
                        file=file_label,
                        line=fn.func_node.start_point[0] + 1,
                        func_node=fn.func_node,
                        src=src,
                        path_params=path_params,
                    )
                )
    return endpoints


def discover_in_repo(root_dir: str) -> list[Endpoint]:
    root = Path(root_dir)
    endpoints: list[Endpoint] = []
    skip = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache"}
    for py in sorted(root.rglob("*.py")):
        if any(part in skip for part in py.parts):
            continue
        try:
            source = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        label = str(py.relative_to(root))
        endpoints.extend(discover_in_source(source, label))
    return endpoints
