"""Map HTTP routes to on-disk sources and extract C++ function bodies."""

from __future__ import annotations

import os
import re
from pathlib import Path

from tree_sitter import Query, QueryCursor

from analyzer.tree_sitter import CodeParser

_AGENT_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _AGENT_DIR.parent

PATH_TO_FILE: dict[str, str] = {
    "/api/login": "login.cpp",
}


def _source_root() -> Path:
    env = os.environ.get("GHOSTCHECK_SOURCE_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    return _PROJECT_ROOT / "tests" / "vulnerable_app"


def normalize_http_path(path: str) -> str:
    if not path:
        return ""
    p = path.split("?", 1)[0].rstrip("/")
    if not p:
        p = "/"
    if not p.startswith("/"):
        p = "/" + p
    return p


def resolve_source_file(http_path: str) -> Path | None:
    key = normalize_http_path(http_path)
    rel = PATH_TO_FILE.get(key)
    if not rel:
        return None
    path = _source_root() / rel
    if not path.is_file():
        return None
    return path


def extract_function_body(
    source_code: str,
    func_name: str,
    language_name: str = "cpp",
) -> str | None:
    """Return full source text of the named function definition, or None."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", func_name):
        return None
    parser = CodeParser(language_name=language_name)
    src_bytes = bytes(source_code, "utf8")
    root = parser.parser.parse(src_bytes).root_node

    query_text = f"""(function_definition
  (function_declarator
    (identifier) @fname)) @fn
(#eq? @fname "{func_name}")
"""
    query = Query(parser.language, query_text)
    cursor = QueryCursor(query)
    for _pattern_index, captures in cursor.matches(root):
        nodes = captures.get("fn")
        if not nodes:
            continue
        fn = nodes[0]
        return src_bytes[fn.start_byte : fn.end_byte].decode("utf8")
    return None


def load_function_for_route(http_path: str, func_name: str) -> tuple[str, str] | None:
    """Load mapped source file and extract func_name's body."""
    src_path = resolve_source_file(http_path)
    if src_path is None:
        return None
    text = src_path.read_text(encoding="utf8")
    body = extract_function_body(text, func_name, language_name="cpp")
    if body is None:
        return None
    return (str(src_path.relative_to(_source_root())), body)
