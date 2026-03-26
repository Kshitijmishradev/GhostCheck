"""C/C++ parsing via tree-sitter-language-pack (tree-sitter 0.25+)."""

from __future__ import annotations

from tree_sitter import Parser, Query, QueryCursor
import tree_sitter_language_pack as tslp


class CodeParser:
    def __init__(self, language_name: str = "cpp") -> None:
        self.language = tslp.get_language(language_name)
        self.parser = Parser(self.language)

    def parse_code(self, source_code: str):
        """Return the root node; source must be representable as UTF-8 bytes for Tree-sitter."""
        tree = self.parser.parse(bytes(source_code, "utf8"))
        return tree.root_node

    def find_function_by_name(self, root_node, func_name: str):
        """Return match dicts from a query that binds @func_name to the given identifier."""
        query_text = f"""(function_definition
  (function_declarator
    (identifier) @func_name))
(#eq? @func_name "{func_name}")
"""
        query = Query(self.language, query_text)
        cursor = QueryCursor(query)
        return [
            captures
            for _pattern_index, captures in cursor.matches(root_node)
            if captures.get("func_name")
        ]
