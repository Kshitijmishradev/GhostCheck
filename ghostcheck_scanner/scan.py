"""Top-level scan orchestration across languages."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .discover import discover_in_source as discover_py, Endpoint
from .detectors.engine import analyze_endpoint as analyze_py
from . import javascript as js
from .findings import Finding, sort_findings

_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__",
              ".mypy_cache", "dist", "build", ".next", "coverage"}
_PY_EXT = {".py"}
_JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


@dataclass
class ScanResult:
    root: str
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def vulnerable_endpoints(self) -> int:
        return len({(f.method, f.path) for f in self.findings})

    @property
    def languages(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.endpoints:
            out[e.language] = out.get(e.language, 0) + 1
        return out

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def _analyze_source(source: str, label: str, ext: str) -> tuple[list[Endpoint], list[Finding]]:
    endpoints: list[Endpoint] = []
    findings: list[Finding] = []
    try:
        if ext in _PY_EXT:
            endpoints = discover_py(source, label)
            for ep in endpoints:
                findings.extend(analyze_py(ep))
        elif ext in _JS_EXT:
            endpoints = js.discover_in_source(source, label)
            for ep in endpoints:
                findings.extend(js.analyze_endpoint(ep))
    except Exception:
        # A parse failure on one file must never sink the whole scan.
        return [], []
    return endpoints, findings


def scan_repo(root: str) -> ScanResult:
    root_path = Path(root)
    endpoints: list[Endpoint] = []
    findings: list[Finding] = []

    if root_path.is_file():
        files = [root_path]
        base = root_path.parent
    else:
        files = [p for p in sorted(root_path.rglob("*"))
                 if p.is_file() and p.suffix in (_PY_EXT | _JS_EXT)
                 and not any(part in _SKIP_DIRS for part in p.parts)]
        base = root_path

    for f in files:
        try:
            source = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        label = str(f.relative_to(base)) if f != base else f.name
        eps, fnd = _analyze_source(source, label, f.suffix)
        endpoints.extend(eps)
        findings.extend(fnd)

    return ScanResult(root=root, endpoints=endpoints, findings=sort_findings(findings))
