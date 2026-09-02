"""Finding data model + vulnerability metadata."""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

VULN_META: dict[str, dict[str, str]] = {
    "SQLI": {
        "title": "SQL Injection",
        "severity": "HIGH",
        "cwe": "CWE-89",
        "fix": "Use parameterised queries / prepared statements (placeholders + bound "
               "parameters); never build SQL by string concatenation or interpolation.",
    },
    "CMDI": {
        "title": "OS Command Injection",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "fix": "Don't pass user input to a shell. Use a no-shell exec API with an argument "
               "array (subprocess.run([...]) / execFile) and allow-list the input.",
    },
    "PATH": {
        "title": "Path Traversal",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "fix": "Reduce the input to a basename and confirm the resolved path stays inside "
               "the intended directory before opening it.",
    },
    "SSRF": {
        "title": "Server-Side Request Forgery",
        "severity": "HIGH",
        "cwe": "CWE-918",
        "fix": "Allow-list the hosts/schemes the server may request; reject internal "
               "addresses and cloud-metadata endpoints.",
    },
    "XSS": {
        "title": "Reflected Cross-Site Scripting",
        "severity": "MEDIUM",
        "cwe": "CWE-79",
        "fix": "Escape user input before placing it in HTML (template auto-escaping or a "
               "dedicated escaper); never build HTML by string concatenation.",
    },
}


@dataclass
class Finding:
    vuln: str                 # SQLI / CMDI / ...
    method: str
    path: str
    handler: str
    file: str
    line: int
    evidence: str
    sink: str
    param: str
    severity: str = ""
    confidence: str = "HIGH"
    fix: str = ""
    poc_payload: str = ""
    poc_request: str = ""
    cwe: str = ""

    def enrich(self) -> "Finding":
        meta = VULN_META.get(self.vuln, {})
        self.severity = self.severity or meta.get("severity", "MEDIUM")
        self.fix = self.fix or meta.get("fix", "")
        self.cwe = self.cwe or meta.get("cwe", "")
        return self

    @property
    def title(self) -> str:
        return VULN_META.get(self.vuln, {}).get("title", self.vuln)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["title"] = self.title
        return d


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line),
    )
