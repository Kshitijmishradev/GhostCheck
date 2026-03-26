import json
import os
import re
from typing import Any, Dict, List

from analyzer.mapper import UNSAFE_PATTERNS, map_request_to_source_snippets
from brain.llm_client import ollama_chat


INJECTION_REGEXES = [
    # Command injection indicators
    re.compile(r"[;&|]{1,2}.*", re.IGNORECASE),
    re.compile(r"\$\([^\)]*\)", re.IGNORECASE),
    re.compile(r"`[^`]*`", re.IGNORECASE),
    re.compile(r"\b(?:cat|ls|whoami|id|uname)\b", re.IGNORECASE),
    # SQL injection indicators
    re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    re.compile(r"\bSELECT\s+.*\bFROM\b", re.IGNORECASE),
    re.compile(r"\bOR\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"--\s*[^\n]*", re.IGNORECASE),
    re.compile(r"/\*\s*\d+?\s*\*/", re.IGNORECASE),
    # Template-ish / proto-pollution-ish indicators
    re.compile(r"\{\{.*\}\}", re.IGNORECASE),
    re.compile(r"\$\{.*\}", re.IGNORECASE),
]


def _truncate(s: str, max_chars: int) -> str:
    s = s or ""
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 3] + "..."


def is_injection_like(event: Dict[str, Any]) -> bool:
    body = event.get("body", "") or ""
    path = event.get("path", "") or ""
    headers = event.get("headers", {}) or {}

    haystack = (path + "\n" + body).lower()
    # Include a few header values too (auth tokens often contain separators)
    for k, v in headers.items():
        if k.lower() in {"user-agent", "referer", "x-forwarded-for", "cookie"}:
            haystack += "\n" + str(v)

    if any(r.search(haystack) for r in INJECTION_REGEXES):
        return True

    # Extra fast heuristics: common shell meta characters
    for ch in [";", "|", "&", "`", "$", "{", "}", "<", ">"]:
        if ch in haystack:
            # avoid firing for benign braces in templates, but still catch obvious cases
            return True

    return False


def _extract_first_json_object(text: str) -> Dict[str, Any] | None:
    if not text:
        return None
    # Try strict parse first (if model already outputs JSON)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    # Otherwise, extract first {...} block.
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def _build_prompt(event: Dict[str, Any], mapped: List[Dict[str, str]]) -> str:
    # Keep the prompt bounded for speed.
    body = _truncate(event.get("body", "") or "", 2000)
    path = event.get("path", "") or ""
    method = event.get("method", "") or ""

    mapped_text = ""
    if mapped:
        mapped_text = "\n\n".join(
            [
                f"FILE: {m['file']}\nSNIPPET:\n{m['snippet']}"
                for m in mapped[:6]
            ]
        )
    else:
        mapped_text = "No matching unsafe execution primitives (system/popen/exec) were found in the mapped C++ files."

    return f"""You are a security audit engine for a C++ web service.
Task:
Decide whether the incoming request should be BLOCKED or ALLOWED based on whether the relevant C++ code uses unsafe command execution with untrusted input.

Inputs:
- HTTP Method: {method}
- Request Path (+ query): {path}
- Request Body (truncated): {body}

Mapped C++ snippets (may be empty):
{mapped_text}

Rules:
1. If the mapped code contains raw unsafe execution primitives like `system(...)`, `popen(...)`, or `exec...(...)`, treat it as HIGH RISK and set action=BLOCK.
2. If no such unsafe primitives are present in the mapped snippets, treat it as LOW RISK and set action=ALLOW (even if the request looks injection-like).
3. Output MUST be valid JSON only, with this schema:
{{
  "action": "ALLOW" | "BLOCK",
  "risk": "LOW" | "HIGH",
  "reason": "one short sentence",
  "evidence": "short evidence excerpt from mapped snippets or an explanation"
}}
"""


def audit_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal LangGraph-style state machine:
    - Step 1: detect whether the request looks injection-like
    - Step 2: map request to likely C++ handlers and extract unsafe execution snippets
    - Step 3: decide ALLOW/BLOCK using deterministic rules + Ollama confirmation
    """

    action = "ALLOW"
    risk = "LOW"
    reason = "not injection-like"
    evidence = ""

    if not is_injection_like(event):
        return {"action": action, "risk": risk, "reason": reason, "evidence": evidence}

    # Injection-like => map to code and extract unsafe calls.
    mapped = map_request_to_source_snippets(event)

    # Deterministic high-risk rule: if unsafe primitives exist, we block.
    if mapped:
        action = "BLOCK"
        risk = "HIGH"
        first = mapped[0]
        reason = "unsafe command execution primitive present in mapped code"
        evidence = f"{first['file']}:\n{_truncate(first['snippet'], 600)}"
        return {"action": action, "risk": risk, "reason": reason, "evidence": evidence}

    # No unsafe snippets found => ask the LLM for a confirmation verdict.
    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    prompt = _build_prompt(event, mapped)
    system_prompt = "You are strict about outputting valid JSON only."
    try:
        raw = ollama_chat(model=model, prompt=prompt, system_prompt=system_prompt, timeout_s=25)
        decision = _extract_first_json_object(raw)
        if decision and decision.get("action") in {"ALLOW", "BLOCK"}:
            return {
                "action": decision.get("action", "ALLOW"),
                "risk": decision.get("risk", "LOW"),
                "reason": decision.get("reason", ""),
                "evidence": decision.get("evidence", _truncate(raw, 300)),
            }
    except Exception as e:
        # Fail-open to avoid breaking traffic; we still log elsewhere.
        return {
            "action": "ALLOW",
            "risk": "LOW",
            "reason": f"LLM audit failed: {e}",
            "evidence": "",
        }

    return {
        "action": "ALLOW",
        "risk": "LOW",
        "reason": "LLM response unparseable; defaulting to allow",
        "evidence": "",
    }

