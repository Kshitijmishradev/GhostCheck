"""Ollama-backed analysis via LangChain."""

from __future__ import annotations

import os

from langchain_ollama import ChatOllama


def _model() -> str:
    return os.environ.get("OLLAMA_MODEL", "llama3.2")


def analyze_login_injection(function_source: str, request_body: str) -> str:
    """
    Ask the local LLM whether the raw request body could carry an injection or
    bypass that the shown login implementation does not safely handle.
    """
    llm = ChatOllama(model=_model(), temperature=0)
    prompt = f"""You are a security reviewer. You are given a C++ login-related function and a raw HTTP request body (may be JSON, form-encoded, or plain text).

Determine whether the request body could plausibly carry an injection, parsing mismatch, or authentication bypass that this specific C++ code does NOT adequately defend against. Consider only what is visible in the function (no guessing hidden framework code).

C++ function:
```cpp
{function_source}
```

Request body (raw):
{request_body}

Respond in 3-5 sentences. Start your answer with exactly one line: RISK: HIGH or RISK: MEDIUM or RISK: LOW, then explain briefly with reference to the code.
"""
    message = llm.invoke(prompt)
    return getattr(message, "content", str(message))
