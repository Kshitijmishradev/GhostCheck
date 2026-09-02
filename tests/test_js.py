"""End-to-end tests for the JavaScript / Express analyzer."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghostcheck_scanner.scan import scan_repo
from ghostcheck_scanner import javascript as js

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "sample_vulnerable_express")

EXPECTED = {
    ("GET", "/users/:id"): "SQLI",
    ("POST", "/login"): "SQLI",
    ("GET", "/download"): "PATH",
    ("GET", "/read"): "PATH",
    ("GET", "/fetch"): "SSRF",
    ("GET", "/ping"): "CMDI",
    ("GET", "/greet"): "XSS",
    ("GET", "/users_safe/:id"): None,
    ("GET", "/download_safe"): None,
    ("GET", "/ping_safe"): None,
    ("GET", "/health"): None,
}


@pytest.fixture(scope="module")
def result():
    return scan_repo(SAMPLE)


def test_endpoints_discovered(result):
    found = {(e.method, e.path) for e in result.endpoints}
    assert set(EXPECTED).issubset(found)
    assert all(e.language == "javascript" for e in result.endpoints)


def test_js_no_false_negatives(result):
    got = {(f.method, f.path): f.vuln for f in result.findings}
    for ep, expected in EXPECTED.items():
        if expected is not None:
            assert got.get(ep) == expected, f"{ep}: expected {expected}, got {got.get(ep)}"


def test_js_no_false_positives(result):
    flagged = {(f.method, f.path) for f in result.findings}
    for ep, expected in EXPECTED.items():
        if expected is None:
            assert ep not in flagged, f"false positive on safe endpoint {ep}"


def _analyze(source, label="t.js"):
    out = []
    for e in js.discover_in_source(source, label):
        out.extend(js.analyze_endpoint(e))
    return out


def test_template_literal_sql_flagged():
    src = 'app.get("/u/:id", (req, res) => { db.query(`SELECT * FROM u WHERE id=${req.params.id}`); });'
    f = _analyze(src)
    assert len(f) == 1 and f[0].vuln == "SQLI"


def test_parameterized_sql_safe():
    src = 'app.get("/u/:id", (req, res) => { db.query("SELECT * FROM u WHERE id=?", [req.params.id]); });'
    assert _analyze(src) == []


def test_typescript_parses():
    src = 'const r = router.get("/x", (req: Request, res: Response) => { res.send(`<b>${req.query.q}</b>`); });'
    f = _analyze(src, "t.ts")
    assert len(f) == 1 and f[0].vuln == "XSS"
