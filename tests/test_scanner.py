"""End-to-end + unit tests for the GhostCheck scanner."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghostcheck_scanner.scan import scan_repo
from ghostcheck_scanner.discover import discover_in_source
from ghostcheck_scanner.detectors.engine import analyze_endpoint

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "sample_vulnerable_app")

# Ground truth for the sample app: endpoint -> expected vuln class (None = safe).
EXPECTED = {
    ("GET", "/users/<user_id>"): "SQLI",
    ("POST", "/login"): "SQLI",
    ("GET", "/search"): "SQLI",
    ("GET", "/download"): "PATH",
    ("GET", "/read"): "PATH",
    ("GET", "/fetch"): "SSRF",
    ("GET", "/ping"): "CMDI",
    ("POST", "/backup"): "CMDI",
    ("GET", "/greet"): "XSS",
    ("GET", "/users_safe/<user_id>"): None,
    ("GET", "/download_safe"): None,
    ("GET", "/ping_safe"): None,
    ("GET", "/health"): None,
}


@pytest.fixture(scope="module")
def result():
    return scan_repo(SAMPLE)


def test_all_endpoints_discovered(result):
    found = {(e.method, e.path) for e in result.endpoints}
    assert set(EXPECTED).issubset(found)


def test_no_false_negatives(result):
    got = {(f.method, f.path): f.vuln for f in result.findings}
    for ep, expected in EXPECTED.items():
        if expected is not None:
            assert ep in got, f"missed vulnerability at {ep}"
            assert got[ep] == expected, f"{ep}: expected {expected}, got {got[ep]}"


def test_no_false_positives(result):
    flagged = {(f.method, f.path) for f in result.findings}
    for ep, expected in EXPECTED.items():
        if expected is None:
            assert ep not in flagged, f"false positive on safe endpoint {ep}"


def test_every_finding_has_a_poc(result):
    for f in result.findings:
        assert f.poc_payload and f.poc_request
        assert f.param and f.fix and f.cwe


def _analyze(source):
    eps = discover_in_source(source, "t.py")
    out = []
    for e in eps:
        out.extend(analyze_endpoint(e))
    return out


def test_parameterized_query_is_safe():
    src = '''
from flask import Flask, request
app = Flask(__name__)
@app.route("/u/<uid>")
def u(uid):
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
'''
    assert _analyze(src) == []


def test_concat_sql_is_flagged():
    src = '''
from flask import Flask, request
app = Flask(__name__)
@app.route("/u/<uid>")
def u(uid):
    q = "SELECT * FROM users WHERE id = " + uid
    return db.execute(q).fetchone()
'''
    findings = _analyze(src)
    assert len(findings) == 1 and findings[0].vuln == "SQLI"


def test_basename_sanitizer_is_safe():
    src = '''
import os
from flask import Flask, request, send_file
app = Flask(__name__)
@app.route("/d")
def d():
    name = os.path.basename(request.args.get("name", ""))
    return send_file("/up/" + name)
'''
    assert _analyze(src) == []
