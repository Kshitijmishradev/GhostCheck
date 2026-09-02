# GhostCheck Scanner

Code-aware endpoint security scanner. It discovers every HTTP endpoint in an
app, uses tree-sitter to read each handler, runs a lightweight **taint
analysis** to see whether request input reaches a dangerous sink, and generates
a **proof-of-concept exploit** for every vulnerability it finds.

**Languages:** Python (Flask / FastAPI-style decorators) and
JavaScript / TypeScript (Express). One engine, per-language front-ends.

> This is the "hybrid, code-guided" core: the analyzer finds *where* the risk
> is from the source, then crafts the payload that would prove it. A future
> dynamic mode can fire that payload at a running instance to confirm.

## Install

```bash
pip install -e .          # gives you the `ghostcheck` command
# or, without installing:
pip install -r requirements-scanner.txt
python -m ghostcheck_scanner scan ...
```

## Use

```bash
# Scan a repo, print findings, write reports
ghostcheck scan ./sample_vulnerable_app  --html report.html --json findings.json
ghostcheck scan ./sample_vulnerable_express            # JavaScript / Express

# Options
#   --fail-on {CRITICAL,HIGH,MEDIUM,LOW,NONE}   exit non-zero for CI gating (default HIGH)
#   --no-color                                   plain output
```

Exit code is non-zero when a finding at/above `--fail-on` exists, so it drops
straight into CI as a security gate (see `.github/workflows/ci.yml`).

## What it detects

| Class | CWE | How it's judged |
|-------|-----|-----------------|
| SQL injection | CWE-89 | tainted input reaches `.execute()` / `.query()` via concat, f-string, template literal, `%` or `.format()` — parameterised queries are treated as safe |
| OS command injection | CWE-78 | tainted input reaches `os.system` / `popen` / `subprocess(shell=True)` / `child_process.exec` |
| Path traversal | CWE-22 | tainted input reaches `open` / `send_file` / `fs.readFile` / `res.sendFile` without `basename`/path validation |
| SSRF | CWE-918 | tainted input reaches `urlopen` / `requests` / `axios` / `fetch` |
| Reflected XSS | CWE-79 | tainted input returned inside an HTML string that isn't escaped |

**Sanitisers understood** — Python: parameterised queries, `os.path.basename`,
`secure_filename`, `int()`/`float()`, `shlex.quote`, `escape`, `.isalnum()` /
`.isdigit()` / `abspath().startswith()` guards. JavaScript: parameterised
queries, `path.basename` / `path.normalize`, `parseInt` / `Number`,
`encodeURIComponent` / `escape`, `execFile` with an args array, regex validation.

## Layout

```
ghostcheck_scanner/
  parsing.py          multi-language tree-sitter helpers
  discover.py         Python route discovery -> endpoints
  taint.py            Python taint engine (source -> sink, sanitiser-aware)
  detectors/engine.py Python sink specifications
  javascript.py       JS/TS (Express) discovery + taint + sinks
  poc.py              proof-of-concept payload + curl generator
  findings.py         data model + CWE / fix metadata
  report.py           terminal / JSON / HTML output
  scan.py             routes each file to the right language analyzer
  __main__.py         CLI (`ghostcheck` entry point)
```

## Tests

```bash
python -m pytest -q     # 13 tests: full confusion matrix for both languages
```

The suite scans `sample_vulnerable_app/` (Python) and
`sample_vulnerable_express/` (JS) and asserts every vulnerable endpoint is
caught and every safe control is left alone — zero false positives, zero false
negatives on both samples.

## Roadmap

- **Dynamic mode**: fire the generated PoC at a running target and confirm it.
- **More languages**: Go, Java (the tree-sitter language pack already ships them).
- **Optional LLM pass** (Ollama local, or bring-your-own-key) to reason about
  logic flaws the heuristics can't see and to reduce false positives.
- **Auth / access-control checks** (missing `@login_required`, IDOR).
