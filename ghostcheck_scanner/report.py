"""Render scan results: terminal, JSON, and standalone HTML."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .scan import ScanResult

# ---- ANSI ----------------------------------------------------------------
_C = {
    "CRITICAL": "\033[41;97m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
    "LOW": "\033[36m", "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "grn": "\033[32m", "vio": "\033[35m",
}


def _use_color(force: bool | None) -> bool:
    import sys
    if force is not None:
        return force
    return sys.stdout.isatty()


def render_terminal(result: ScanResult, color: bool | None = None) -> str:
    c = _C if _use_color(color) else {k: "" for k in _C}
    out: list[str] = []
    out.append(f"\n{c['vio']}{c['bold']}👻 GhostCheck{c['reset']} — endpoint security scan")
    out.append(f"{c['dim']}   target: {result.root}{c['reset']}\n")

    n_ep = len(result.endpoints)
    n_vuln = result.vulnerable_endpoints
    n_safe = n_ep - n_vuln
    counts = result.counts
    summary = "  ".join(
        f"{_C.get(sev,'') if color!=False else ''}{counts.get(sev,0)} {sev}{c['reset']}"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(sev)
    ) or f"{c['grn']}0 issues{c['reset']}"
    langs = ", ".join(f"{v} {k}" for k, v in sorted(result.languages.items())) or "—"
    out.append(f"  Endpoints discovered : {n_ep}  {c['dim']}({langs}){c['reset']}")
    out.append(f"  Vulnerable / clean   : {c['HIGH']}{n_vuln}{c['reset']} / {c['grn']}{n_safe}{c['reset']}")
    out.append(f"  Findings             : {summary}\n")

    if not result.findings:
        out.append(f"  {c['grn']}✓ No injection vulnerabilities found.{c['reset']}\n")
        return "\n".join(out)

    out.append(f"{c['bold']}  FINDINGS{c['reset']}")
    out.append(f"  {c['dim']}{'─'*66}{c['reset']}")
    for i, f in enumerate(result.findings, 1):
        sev_c = _C.get(f.severity, "") if color is not False else ""
        out.append(f"  {sev_c}{c['bold']} {f.severity:<8}{c['reset']} {c['bold']}{f.title}{c['reset']}  {c['dim']}{f.cwe}{c['reset']}")
        handler_part = f"  →  {f.handler}()" if f.handler else ""
        out.append(f"     {c['bold']}{f.method} {f.path}{c['reset']}{handler_part}")
        out.append(f"     {c['dim']}{f.file}:{f.line}{c['reset']}   sink: {f.sink}   param: {c['vio']}{f.param}{c['reset']}")
        out.append(f"     evidence : {f.evidence}")
        out.append(f"     exploit  : {c['HIGH']}{f.poc_payload}{c['reset']}")
        for line in f.poc_request.splitlines():
            out.append(f"                {c['dim']}{line}{c['reset']}")
        out.append(f"     fix      : {f.fix}")
        out.append("")
    return "\n".join(out)


def to_json(result: ScanResult) -> str:
    payload = {
        "tool": "ghostcheck",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": result.root,
        "summary": {
            "endpoints": len(result.endpoints),
            "vulnerable_endpoints": result.vulnerable_endpoints,
            "findings": len(result.findings),
            "by_severity": result.counts,
        },
        "endpoints": [
            {"method": e.method, "path": e.path, "handler": e.handler,
             "file": e.file, "line": e.line}
            for e in result.endpoints
        ],
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2)


def to_html(result: ScanResult) -> str:
    e = html.escape
    counts = result.counts
    sev_badges = "".join(
        f'<span class="pill {s.lower()}">{counts.get(s,0)} {s}</span>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(s)
    ) or '<span class="pill ok">No issues</span>'

    rows = []
    for f in result.findings:
        rows.append(f"""
      <article class="card {f.severity.lower()}">
        <header>
          <span class="sev {f.severity.lower()}">{f.severity}</span>
          <h3>{e(f.title)}</h3><span class="cwe">{e(f.cwe)}</span>
        </header>
        <p class="ep"><b>{e(f.method)} {e(f.path)}</b>{(' &rarr; ' + e(f.handler) + '()') if f.handler else ''}</p>
        <p class="loc">{e(f.file)}:{f.line} · sink <code>{e(f.sink)}</code> · param <code>{e(f.param)}</code></p>
        <pre class="ev">{e(f.evidence)}</pre>
        <p class="lbl">Proof-of-concept exploit</p>
        <pre class="poc">{e(f.poc_request)}</pre>
        <p class="fix"><b>Fix.</b> {e(f.fix)}</p>
      </article>""")

    clean = [ep for ep in result.endpoints
             if (ep.method, ep.path) not in {(f.method, f.path) for f in result.findings}]
    clean_rows = "".join(
        f"<li><code>{e(ep.method)} {e(ep.path)}</code> <span>{(e(ep.handler) + '()') if ep.handler else e(ep.language)}</span></li>"
        for ep in clean
    )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GhostCheck Report</title>
<style>
:root{{--bg:#0a0c13;--panel:#12151f;--line:#222839;--ink:#e8ebf5;--muted:#98a0b8;
--vio:#9a8cff;--crit:#ff6a61;--high:#ff8a5c;--med:#f2b64a;--low:#5cc8ff;--ok:#46d489;
--mono:'IBM Plex Mono',ui-monospace,Menlo,monospace}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.55}}
.wrap{{max-width:900px;margin:0 auto;padding:34px 20px 60px}}
h1{{font-family:var(--mono);letter-spacing:.14em;margin:0 0 4px}}
.sub{{color:var(--muted);margin:0 0 22px;font-size:14px}}
.summary{{display:flex;flex-wrap:wrap;gap:20px;background:var(--panel);border:1px solid var(--line);
border-radius:12px;padding:18px 20px;margin-bottom:26px}}
.summary div span{{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}}
.summary div b{{font-size:22px}}
.pills{{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-left:auto}}
.pill{{font-family:var(--mono);font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid var(--line)}}
.pill.critical{{color:var(--crit)}}.pill.high{{color:var(--high)}}.pill.medium{{color:var(--med)}}
.pill.low{{color:var(--low)}}.pill.ok{{color:var(--ok)}}
.card{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--muted);
border-radius:10px;padding:18px 20px;margin-bottom:16px}}
.card.critical{{border-left-color:var(--crit)}}.card.high{{border-left-color:var(--high)}}
.card.medium{{border-left-color:var(--med)}}.card.low{{border-left-color:var(--low)}}
.card header{{display:flex;align-items:center;gap:12px;margin-bottom:8px}}
.card h3{{margin:0;font-size:17px}}
.sev{{font-family:var(--mono);font-size:11px;font-weight:700;padding:3px 8px;border-radius:6px}}
.sev.critical{{background:#2a1512;color:var(--crit)}}.sev.high{{background:#2a1a12;color:var(--high)}}
.sev.medium{{background:#2a2410;color:var(--med)}}.sev.low{{background:#0e1f2a;color:var(--low)}}
.cwe{{margin-left:auto;color:var(--muted);font-family:var(--mono);font-size:12px}}
.ep{{margin:2px 0}}.loc{{color:var(--muted);font-size:13px;margin:2px 0 10px}}
code{{font-family:var(--mono);font-size:.85em;background:#0e1119;border:1px solid var(--line);border-radius:5px;padding:1px 5px;color:var(--vio)}}
pre{{font-family:var(--mono);font-size:12.5px;overflow-x:auto;background:#0e1119;border:1px solid var(--line);
border-radius:8px;padding:12px 14px;margin:6px 0}}
pre.poc{{color:var(--high)}}.lbl{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:12px 0 0}}
.fix{{font-size:14px;color:var(--ink);background:#101826;border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:10px 0 0}}
.fix b{{color:var(--ok)}}
h2{{font-size:15px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:32px 0 10px}}
ul.clean{{list-style:none;padding:0;margin:0;display:grid;gap:6px}}
ul.clean li{{display:flex;gap:12px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font-size:13px}}
ul.clean li span{{color:var(--muted)}}
footer{{color:var(--muted);font-size:12px;margin-top:36px;font-family:var(--mono)}}
</style></head><body><div class="wrap">
<h1>👻 GHOSTCHECK</h1>
<p class="sub">Endpoint security report · {e(result.root)} · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
<div class="summary">
  <div><span>Endpoints</span><b>{len(result.endpoints)}</b></div>
  <div><span>Languages</span><b style="font-size:15px">{e(', '.join(sorted(result.languages)) or '—')}</b></div>
  <div><span>Vulnerable</span><b style="color:var(--high)">{result.vulnerable_endpoints}</b></div>
  <div><span>Findings</span><b>{len(result.findings)}</b></div>
  <div class="pills">{sev_badges}</div>
</div>
{''.join(rows) if rows else '<p class="pill ok">No injection vulnerabilities found.</p>'}
<h2>Clean endpoints ({len(clean)})</h2>
<ul class="clean">{clean_rows or '<li><span>none</span></li>'}</ul>
<footer>Generated by GhostCheck · static taint analysis + code-guided PoC · findings are indicators, verify before acting</footer>
</div></body></html>"""
