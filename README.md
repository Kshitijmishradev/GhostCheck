<div align="center">

<br/>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://img.icons8.com/sf-ultralight/100/FFFFFF/ghost.png">
  <source media="(prefers-color-scheme: light)" srcset="https://img.icons8.com/sf-ultralight/100/000000/ghost.png">
  <img alt="GhostCheck logo" width="80" src="https://img.icons8.com/sf-ultralight/100/000000/ghost.png">
</picture>

# G H O S T C H E C K

### *The request you see. The vulnerability you don't.*

<br/>

[![Go](https://img.shields.io/badge/Go_1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
&nbsp;
[![Python](https://img.shields.io/badge/Python_3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org/)
&nbsp;
[![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-000000?style=for-the-badge&logo=ollama&logoColor=white)](https://ollama.com/)
&nbsp;
[![Tree‑sitter](https://img.shields.io/badge/Tree--sitter-AST-6DB33F?style=for-the-badge)](https://tree-sitter.github.io/)

<br/>

<p align="center">
  <b>Zero-latency reverse proxy</b> &nbsp;·&nbsp; <b>AST-aware code mapping</b> &nbsp;·&nbsp; <b>Local AI audit</b> &nbsp;·&nbsp; <b>No cloud required</b>
</p>

<br/>

</div>

---

<br/>

## The Problem

Traditional WAFs match against static signatures—regex lists, known CVE patterns, OWASP rule sets. They have **no idea what your code actually does**. A request that looks benign might exploit a quirk in your specific `login()` implementation. A request that looks malicious might be perfectly safe because your code already sanitises it.

**GhostCheck flips the model.** It reads the live HTTP request *and* the source code that will handle it, then asks an LLM: *"given this exact function, can this exact payload cause harm?"*

<br/>

---

<br/>

## How It Works

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                      G H O S T C H E C K                   │
                    │                                                             │
  HTTP request      │   ┌────────────────┐    Unix Socket    ┌────────────────┐   │
 ────────────────▶  │   │                │  ─────────────▶  │                │   │
                    │   │  Wraith Proxy   │   JSON stream     │ Specter Agent  │   │
  HTTP response     │   │     (Go)        │                   │   (Python)     │   │
 ◀────────────────  │   │                │                   │                │   │
                    │   └───────┬────────┘                   └───┬────┬───────┘   │
                    │           │                                │    │           │
                    │           ▼                                ▼    ▼           │
                    │     Your Backend                  Tree-sitter  Ollama       │
                    │      (untouched)                   AST parse   LLM audit   │
                    │                                                             │
                    └─────────────────────────────────────────────────────────────┘
```

<br/>

<table>
<tr>
<td width="50%">

### <samp>WRAITH PROXY</samp> &nbsp; <sub>Data Plane · Go</sub>

The **invisible layer**. Wraith is a production-grade reverse proxy that sits in front of your application. Every request passes through unchanged—zero tampering, zero added latency to the response.

Behind the scenes, it **clones each request** (method, path, headers, body, client IP) and streams a structured JSON event over a Unix domain socket to Specter.

If Specter is down, Wraith stays up. Blind mode — logged, not blocked.

</td>
<td width="50%">

### <samp>SPECTER AGENT</samp> &nbsp; <sub>Control Plane · Python</sub>

The **thinking layer**. Specter receives the event stream and runs a multi-stage pipeline:

1. **Heuristic scan** — fast regex-based check for injection indicators (SQLi, command injection, template pollution)
2. **Code mapping** — resolves the route to an on-disk source file and uses **Tree-sitter** to extract the exact handler function
3. **LLM audit** — sends the function body + raw payload to a **local Ollama model** that reasons about whether this specific code is vulnerable to this specific input

</td>
</tr>
</table>

<br/>

---

<br/>

## Architecture Deep Dive

```
wraith-proxy/
├── main.go              Reverse proxy server with production timeouts
├── interceptor.go       Clones request body, builds InterceptEvent, pushes to socket
├── socket_client.go     Singleton Unix socket client with thread-safe writes + auto-reconnect
└── go.mod

specter-agent/
├── main.py              Unix socket server, event loop, dispatch
├── analyzer/
│   ├── mapper.py        Route → source file resolution + Tree-sitter function extraction
│   └── tree_sitter.py   C/C++ parser via tree-sitter-language-pack
└── brain/
    ├── langgraph.py      Multi-stage audit engine (heuristic → mapping → LLM verdict)
    └── llm_client.py     LangChain + Ollama interface

shared/
└── ghostcheck.sock      Unix domain socket (created at runtime)
```

<br/>

---

<br/>

## Quick Start

> **Prerequisites** — [Go 1.22+](https://go.dev/dl/) · [Python 3.12+](https://python.org/) · [Ollama](https://ollama.com/) running locally

<br/>

### 1 &nbsp; Clone & prepare

```bash
git clone https://github.com/your-username/ghostCheck.git
cd ghostCheck
mkdir -p shared
```

### 2 &nbsp; Start the Specter Agent

```bash
cd specter-agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python main.py
# 👻 Specter Agent: Listening on .../shared/ghostcheck.sock...
```

### 3 &nbsp; Start the Wraith Proxy

```bash
cd wraith-proxy
go build -o wraith .

./wraith -target http://localhost:8080 -port 9000
# 🛡️ GhostCheck Production Proxy Started
# Listening on :9000 | Protecting: http://localhost:8080
```

### 4 &nbsp; Send traffic

```bash
# Normal request — passes through
curl http://localhost:9000/api/login \
  -d '{"user":"alice","pass":"secret"}'

# Suspicious request — Specter flags it
curl http://localhost:9000/api/login \
  -d '{"user":"admin\" OR 1=1 --","pass":"x"}'
```

<br/>

---

<br/>

## Configuration

| Variable | Default | Description |
|:---------|:--------|:------------|
| `GHOSTCHECK_SOURCE_ROOT` | `tests/vulnerable_app/` | Root directory containing the source files mapped by route |
| `OLLAMA_MODEL` | `llama3.2` | Which Ollama model to use for the security audit |

### Route Mapping

Routes are mapped to source files in `specter-agent/analyzer/mapper.py`:

```python
PATH_TO_FILE = {
    "/api/login": "login.cpp",
}
```

Add entries as you expand coverage. Specter uses Tree-sitter to extract only the relevant function—the LLM never sees your whole codebase.

<br/>

---

<br/>

## Detection Capabilities

<table>
<tr>
<td>

**Injection Types**
- SQL injection (`UNION SELECT`, `OR 1=1`, comment markers)
- OS command injection (`; cat /etc/passwd`, backtick subshells)
- Template injection (`{{...}}`, `${...}`)

</td>
<td>

**Analysis Depth**
- Regex heuristics for fast pre-filtering
- AST-level function extraction (not string matching)
- Contextual LLM reasoning against actual code logic

</td>
<td>

**Verdict Format**
```json
{
  "action": "BLOCK",
  "risk": "HIGH",
  "reason": "unsafe system() call",
  "evidence": "login.cpp: system(cmd)"
}
```

</td>
</tr>
</table>

<br/>

---

<br/>

## Design Principles

| Principle | How |
|:----------|:----|
| **Zero interference** | The proxy never modifies requests or responses. Your app behaves identically with or without GhostCheck. |
| **Fail-safe** | If the agent or LLM is unavailable, traffic flows normally. No single point of failure. |
| **Local-first** | All inference runs on your machine via Ollama. No API keys, no data leaving your network. |
| **Code-aware** | Decisions are grounded in the actual implementation, not generic vulnerability databases. |
| **Minimal surface** | Tree-sitter extracts only the target function. The LLM sees the smallest context needed. |

<br/>

---

<br/>

## Tech Stack

| Layer | Technology | Purpose |
|:------|:-----------|:--------|
| Proxy | **Go** `net/http/httputil` | High-throughput reverse proxy with production timeouts |
| IPC | **Unix Domain Socket** | Near-zero-latency bridge between Go and Python |
| Parsing | **Tree-sitter** | Language-agnostic AST parsing for C/C++ function extraction |
| Reasoning | **LangChain** + **Ollama** | Local LLM inference with structured prompt engineering |
| Orchestration | **LangGraph-style** state machine | Heuristic → mapping → LLM → verdict pipeline |

<br/>

---

<br/>

<div align="center">

<br/>

```
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║   It's not about blocking everything.                ║
    ║   It's about understanding what your code can't      ║
    ║   handle — before an attacker figures it out.        ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
```

<br/>

**Built with paranoia. Runs with calm.**

<sub>Made by <a href="https://github.com/your-username">kshitijmishra</a></sub>

<br/><br/>

</div>
