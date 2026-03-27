<div align="center">

# GhostCheck

**Invisible proxy · visible risk**

A reverse proxy that watches traffic in real time and hands it to an offline AI agent—so you can audit sensitive routes (like login) against the *actual* code on disk, not just pattern lists.

<br/>

```
     · · ·  traffic in  · · ·
           │
           ▼
    ┌──────────────┐     unix socket      ┌─────────────────┐
    │ Wraith Proxy │ ──────────────────▶ │  Specter Agent  │
    │    (Go)      │   JSON events        │    (Python)     │
    └──────────────┘                      └────────┬──────────┘
           │                                      │
           ▼                                      ▼
    your backend app                    Tree-sitter + Ollama
```

<br/>

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Ollama](https://img.shields.io/badge/Ollama-local_LLM-111111?style=flat)](https://ollama.com/)

</div>

---

## What it does

| Piece | Role |
|--------|------|
| **Wraith** | Sits in front of your app. Forwards requests unchanged, but clones the body and emits a structured event (method, path, headers, body, client IP) over a Unix socket. |
| **Specter** | Listens on that socket, maps routes like `/api/login` to C++ sources, pulls the relevant function with **Tree-sitter**, and asks a **local LLM** (via LangChain + Ollama) whether the payload could bypass or inject past what the code actually does. |

If the agent is not running, the proxy keeps working—it logs *blind mode* and still protects your upstream.

---

## Why it exists

Signature-only scanners miss context. GhostCheck ties **raw HTTP** to **parsed source** so the model reasons about *this* `login()` implementation—not a generic CWE bullet list.

---

## Prerequisites

- **Go** 1.22+
- **Python** 3.10+ with `pip`
- **Ollama** running locally (default model: `llama3.2`, override with `OLLAMA_MODEL`)

---

## Quick start

**1. Create the shared socket directory** (from the repo root):

```bash
mkdir -p shared
```

**2. Install the Python agent**

```bash
cd specter-agent
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**3. Start Ollama** (if it is not already running), then start Specter:

```bash
python main.py
```

**4. Build and run Wraith** (in another terminal):

```bash
cd wraith-proxy
go build -o wraith .
./wraith -target http://localhost:8080 -port 9000
```

Point clients at `http://localhost:9000` instead of the app directly. The proxy forwards to `-target` and streams events to `shared/ghostcheck.sock`.

---

## Configuration

| Variable | Purpose |
|----------|---------|
| `GHOSTCHECK_SOURCE_ROOT` | Directory containing mapped sources (e.g. `login.cpp`). Defaults to `tests/vulnerable_app` under the repo root when unset. |
| `OLLAMA_MODEL` | Ollama model name (default `llama3.2`). |

Route → file mappings live in `specter-agent/analyzer/mapper.py` (`PATH_TO_FILE`). Extend that table as you add routes.

---

## Project layout

```
ghostCheck/
├── wraith-proxy/     # Go reverse proxy + Unix socket client
├── specter-agent/    # Socket server, Tree-sitter, LangGraph / LLM brain
└── shared/           # ghostcheck.sock (created at runtime)
```

---

## License

Add your license here when you choose one.

---

<div align="center">

<sub>Named for what you cannot see in the wire—and what you still need to catch.</sub>

</div>
