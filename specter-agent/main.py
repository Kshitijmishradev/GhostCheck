import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

import json
import os
import socket

from analyzer.mapper import load_function_for_route, normalize_http_path
from brain.llm_client import analyze_login_injection

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.normpath(os.path.join(_AGENT_DIR, ".."))
SOCKET_PATH = os.path.join(_PROJECT_ROOT, "shared", "ghostcheck.sock")


def start_agent():
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(5)

    print(f"👻 Specter Agent: Listening on {SOCKET_PATH}...")

    try:
        while True:
            conn, _ = server.accept()
            print("🔗 Wraith Proxy connected.")

            with conn:
                buffer = ""
                while True:
                    data = conn.recv(4096).decode("utf-8")
                    if not data:
                        break

                    buffer += data
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        if line.strip():
                            process_event(line)
    except KeyboardInterrupt:
        print("\nStopping Specter Agent...")
    finally:
        if os.path.exists(SOCKET_PATH):
            os.remove(SOCKET_PATH)


def process_event(raw_json: str) -> None:
    try:
        event = json.loads(raw_json)
        path = event.get("path", "")
        body = event.get("body", "") or ""
        preview = body[:80] + ("…" if len(body) > 80 else "")
        print(f"👀 Captured: {event.get('method')} {path} | Body: {preview!r}")
    except Exception as e:
        print(f"❌ Error parsing event: {e}")
        return

    if normalize_http_path(path) != "/api/login":
        return

    loaded = load_function_for_route(path, "login")
    if not loaded:
        print("⚠️ No mapped source for /api/login (set GHOSTCHECK_SOURCE_ROOT or add tests/vulnerable_app/login.cpp).")
        return

    file_label, fn_src = loaded
    try:
        verdict = analyze_login_injection(fn_src, body)
    except Exception as e:
        print(f"❌ LLM audit failed (is Ollama running?): {e}")
        return

    print(f"🔐 Audit [{file_label}] login()\n{verdict}\n")


if __name__ == "__main__":
    start_agent()
