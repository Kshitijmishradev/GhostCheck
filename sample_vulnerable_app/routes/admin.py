"""Admin/ops routes. Contains command injection + reflected XSS sinks."""
import os
import subprocess

from flask import Blueprint, request

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/ping")
def ping():
    # VULNERABLE: OS command injection. host flows into a shell.
    host = request.args.get("host", "")
    output = os.popen("ping -c 1 " + host).read()
    return output


@admin_bp.route("/backup", methods=["POST"])
def backup():
    # VULNERABLE: command injection via subprocess with shell=True.
    target = request.form.get("dir", ".")
    subprocess.call(f"tar czf backup.tgz {target}", shell=True)
    return {"ok": True}


@admin_bp.route("/greet")
def greet():
    # VULNERABLE: reflected XSS. name echoed into HTML unescaped.
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"


@admin_bp.route("/ping_safe")
def ping_safe():
    # SAFE control: no shell, arg passed as a list element.
    host = request.args.get("host", "")
    if not host.replace(".", "").isalnum():
        return {"error": "bad host"}, 400
    output = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True
    ).stdout
    return output
