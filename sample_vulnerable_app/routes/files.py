"""File + network routes. Contains path traversal + SSRF sinks."""
import os

from flask import Blueprint, request, send_file, jsonify

files_bp = Blueprint("files", __name__)

UPLOAD_DIR = "/var/app/uploads"


@files_bp.route("/download")
def download():
    # VULNERABLE: path traversal. `name` can be ../../etc/passwd.
    name = request.args.get("name", "")
    path = UPLOAD_DIR + "/" + name
    return send_file(path)


@files_bp.route("/read")
def read_file():
    # VULNERABLE: path traversal via open() on user-controlled path.
    fname = request.args["file"]
    with open(os.path.join(UPLOAD_DIR, fname)) as fh:
        return fh.read()


@files_bp.route("/fetch")
def fetch_url():
    # VULNERABLE: SSRF. Server fetches an attacker-supplied URL.
    import urllib.request

    target = request.args.get("url")
    data = urllib.request.urlopen(target).read()
    return data


@files_bp.route("/download_safe")
def download_safe():
    # SAFE control: basename strips traversal, and path is validated.
    name = os.path.basename(request.args.get("name", ""))
    path = os.path.join(UPLOAD_DIR, name)
    if not os.path.abspath(path).startswith(UPLOAD_DIR):
        return jsonify({"error": "bad path"}), 400
    return send_file(path)
