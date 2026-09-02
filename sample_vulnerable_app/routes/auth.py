"""Auth + user lookup routes. Contains SQL injection sinks."""
import sqlite3

from flask import Blueprint, request, jsonify

auth_bp = Blueprint("auth", __name__)


def _db():
    return sqlite3.connect("app.db")


@auth_bp.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    # VULNERABLE: SQL injection. user_id is interpolated straight into SQL.
    conn = _db()
    query = "SELECT id, name, email FROM users WHERE id = " + user_id
    row = conn.execute(query).fetchone()
    return jsonify(row)


@auth_bp.route("/login", methods=["POST"])
def login():
    # VULNERABLE: SQL injection via f-string on request body fields.
    username = request.form["username"]
    password = request.form["password"]
    conn = _db()
    q = f"SELECT * FROM users WHERE name = '{username}' AND pass = '{password}'"
    user = conn.execute(q).fetchone()
    if user:
        return jsonify({"ok": True})
    return jsonify({"ok": False}), 401


@auth_bp.route("/search")
def search_users():
    # VULNERABLE: SQL injection via query-string arg used with %-format.
    term = request.args.get("q", "")
    conn = _db()
    rows = conn.execute(
        "SELECT name FROM users WHERE name LIKE '%%%s%%'" % term
    ).fetchall()
    return jsonify(rows)


@auth_bp.route("/users_safe/<user_id>")
def get_user_safe(user_id):
    # SAFE control: parameterized query. Scanner must NOT flag this.
    conn = _db()
    row = conn.execute(
        "SELECT id, name, email FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return jsonify(row)
