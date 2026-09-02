"""
Deliberately vulnerable Flask app — GhostCheck test target.

DO NOT DEPLOY. This app exists only so GhostCheck's scanner has real
endpoints to analyze: a mix of injectable handlers and safe controls.
"""
from flask import Flask

from routes.auth import auth_bp
from routes.files import files_bp
from routes.admin import admin_bp

app = Flask(__name__)
app.register_blueprint(auth_bp)
app.register_blueprint(files_bp)
app.register_blueprint(admin_bp)


@app.route("/health")
def health():
    # Safe: no user input touches anything dangerous.
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(port=8080, debug=True)
