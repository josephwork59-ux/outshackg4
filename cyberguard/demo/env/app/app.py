"""Tiny demo Flask app - not run by the scanner, only read."""

from flask import Flask, request, jsonify
import yaml

from settings import DB_DSN

app = Flask(__name__)


@app.get("/api/v1/health")
def health():
    return jsonify(status="ok")


@app.post("/api/v1/config")
def load_config():
    # Intentionally unsafe: full_load on untrusted input (see PyYAML CVE-2020-14343).
    parsed = yaml.full_load(request.data)
    return jsonify(parsed=parsed)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
