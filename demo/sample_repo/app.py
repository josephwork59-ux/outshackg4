"""Deliberately vulnerable demo app — DO NOT deploy. Used only as a scan
target so the Vulnerability Scanner Agent has real, findable weaknesses.
"""
import os
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

# --- CWE-798: hardcoded credential (should be caught by secret scan) -------
AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"
DB_PASSWORD = "hunter2-supersecret"


@app.route("/user")
def get_user():
    # --- CWE-89: SQL injection (string-formatted query, no parameterization)
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cur = conn.execute(query)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    # --- CWE-78: OS command injection via shell=True with user input -------
    host = request.args.get("host", "localhost")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output


@app.route("/config", methods=["POST"])
def load_config():
    # --- Unsafe deserialization: yaml.load without a safe loader -----------
    data = request.data
    config = yaml.load(data, Loader=yaml.FullLoader)
    return str(config)


@app.route("/debug")
def debug():
    # --- CWE-489: debug mode / verbose error leakage in production ---------
    if os.environ.get("DEBUG"):
        raise Exception("debug endpoint hit: " + str(request.args))
    return "ok"


if __name__ == "__main__":
    # --- binding to all interfaces with debug on ----------------------------
    app.run(host="0.0.0.0", debug=True)
