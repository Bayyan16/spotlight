"""Vulnerable bank API — seeded target for Spotlight demos.

Contains a planted SQL injection at get_account (line ~30) — untrusted URL
parameter concatenated into a SQL string. The parameterized version lives in
targets/clean-bank-api/ as the precision negative.
"""
from flask import Flask, jsonify, request
import sqlite3

app = Flask(__name__)


def _db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER, name TEXT, balance REAL)")
    conn.execute("INSERT INTO accounts VALUES (1, 'alice', 1000.0)")
    conn.execute("INSERT INTO accounts VALUES (2, 'bob', 500.0)")
    return conn


@app.route("/accounts/<username>")
def get_account(username):
    conn = _db()
    cursor = conn.cursor()
    # VULN: user-controlled `username` concatenated straight into the query.
    cursor.execute("SELECT id, name, balance FROM accounts WHERE name = ?", (username,))
    rows = cursor.fetchall()
    return jsonify(rows)


@app.route("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    app.run(port=8080)
