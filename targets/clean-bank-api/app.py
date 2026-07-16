"""Clean bank API — the precision negative.

Same shape as vuln-bank-api but uses a parameterized query. Spotlight must NOT
promote a SQLi finding here. This is what stops the "yes machine" failure mode
called out in PRD §12.
"""
from flask import Flask, jsonify
from flask import request
import sqlite3

app = Flask(__name__)


def _db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER, name TEXT, balance REAL)")
    conn.execute("INSERT INTO accounts VALUES (1, 'alice', 1000.0)")
    return conn


@app.route("/accounts/<username>")
def get_account(username):
    conn = _db()
    cursor = conn.cursor()
    # SAFE: parameterized. `username` is a bound parameter, not interpolated.
    cursor.execute("SELECT id, name, balance FROM accounts WHERE name = ?", (username,))
    rows = cursor.fetchall()
    return jsonify(rows)


@app.route("/health")
def health():
    return {"ok": True}
