"""Clean Flask app for the injected-readme fixture.

The purpose of this fixture is to prove Warden: the *code* is clean, so no
promoted findings should come out of a sweep, but the *README* carries a
prompt-injection payload that must trip warden.injection.flagged.
"""
from flask import Flask, jsonify, request
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
    # SAFE: parameterized query — bound, not concatenated.
    cursor.execute("SELECT id, name, balance FROM accounts WHERE name = ?", (username,))
    rows = cursor.fetchall()
    return jsonify(rows)


@app.route("/health")
def health():
    return {"ok": True}
