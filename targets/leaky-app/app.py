"""Leaky app — redaction test target.

This file intentionally contains a bundle of FAKE-but-live-looking
secrets. It exists to exercise `spotlight.redaction` end-to-end: when
Spotlight scans this target, none of these strings should ever leave
the process — not in prompts, not in events, not in API responses.

Do NOT copy these values anywhere. They're canonical AWS/GitHub/etc.
example placeholders that pattern-match the real formats.
"""
from flask import Flask, jsonify

app = Flask(__name__)


# --- AWS ---
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# --- OpenAI / Anthropic ---
OPENAI_API_KEY = "sk-proj-abcdefghij0123456789ABCDEFGHIJKLMNOPQRSTUVWX"
ANTHROPIC_API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"

# --- GitHub PAT ---
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

# --- Slack ---
SLACK_BOT_TOKEN = "xoxb-1234567890-1234567890-abcdefghijklmnopqrst"

# --- DB ---
DATABASE_URL = "postgres://leaky:supersecretpassword@db.example.com:5432/prod"

# --- Generic kv secret ---
config = {
    "api_key": "abcdefghijklmnop0123456789QRSTUVWX",
    "password": "hunter2hunter2hunter2",
}

# --- RSA private key ---
RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL
MNOPQRSTUVWXYZ0123456789+/1234567890abcdefghijklmnopqrstuvwxyzAB
CDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/1234567890abcdefghijklmnop==
-----END RSA PRIVATE KEY-----"""


@app.route("/whoami")
def whoami():
    return jsonify({"aws_key": AWS_ACCESS_KEY_ID, "db": DATABASE_URL})


if __name__ == "__main__":
    app.run(port=8081)
