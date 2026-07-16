"""Unit tests for the redaction detector library.

Each detector must:
  1. Match at least one canonical positive fixture and replace with its token.
  2. NOT match related-but-innocuous strings (false-positive guardrails).
  3. Be idempotent: redact(redact(x)) == redact(x).

If you add a detector to `spotlight/redaction/detectors.py`, add a
positive and a negative here. Silent-failure paths get us hurt — the
whole point of this module is that a live key never leaks.
"""
from __future__ import annotations

import pytest

from spotlight.redaction import Redactor, redact
from spotlight.redaction.detectors import DEFAULT_DETECTORS


# ---------- POSITIVES (30+) ----------
# Format: (label, input_text, expected_kind, expected_token_substring)
POSITIVES: list[tuple[str, str, str, str]] = [
    # AWS access key ID
    ("aws-key-basic", "id: AKIAIOSFODNN7EXAMPLE end", "aws-key", "[REDACTED:aws-key]"),
    ("aws-key-embedded", "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", "aws-key", "[REDACTED:aws-key]"),
    ("aws-key-with-suffix-text", "use AKIAZZZZZZZZZZZZZZZZ for prod", "aws-key", "[REDACTED:aws-key]"),
    # AWS secret access key (quoted, near aws label)
    (
        "aws-secret-double-quoted",
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        "aws-secret",
        "[REDACTED:aws-secret]",
    ),
    (
        "aws-secret-single-quoted",
        "aws_secret_access_key='abcdefghijklmnopqrstuvwxyz0123456789+/AB'",
        "aws-secret",
        "[REDACTED:aws-secret]",
    ),
    # GCP private key
    (
        "gcp-private-key",
        "key: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\nhkiG9w0B\n-----END PRIVATE KEY-----\nrest",
        "gcp-private-key",
        "[REDACTED:gcp-private-key]",
    ),
    # RSA / OpenSSH / EC / DSA private key
    (
        "rsa-private-key",
        "prefix\n-----BEGIN RSA PRIVATE KEY-----\nabc\ndef\n-----END RSA PRIVATE KEY-----\nsuffix",
        "rsa-private-key",
        "[REDACTED:private-key]",
    ),
    (
        "openssh-private-key",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----",
        "rsa-private-key",
        "[REDACTED:private-key]",
    ),
    (
        "ec-private-key",
        "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA==\n-----END EC PRIVATE KEY-----",
        "rsa-private-key",
        "[REDACTED:private-key]",
    ),
    (
        "bare-private-key",
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
        "gcp-private-key",  # bare "BEGIN PRIVATE KEY" matches gcp variant first
        "[REDACTED:gcp-private-key]",
    ),
    # JWT
    (
        "jwt-3-part",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abcdef-123_456",
        "jwt",
        "[REDACTED:jwt]",
    ),
    (
        "jwt-longer",
        "token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoibHVjaWxsZSJ9.PzZq_signature-part",
        "jwt",
        "[REDACTED:jwt]",
    ),
    # OpenAI keys
    (
        "openai-sk-classic",
        "OPENAI_API_KEY=sk-abcdefghij0123456789ABCDEFG",
        "openai-key",
        "[REDACTED:openai-key]",
    ),
    (
        "openai-sk-proj",
        "sk-proj0123456789abcdefghijklmnop",
        "openai-key",
        "[REDACTED:openai-key]",
    ),
    # Anthropic keys (must precede plain sk-)
    (
        "anthropic-key",
        "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx",
        "anthropic-key",
        "[REDACTED:anthropic-key]",
    ),
    (
        "anthropic-key-with-dashes",
        "sk-ant-abcdefghijklmnop_qrstuv-XYZ",
        "anthropic-key",
        "[REDACTED:anthropic-key]",
    ),
    # GitHub PAT
    (
        "github-pat-classic",
        "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "github-pat",
        "[REDACTED:github-pat]",
    ),
    (
        "github-pat-oauth",
        "gho_abcdefghijklmnopqrstuvwxyz012345",
        "github-pat",
        "[REDACTED:github-pat]",
    ),
    (
        "github-pat-user-server",
        "ghu_abcdefghijklmnopqrstuvwxyz012345",
        "github-pat",
        "[REDACTED:github-pat]",
    ),
    (
        "github-pat-refresh",
        "ghr_abcdefghijklmnopqrstuvwxyz012345",
        "github-pat",
        "[REDACTED:github-pat]",
    ),
    (
        "github-pat-fine-grained",
        "ghs_abcdefghijklmnopqrstuvwxyz012345",
        "github-pat",
        "[REDACTED:github-pat]",
    ),
    # Slack tokens
    (
        "slack-bot",
        "SLACK_BOT_TOKEN=xoxb-1234567890-1234567890-abcdefghijklmnop",
        "slack-token",
        "[REDACTED:slack-token]",
    ),
    (
        "slack-app",
        "xoxa-1234567890-abcdef",
        "slack-token",
        "[REDACTED:slack-token]",
    ),
    (
        "slack-personal",
        "xoxp-1234567890-abcdefghij",
        "slack-token",
        "[REDACTED:slack-token]",
    ),
    (
        "slack-refresh",
        "xoxr-1234567890-abcdefghij",
        "slack-token",
        "[REDACTED:slack-token]",
    ),
    (
        "slack-session",
        "xoxs-1234567890-abcdefghij",
        "slack-token",
        "[REDACTED:slack-token]",
    ),
    # DB URLs
    (
        "postgres-url",
        "DATABASE_URL=postgres://user:pw@db.example.com:5432/prod",
        "db-url",
        "[REDACTED:db-url]",
    ),
    (
        "postgresql-url",
        "postgresql://alice:s3cret@10.0.0.5:5432/warehouse",
        "db-url",
        "[REDACTED:db-url]",
    ),
    (
        "mysql-url",
        "mysql://root:root@localhost:3306/app",
        "db-url",
        "[REDACTED:db-url]",
    ),
    (
        "mongodb-url",
        "mongodb://admin:letmein@cluster0.example.net/db",
        "db-url",
        "[REDACTED:db-url]",
    ),
    (
        "mongodb-srv-url",
        "mongodb+srv://admin:letmein@cluster0.mongodb.net/db",
        "db-url",
        "[REDACTED:db-url]",
    ),
    # Generic kv secrets
    (
        "generic-api-key-eq",
        'api_key = "abcdefghijklmnopqrstuvwx"',
        "generic-secret",
        "[REDACTED:generic-secret]",
    ),
    (
        "generic-password-colon",
        'password: "super_secret_password_123"',
        "generic-secret",
        "[REDACTED:generic-secret]",
    ),
    (
        "generic-token-single",
        "token='abcdefghijklmnop0123456789'",
        "generic-secret",
        "[REDACTED:generic-secret]",
    ),
    (
        "generic-secret-kv",
        'SECRET = "opensesame1234567890abcdef"',
        "generic-secret",
        "[REDACTED:generic-secret]",
    ),
]


@pytest.mark.parametrize("label,text,kind,token_sub", POSITIVES)
def test_positive_fixture_gets_redacted(label, text, kind, token_sub):
    redacted, matches = redact(text)
    assert token_sub in redacted, f"{label}: expected {token_sub} in {redacted!r}"
    assert any(m.kind == kind for m in matches), (
        f"{label}: expected a match of kind {kind}, got {[m.kind for m in matches]}"
    )


# ---------- NEGATIVES (20+) ----------
NEGATIVES: list[tuple[str, str]] = [
    ("snake-var-sk_lower", "def sk_lower_snake_var(): return 42"),
    ("aws-region-not-secret", "AWS_REGION = 'us-east-1'"),
    ("aws-region-in-text", "The AWS region is us-west-2"),
    ("cert-not-key", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
    ("pubkey-not-privkey", "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"),
    ("aws-word-no-quotes", "let awsSecret = getSecret()"),
    ("short-akia", "AKIA123"),  # too short — 4 char suffix, not 16
    ("almost-akia-lowercase", "akiaiosfodnn7example"),  # lowercase — not a real ID
    ("jwt-lookalike-two-parts", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0"),  # only 2 parts
    ("plain-sha1", "commit 3fa85f6457174562b3fc2c963f66afa6"),
    ("plain-uuid", "550e8400-e29b-41d4-a716-446655440000"),
    ("db-url-no-creds", "postgres://localhost:5432/dev"),
    ("http-url-no-creds", "https://example.com/path?q=1"),
    ("empty-string", ""),
    ("just-quotes", '"hello"'),
    ("kv-short-value", 'password = "short"'),  # < 16 chars
    ("kv-no-quotes", "api_key = ABC123DEFG456HIJK789"),  # not quoted
    ("openai-word-mention", "we use openai for embeddings"),
    ("github-word-mention", "check github.com/owner/repo"),
    ("slack-word-mention", "join our slack channel"),
    ("license-block", "-----BEGIN CC-BY-4.0 LICENSE-----\n...\n-----END LICENSE-----"),
    ("short-ghp", "ghp_short"),
]


@pytest.mark.parametrize("label,text", NEGATIVES)
def test_negative_fixture_not_redacted(label, text):
    redacted, matches = redact(text)
    assert redacted == text, f"{label}: unexpectedly changed {text!r} -> {redacted!r}"
    assert matches == [], f"{label}: unexpected matches {matches}"


# ---------- STRUCTURAL PROPERTIES ----------


def test_idempotent():
    text = (
        "AKIAIOSFODNN7EXAMPLE and sk-abc123def456ghi789jklmn and "
        'password="hunter2hunter2hunter2"'
    )
    once, _ = redact(text)
    twice, _ = redact(once)
    assert once == twice


def test_all_detectors_have_unique_kinds():
    kinds = [d.kind for d in DEFAULT_DETECTORS]
    assert len(kinds) == len(set(kinds)), f"duplicate detector kinds: {kinds}"


def test_default_detector_coverage():
    """We ship at least the shapes required by Tranche A6."""
    required = {
        "aws-key",
        "aws-secret",
        "gcp-private-key",
        "rsa-private-key",
        "jwt",
        "openai-key",
        "anthropic-key",
        "github-pat",
        "slack-token",
        "db-url",
        "generic-secret",
    }
    got = {d.kind for d in DEFAULT_DETECTORS}
    missing = required - got
    assert not missing, f"missing detectors: {missing}"


def test_redact_dict_walks_recursively():
    r = Redactor()
    obj = {
        "outer": {
            "aws": "AKIAIOSFODNN7EXAMPLE",
            "list": ["ghp_abcdefghijklmnopqrstuvwxyz0123456789", "clean"],
        },
        "int": 42,
        "none": None,
    }
    out = r.redact_dict(obj)
    assert out["outer"]["aws"] == "[REDACTED:aws-key]"
    assert out["outer"]["list"][0] == "[REDACTED:github-pat]"
    assert out["outer"]["list"][1] == "clean"
    assert out["int"] == 42
    assert out["none"] is None


def test_redact_dict_preserves_keys():
    """Keys look like `aws_secret_access_key` — those aren't secrets, they're
    labels. Only values get scrubbed."""
    r = Redactor()
    obj = {"aws_secret_access_key": "hello", "password": "short"}
    out = r.redact_dict(obj)
    assert set(out.keys()) == {"aws_secret_access_key", "password"}


def test_wrap_dict_field_targets_nested_path():
    r = Redactor()
    obj = {"evidence": {"snippet": "leak=AKIAIOSFODNN7EXAMPLE"}, "other": "AKIAIOSFODNN7EXAMPLE"}
    r.wrap_dict_field(obj, ["evidence", "snippet"])
    assert "[REDACTED:aws-key]" in obj["evidence"]["snippet"]
    # Only the targeted path was touched.
    assert obj["other"] == "AKIAIOSFODNN7EXAMPLE"


def test_wrap_dict_field_missing_path_is_noop():
    r = Redactor()
    obj = {"x": "y"}
    out = r.wrap_dict_field(obj, ["nope", "nada"])
    assert out == {"x": "y"}


def test_contains_secret():
    r = Redactor()
    assert r.contains_secret("random text with AKIAIOSFODNN7EXAMPLE")
    assert not r.contains_secret("just a normal sentence")


def test_multiple_shapes_in_one_string():
    text = (
        "AKIAIOSFODNN7EXAMPLE ghp_abcdefghijklmnopqrstuvwxyz0123456789 "
        "and sk-ant-abcdefghijklmnopqrstuvwx"
    )
    _, matches = redact(text)
    kinds = {m.kind for m in matches}
    assert kinds == {"aws-key", "github-pat", "anthropic-key"}


def test_non_string_input_returns_unchanged():
    assert redact(None) == (None, []) or redact("") == ("", [])
    # dict input goes through redact_dict, not redact()
    r = Redactor()
    assert r.redact_dict(123) == 123
    assert r.redact_dict(None) is None


def test_custom_detector_can_be_added():
    from spotlight.redaction.detectors import Detector
    import re as _re

    r = Redactor()
    r.add(
        Detector(
            kind="my-secret",
            pattern=_re.compile(r"MY-CANARY-[0-9]+"),
            token="[REDACTED:my-secret]",
        )
    )
    out, matches = r.redact("prefix MY-CANARY-12345 suffix")
    assert "[REDACTED:my-secret]" in out
    assert matches[0].kind == "my-secret"
