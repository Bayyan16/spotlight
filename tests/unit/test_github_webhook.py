"""C7 · GitHub push/PR webhook.

The webhook must:
  * reject requests without a valid HMAC-SHA256 signature
  * treat `ping` as a no-op success (GitHub's health-check event)
  * fire a sweep on `push` / `pull_request` events with a valid signature
  * refuse payloads missing repository.clone_url
  * refuse ALL requests when GITHUB_WEBHOOK_SECRET isn't set (safe default)

Tests use a synthetic HMAC payload — no real GitHub round-trip needed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

import pytest
from fastapi.testclient import TestClient


_TEST_SECRET = "test-secret-please-rotate"


def _sig(body: bytes, secret: str = _TEST_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", _TEST_SECRET)
    from spotlight.api.app import app

    return TestClient(app)


@pytest.fixture
def push_body() -> bytes:
    return json.dumps(
        {
            "ref": "refs/heads/main",
            "after": "deadbeef",
            "repository": {
                "clone_url": "https://github.com/acme/api.git",
                "full_name": "acme/api",
            },
        }
    ).encode("utf-8")


def test_ping_event_returns_pong(client):
    body = b"{}"
    r = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-Hub-Signature-256": _sig(body),
            "X-GitHub-Event": "ping",
        },
    )
    assert r.status_code == 200
    assert r.json() == {"pong": True, "spotlight": "hello, github"}


def test_missing_signature_rejected(client, push_body):
    r = client.post(
        "/webhooks/github",
        content=push_body,
        headers={"X-GitHub-Event": "push"},
    )
    assert r.status_code == 401


def test_wrong_signature_rejected(client, push_body):
    bad = "sha256=" + "0" * 64
    r = client.post(
        "/webhooks/github",
        content=push_body,
        headers={"X-Hub-Signature-256": bad, "X-GitHub-Event": "push"},
    )
    assert r.status_code == 401


def test_missing_secret_rejects_all(monkeypatch, push_body):
    """Safe default: no env var → 401 even with a signature we compute against
    a placeholder secret. Never leave the endpoint open."""
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    from spotlight.api.app import app

    client = TestClient(app)
    r = client.post(
        "/webhooks/github",
        content=push_body,
        headers={
            "X-Hub-Signature-256": _sig(push_body, secret="anything"),
            "X-GitHub-Event": "push",
        },
    )
    assert r.status_code == 401


def test_missing_clone_url_400(client):
    body = json.dumps({"repository": {}}).encode("utf-8")
    r = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-Hub-Signature-256": _sig(body),
            "X-GitHub-Event": "push",
        },
    )
    assert r.status_code == 400


def test_unhandled_event_skipped(client):
    body = b"{}"
    r = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-Hub-Signature-256": _sig(body),
            "X-GitHub-Event": "watch",
        },
    )
    assert r.status_code == 200
    assert r.json() == {"skipped": True, "event": "watch"}


def test_pull_request_captures_pr_number(client, monkeypatch):
    """PR events should stash the pr_number so a follow-up can post a
    comment. We patch _resolve_repo so this test doesn't actually clone."""
    from spotlight.api import app as app_mod

    class _Fake:
        def resolve(self, url):
            return (app_mod.Path("/tmp"), "git-url")

    monkeypatch.setattr(
        app_mod, "start_sweep", lambda req, request: {"sweep_id": "sw_TEST"}
    )
    body = json.dumps(
        {
            "action": "opened",
            "pull_request": {"number": 42},
            "repository": {
                "clone_url": "https://github.com/acme/api.git",
                "full_name": "acme/api",
            },
        }
    ).encode("utf-8")
    r = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-Hub-Signature-256": _sig(body),
            "X-GitHub-Event": "pull_request",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["started"] is True
    assert body["pr_number"] == 42
    assert body["sweep_id"] == "sw_TEST"
    # The tracker should record the PR association.
    assert app_mod._pr_watch_by_sweep.get("sw_TEST", {}).get("pr_number") == 42
