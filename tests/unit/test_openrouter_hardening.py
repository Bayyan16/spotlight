from unittest.mock import patch

import pytest

from spotlight.agents.moonshot import (
    MoonshotModelClient,
    _parse_json_safely,
    maybe_from_env,
)


def _recon_context():
    return {
        "signals": [],
        "has_ai_layer": False,
        "wrapped_docs": [],
    }


def test_parser_accepts_strict_json_object():
    out = _parse_json_safely(
        '{"stack":{"language":"python"}}',
        "recon",
        _recon_context(),
        fail_closed=True,
    )

    assert out == {
        "stack": {
            "language": "python",
        }
    }


def test_parser_accepts_json_with_trailing_prose_and_marks_warning():
    out = _parse_json_safely(
        '{"stack":{"language":"python"}} Classification note: test only.',
        "recon",
        _recon_context(),
        fail_closed=True,
    )

    assert out["stack"]["language"] == "python"
    assert out["_parse_warning"] == "trailing_text_ignored"
    assert "_parse_error" not in out
    assert "_fallback" not in out


def test_parser_invalid_json_fails_closed():
    with pytest.raises(ValueError, match="invalid JSON"):
        _parse_json_safely(
            "this is not json",
            "recon",
            _recon_context(),
            fail_closed=True,
        )


def test_reasoning_effort_is_sent_to_provider():
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": "{}",
                        }
                    }
                ]
            }

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return FakeResponse()

    client = MoonshotModelClient(
        api_key="test-key",
        base_url="https://openrouter.ai/api/v1",
        model="stealth/ox-alpha",
        timeout_s=120.0,
        fail_closed=True,
        reasoning_effort="max",
    )

    with patch(
        "spotlight.agents.moonshot.httpx.post",
        side_effect=fake_post,
    ):
        out = client.complete(
            role="recon",
            prompt="test",
            context=_recon_context(),
        )

    assert out == {}
    assert captured["timeout"] == 120.0
    assert captured["json"]["model"] == "stealth/ox-alpha"
    assert captured["json"]["reasoning"] == {
        "effort": "max",
        "exclude": True,
    }


def test_http_failure_fails_closed_instead_of_mock_fallback():
    client = MoonshotModelClient(
        api_key="test-key",
        base_url="https://openrouter.ai/api/v1",
        model="stealth/ox-alpha",
        fail_closed=True,
    )

    with patch(
        "spotlight.agents.moonshot.httpx.post",
        side_effect=RuntimeError("provider unavailable"),
    ):
        with pytest.raises(RuntimeError, match="Live model call failed"):
            client.complete(
                role="recon",
                prompt="test",
                context=_recon_context(),
            )


def test_provider_neutral_env_controls(monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_LLM_API_KEY", "test-key")
    monkeypatch.setenv(
        "SPOTLIGHT_LLM_BASE_URL",
        "https://openrouter.ai/api/v1",
    )
    monkeypatch.setenv(
        "SPOTLIGHT_LLM_MODEL",
        "stealth/ox-alpha",
    )
    monkeypatch.setenv(
        "SPOTLIGHT_LLM_TIMEOUT_S",
        "120",
    )
    monkeypatch.setenv(
        "SPOTLIGHT_LLM_FAIL_CLOSED",
        "1",
    )
    monkeypatch.setenv(
        "SPOTLIGHT_LLM_REASONING_EFFORT",
        "max",
    )

    client = maybe_from_env()

    assert client is not None
    assert client.model == "stealth/ox-alpha"
    assert client.base_url == "https://openrouter.ai/api/v1"
    assert client.timeout_s == 120.0
    assert client.fail_closed is True
    assert client.reasoning_effort == "max"


def _valid_investigator_json():
    import json

    return json.dumps({
        "verdict": "candidate",
        "class": "sqli",
        "cwe": "CWE-89",
        "title": "SQL injection",
        "severity": "high",
        "location": {
            "file": "app.py",
            "line": 27,
            "function": "query_user",
        },
        "root_cause": "Untrusted input reaches a raw SQL execution sink.",
        "recommendation": "Use parameterized queries.",
        "evidence_used": [
            "source-to-sink path reaches execute()",
        ],
    })


def test_deterministic_local_repair_uses_no_second_http_call_and_marks_output():
    import hashlib

    malformed = (
        '{"verdict":"candidate",'
        '"class":"sqli",'
        '"cwe":"CWE-89",'
        '"title":"SQL injection",'
        '"severity":"high",'
        '"location":{"file":"app.py","line":27,"function":"query_user"},'
        '"root_cause":"Untrusted input reaches a raw SQL execution sink.",'
        '"recommendation":"Reject payload "' + "' OR 1=1--" + '" and use parameterized queries.",'
        '"evidence_used":["source-to-sink path reaches execute()"]}'
    )

    calls = []

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": malformed,
                        }
                    }
                ]
            }

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append({
            "url": url,
            "json": json,
            "timeout": timeout,
        })
        return FakeResponse()

    client = MoonshotModelClient(
        api_key="test-key",
        base_url="https://openrouter.ai/api/v1",
        model="stealth/ox-alpha",
        timeout_s=120.0,
        fail_closed=True,
        reasoning_effort="max",
        repair_invalid_json=True,
    )

    with patch(
        "spotlight.agents.moonshot.httpx.post",
        side_effect=fake_post,
    ):
        out = client.complete(
            role="investigator",
            prompt="test",
            context={"slice": {}},
        )

    # Critical invariant: original model request only.
    # Deterministic repair MUST NOT make a second network/model request.
    assert len(calls) == 1

    assert out["verdict"] == "candidate"
    assert out["class"] == "sqli"
    assert out["cwe"] == "CWE-89"

    assert out["_parse_repaired"] is True
    assert out["_parse_repair_method"] == "deterministic-local"
    assert out["_parse_repair_attempts"] == 1

    assert out["_parse_repair_source_sha256"] == hashlib.sha256(
        malformed.encode("utf-8")
    ).hexdigest()

    assert len(out["_parse_repair_output_sha256"]) == 64

    # Semantic content that triggered the malformed JSON must survive repair.
    assert "OR 1=1--" in out["recommendation"]


def test_deterministic_local_repair_failure_stays_fail_closed_without_second_http_call():
    malformed = (
        '{"verdict":"candidate","class":"sqli",'
        '"recommendation":"broken "quoted" value"}'
    )

    calls = []

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": malformed,
                        }
                    }
                ]
            }

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(json)
        return FakeResponse()

    client = MoonshotModelClient(
        api_key="test-key",
        base_url="https://openrouter.ai/api/v1",
        model="stealth/ox-alpha",
        fail_closed=True,
        repair_invalid_json=True,
    )

    # Force the local repair stage to produce a structurally unacceptable
    # object. This must fail closed and MUST NOT trigger another HTTP request.
    with patch(
        "spotlight.agents.moonshot.httpx.post",
        side_effect=fake_post,
    ), patch(
        "spotlight.agents.moonshot.repair_json",
        return_value="{}",
    ):
        with pytest.raises(RuntimeError, match="Live model call failed"):
            client.complete(
                role="investigator",
                prompt="test",
                context={"slice": {}},
            )

    assert len(calls) == 1


def test_valid_json_never_triggers_repair_request():
    calls = []

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": _valid_investigator_json(),
                        }
                    }
                ]
            }

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(json)
        return FakeResponse()

    client = MoonshotModelClient(
        api_key="test-key",
        base_url="https://openrouter.ai/api/v1",
        model="stealth/ox-alpha",
        fail_closed=True,
        repair_invalid_json=True,
    )

    with patch(
        "spotlight.agents.moonshot.httpx.post",
        side_effect=fake_post,
    ):
        out = client.complete(
            role="investigator",
            prompt="test",
            context={"slice": {}},
        )

    assert len(calls) == 1
    assert out["verdict"] == "candidate"
    assert "_parse_repaired" not in out


def test_repair_disabled_keeps_fail_closed_behavior():
    calls = []

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": '{"broken": "json" "still-broken"}',
                        }
                    }
                ]
            }

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(json)
        return FakeResponse()

    client = MoonshotModelClient(
        api_key="test-key",
        base_url="https://openrouter.ai/api/v1",
        model="stealth/ox-alpha",
        fail_closed=True,
        repair_invalid_json=False,
    )

    with patch(
        "spotlight.agents.moonshot.httpx.post",
        side_effect=fake_post,
    ):
        with pytest.raises(RuntimeError, match="Live model call failed"):
            client.complete(
                role="investigator",
                prompt="test",
                context={"slice": {}},
            )

    assert len(calls) == 1


def test_env_enables_bounded_json_repair(monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_LLM_API_KEY", "test-key")
    monkeypatch.setenv(
        "SPOTLIGHT_LLM_BASE_URL",
        "https://openrouter.ai/api/v1",
    )
    monkeypatch.setenv(
        "SPOTLIGHT_LLM_MODEL",
        "stealth/ox-alpha",
    )
    monkeypatch.setenv(
        "SPOTLIGHT_LLM_FAIL_CLOSED",
        "1",
    )
    monkeypatch.setenv(
        "SPOTLIGHT_LLM_REPAIR_INVALID_JSON",
        "1",
    )

    client = maybe_from_env()

    assert client is not None
    assert client.fail_closed is True
    assert client.repair_invalid_json is True
