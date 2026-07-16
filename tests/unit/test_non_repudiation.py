"""Unit tests for the non-repudiation ledger and git-ops trailer/PR wiring.

Covers:
- Ed25519 sign/verify happy path (with an explicit private key so tests are
  hermetic — no reliance on ``SPOTLIGHT_SIGNING_KEY``).
- Tamper detection: mutate the payload_hash after signing, verify fails.
- ChainOfCustody with a mix of agent + human entries, verify_all() True.
- Two independent keys produce different signatures for the same input.
- ``stage_and_commit(trailers=...)`` writes the trailer verbatim to the
  commit message body (real ``git`` binary, tmp repo).
- ``open_pr`` mock: PR body built with ``format_non_repudiation_footer``
  contains the Non-repudiation section header + attestation URL.
"""
from __future__ import annotations

import base64
import copy
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from spotlight.git_ops import GitOps, format_non_repudiation_footer
from spotlight.non_repudiation import (
    ChainOfCustody,
    Signer,
    sign_action,
    verify_action,
)
from spotlight.non_repudiation.api import public_key_response


# ---------------------------------------------------------------- signing


def _fresh_signer() -> Signer:
    """Build a Signer around a freshly-generated in-memory key.

    Bypasses ``SPOTLIGHT_SIGNING_KEY`` so tests don't leak the workspace key
    or produce warnings from the ephemeral-key path.
    """
    return Signer(private_key=Ed25519PrivateKey.generate())


def test_sign_and_verify_roundtrip():
    signer = _fresh_signer()
    entry = signer.sign(
        actor_kind="agent",
        actor_id="Remediator",
        action="propose_patch",
        payload={"finding_id": "SPOT-0001", "lines": 42},
    )
    # Envelope shape is what the store persists.
    assert entry["actor_kind"] == "agent"
    assert entry["actor_id"] == "Remediator"
    assert entry["action"] == "propose_patch"
    assert len(entry["payload_hash"]) == 64  # sha256 hex
    assert len(entry["key_fingerprint"]) == 16
    # And the signature verifies against the same key.
    assert signer.verify(entry) is True
    assert verify_action(entry, signer.public_key) is True


def test_verify_fails_when_payload_hash_tampered():
    signer = _fresh_signer()
    entry = signer.sign(
        "agent",
        "Triager",
        "confirm_finding",
        {"finding_id": "SPOT-0002", "class": "sqli"},
    )
    # Attacker rewrites the payload_hash to point at a different payload
    # while leaving the signature alone.
    tampered = dict(entry)
    tampered["payload_hash"] = "0" * 64
    assert verify_action(tampered, signer.public_key) is False
    # Same result if we tamper with actor_id.
    tampered2 = dict(entry)
    tampered2["actor_id"] = "SomeoneElse"
    assert verify_action(tampered2, signer.public_key) is False


def test_verify_fails_on_missing_fields():
    signer = _fresh_signer()
    entry = signer.sign("agent", "Verifier", "run_poc", {"passed": True})
    broken = {k: v for k, v in entry.items() if k != "signature"}
    assert verify_action(broken, signer.public_key) is False


def test_different_keys_produce_different_signatures():
    """Same input, two distinct keys → two distinct signatures.

    (Ed25519 is deterministic per key, so this specifically pins that
    ``Signer`` is actually threading the key material through — not
    accidentally reading from a global.)
    """
    signer_a = _fresh_signer()
    signer_b = _fresh_signer()
    payload = {"finding_id": "SPOT-0003"}
    # Freeze the timestamp so the signing input is identical.
    from spotlight.non_repudiation import signing as sig_mod

    fixed_ts = "2026-07-16T12:00:00.000000Z"

    class _FrozenDT:
        @staticmethod
        def now(_tz):
            class _F:
                def strftime(self, _fmt):
                    return fixed_ts

            return _F()

    orig = sig_mod.datetime
    sig_mod.datetime = _FrozenDT  # type: ignore[assignment]
    try:
        e_a = signer_a.sign("agent", "Triager", "act", payload)
        e_b = signer_b.sign("agent", "Triager", "act", payload)
    finally:
        sig_mod.datetime = orig
    assert e_a["ts"] == e_b["ts"]
    assert e_a["payload_hash"] == e_b["payload_hash"]
    assert e_a["signature"] != e_b["signature"]
    # And each verifies only under its own key.
    assert verify_action(e_a, signer_a.public_key) is True
    assert verify_action(e_a, signer_b.public_key) is False
    assert verify_action(e_b, signer_b.public_key) is True
    assert verify_action(e_b, signer_a.public_key) is False


def test_sign_action_convenience_uses_provided_signer():
    signer = _fresh_signer()
    entry = sign_action("human", "abhi", "approve", {"decision": "ship"}, signer=signer)
    assert entry["actor_kind"] == "human"
    assert verify_action(entry, signer.public_key) is True


def test_canonical_json_stable_across_key_order():
    """Same payload with keys in different insertion orders → same hash.

    Guards against a class of bug where an attacker reorders keys to slip
    a mutation past hash verification.
    """
    signer = _fresh_signer()
    p1 = {"a": 1, "b": 2, "c": [3, 4]}
    p2 = {"c": [3, 4], "b": 2, "a": 1}
    e1 = signer.sign("agent", "X", "act", p1)
    e2 = signer.sign("agent", "X", "act", p2)
    assert e1["payload_hash"] == e2["payload_hash"]


# ---------------------------------------------------- chain of custody


def test_chain_of_custody_verify_all_three_entries():
    chain = ChainOfCustody(signer=_fresh_signer())
    chain.add_agent_action("Triager", "confirm", {"finding_id": "SPOT-0004"})
    chain.add_agent_action("Remediator", "patch", {"finding_id": "SPOT-0004", "lines": 12})
    chain.add_human_action("abhi", "approve", {"finding_id": "SPOT-0004", "note": "lgtm"})
    entries = chain.to_list()
    assert len(entries) == 3
    assert entries[0]["actor_kind"] == "agent"
    assert entries[2]["actor_kind"] == "human"
    assert chain.verify_all() is True


def test_chain_verify_all_fails_if_any_entry_tampered():
    chain = ChainOfCustody(signer=_fresh_signer())
    chain.add_agent_action("Triager", "confirm", {"finding_id": "SPOT-0005"})
    chain.add_agent_action("Remediator", "patch", {"finding_id": "SPOT-0005"})
    # Reach into the internal list and mutate the second entry's action.
    chain._entries[1]["action"] = "delete_repo"  # noqa: SLF001 — test-only
    assert chain.verify_all() is False


def test_chain_to_list_returns_copy():
    """Downstream mutation shouldn't corrupt the in-memory chain."""
    chain = ChainOfCustody(signer=_fresh_signer())
    chain.add_agent_action("Triager", "confirm", {"x": 1})
    out = chain.to_list()
    out.append({"malicious": True})
    assert len(chain) == 1


# ---------------------------------------------------- public-key envelope


def test_public_key_response_shape(monkeypatch):
    # Force a known key via env so the response is deterministic across runs.
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes_raw()
    monkeypatch.setenv("SPOTLIGHT_SIGNING_KEY", base64.b64encode(raw).decode())
    resp = public_key_response()
    assert resp["algorithm"] == "Ed25519"
    # Raw Ed25519 pub key is 32 bytes -> base64 length 44 with padding.
    assert len(base64.b64decode(resp["public_key_b64"])) == 32
    assert len(resp["fingerprint"]) == 16


# ---------------------------------------------------- git trailers


def _git(cwd: Path, *args: str) -> str:
    r = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True
    )
    return r.stdout


@pytest.fixture
def tmp_git_repo(tmp_path):
    src = tmp_path / "repo"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    _git(src, "config", "user.email", "test@spotlight.local")
    _git(src, "config", "user.name", "Spotlight Test")
    (src / "app.py").write_text("x = 1\n")
    _git(src, "add", "app.py")
    _git(src, "commit", "-q", "-m", "seed")
    return src


def test_stage_and_commit_appends_trailer(tmp_git_repo):
    gh = GitOps()
    (tmp_git_repo / "app.py").write_text("x = 2\n")
    sha = gh.stage_and_commit(
        tmp_git_repo,
        [tmp_git_repo / "app.py"],
        message="fix: patch sqli",
        trailers={"Signed-off-by-agent": "sw_abc/SPOT-0001"},
    )
    assert len(sha) == 40
    # Full message body includes the trailer as a `Key: Value` line at the end.
    body = _git(tmp_git_repo, "log", "-1", "--format=%B").rstrip("\n")
    assert "fix: patch sqli" in body
    assert "Signed-off-by-agent: sw_abc/SPOT-0001" in body
    # And it's separated from the subject by a blank line (trailers convention).
    lines = body.splitlines()
    assert "" in lines
    idx_blank = lines.index("")
    assert any(
        line == "Signed-off-by-agent: sw_abc/SPOT-0001" for line in lines[idx_blank + 1 :]
    )


def test_stage_and_commit_no_trailers_matches_legacy_behavior(tmp_git_repo):
    """Trailers default to None — commit message should be unchanged."""
    gh = GitOps()
    (tmp_git_repo / "app.py").write_text("x = 3\n")
    gh.stage_and_commit(
        tmp_git_repo,
        [tmp_git_repo / "app.py"],
        message="fix: no trailer",
    )
    body = _git(tmp_git_repo, "log", "-1", "--format=%B").strip()
    assert body == "fix: no trailer"


def test_stage_and_commit_default_author_is_spotlight_bot(tmp_git_repo):
    """Every Spotlight commit must be authored by ``Spotlight <bot@cmul8.com>``
    — that's the bank-visible signal that this diff came from an agent, not
    a human on the workspace."""
    gh = GitOps()
    (tmp_git_repo / "app.py").write_text("x = 4\n")
    gh.stage_and_commit(
        tmp_git_repo,
        [tmp_git_repo / "app.py"],
        message="fix: author check",
    )
    author = _git(tmp_git_repo, "log", "-1", "--format=%an <%ae>").strip()
    assert author == "Spotlight <bot@cmul8.com>"


# ---------------------------------------------------- open_pr non-repudiation section


def test_open_pr_body_contains_non_repudiation_section(tmp_git_repo, monkeypatch):
    """The PR body assembled via ``format_non_repudiation_footer`` must land
    in the ``gh pr create --body`` arg verbatim so auditors can find the
    attestation URL directly from the PR page."""
    gh = GitOps()
    attestation_url = "https://spotlight.cmul8.com/findings/SPOT-0001/attestation"
    body = "Auto-remediation for SPOT-0001." + format_non_repudiation_footer(attestation_url)

    seen_args: list[list[str]] = []

    def fake_run(args, **kwargs):
        seen_args.append(args)
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="https://github.com/AbhiK24/Spotlight/pull/1\n",
            stderr="",
        )

    monkeypatch.setattr("spotlight.git_ops.ops.subprocess.run", fake_run)
    result = gh.open_pr(
        tmp_git_repo, base="main", head="scratch", title="fix", body=body
    )
    assert result.ok is True
    # Body arg was passed to `gh pr create` unmodified.
    gh_call = next(a for a in seen_args if a and a[0] == "gh")
    body_idx = gh_call.index("--body") + 1
    body_arg = gh_call[body_idx]
    assert "## Non-repudiation" in body_arg
    assert attestation_url in body_arg


def test_format_non_repudiation_footer_shape():
    footer = format_non_repudiation_footer("https://example/attestation/1")
    assert "## Non-repudiation" in footer
    assert "https://example/attestation/1" in footer
    # Blank-line separation from any preceding body content.
    assert footer.startswith("\n\n")
