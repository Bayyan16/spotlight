"""Ed25519 signing for Spotlight's non-repudiation ledger.

Every action performed by an agent (or human) inside Spotlight can be signed
with the workspace's Ed25519 private key. The resulting entry — hash of
payload + signature + timestamp — is what gets stored on
``finding.audit.chain_of_custody`` so that when a bad diff makes it into a
customer PR we can prove *which actor* (human or agent, and which agent)
authored each step, not just "someone in the workspace."

Key material:
    ``SPOTLIGHT_SIGNING_KEY`` env var — base64-encoded Ed25519 raw private key
    (32 bytes). On Railway this is a workspace-scoped secret. If missing at
    startup we generate a fresh key in-memory and print a loud warning; that
    key is *lost* on the next deploy so all previous signatures become
    unverifiable. Never run production without ``SPOTLIGHT_SIGNING_KEY``.

Wire format for signatures::

    signing_input = f"{ts}|{actor_kind}|{actor_id}|{action}|{payload_hash}"

We deliberately don't sign the raw payload — we sign its SHA-256 hex digest —
so entries stay small on the wire (~200 bytes) and payloads can carry
arbitrarily large diffs / logs without bloating the audit trail.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# Public type aliases — thin wrappers so callers don't have to import
# cryptography.* directly.
SigningKey = Ed25519PrivateKey
VerifyKey = Ed25519PublicKey

_ENV_VAR = "SPOTLIGHT_SIGNING_KEY"
_WARNED = False  # module-level so the ephemeral-key warning only fires once


def _canonical_json(payload: dict) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 clean.

    Two payloads that are semantically equal MUST produce byte-identical
    output — otherwise the payload_hash would drift and verify would fail.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _payload_hash(payload: dict) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _fingerprint(pub: Ed25519PublicKey) -> str:
    """First 16 hex chars of SHA-256 over the raw public key bytes."""
    from cryptography.hazmat.primitives import serialization

    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def _signing_input(ts: str, actor_kind: str, actor_id: str, action: str, payload_hash: str) -> bytes:
    return f"{ts}|{actor_kind}|{actor_id}|{action}|{payload_hash}".encode("utf-8")


def get_or_create_workspace_keys() -> tuple[SigningKey, VerifyKey]:
    """Return (private, public). Reads ``SPOTLIGHT_SIGNING_KEY`` from env.

    If the env var isn't set we generate a fresh key and print a warning to
    stderr. The generated key lives only for this process — all downstream
    signatures become un-verifiable across deploys — so production MUST set
    the env var explicitly.
    """
    global _WARNED
    b64 = os.environ.get(_ENV_VAR)
    if b64:
        try:
            raw = base64.b64decode(b64)
        except Exception as exc:
            raise RuntimeError(
                f"{_ENV_VAR} is set but not valid base64: {exc!r}"
            ) from exc
        if len(raw) != 32:
            raise RuntimeError(
                f"{_ENV_VAR} decodes to {len(raw)} bytes; expected 32 (raw Ed25519 seed)"
            )
        priv = Ed25519PrivateKey.from_private_bytes(raw)
        return priv, priv.public_key()

    if not _WARNED:
        print(
            f"[non_repudiation] WARNING: {_ENV_VAR} not set — generating an ephemeral "
            "Ed25519 key. Signatures produced by this process will NOT verify after "
            "restart. Set SPOTLIGHT_SIGNING_KEY on Railway to persist across deploys.",
            file=sys.stderr,
        )
        _WARNED = True
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def validate_signing_configuration(*, require_persistent: bool = False) -> None:
    """Validate key material without generating an ephemeral replacement."""
    b64 = os.environ.get(_ENV_VAR, "").strip()
    if require_persistent and not b64:
        raise RuntimeError(
            f"{_ENV_VAR} is required in production so audit signatures survive restarts"
        )
    if not b64:
        return
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as exc:
        raise RuntimeError(f"{_ENV_VAR} is not valid base64") from exc
    if len(raw) != 32:
        raise RuntimeError(f"{_ENV_VAR} must decode to exactly 32 bytes")


class Signer:
    """Convenience wrapper around a workspace signing key.

    Instantiating with no args pulls the workspace key from env (or generates
    an ephemeral one). Pass an explicit ``private_key`` in tests to keep
    signatures deterministic.
    """

    def __init__(self, private_key: SigningKey | None = None) -> None:
        if private_key is None:
            priv, pub = get_or_create_workspace_keys()
            self._priv = priv
            self._pub = pub
        else:
            self._priv = private_key
            self._pub = private_key.public_key()
        self._fp = _fingerprint(self._pub)

    @property
    def public_key(self) -> VerifyKey:
        return self._pub

    @property
    def fingerprint(self) -> str:
        return self._fp

    def public_key_b64(self) -> str:
        from cryptography.hazmat.primitives import serialization

        raw = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")

    def sign(self, actor_kind: str, actor_id: str, action: str, payload: dict) -> dict:
        ph = _payload_hash(payload)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        sig = self._priv.sign(_signing_input(ts, actor_kind, actor_id, action, ph))
        return {
            "actor_kind": actor_kind,
            "actor_id": actor_id,
            "action": action,
            "ts": ts,
            "payload_hash": ph,
            "payload": payload,
            "signature": base64.b64encode(sig).decode("ascii"),
            "key_fingerprint": self._fp,
        }

    def verify(self, entry: dict) -> bool:
        return verify_action(entry, self._pub)


def sign_action(
    actor_kind: str,
    actor_id: str,
    action: str,
    payload: dict,
    signer: Signer | None = None,
) -> dict:
    """Top-level convenience — sign a single action with the workspace key.

    Callers who need to sign many entries should hold a :class:`Signer`
    instance instead so the key is only loaded once.
    """
    s = signer or Signer()
    return s.sign(actor_kind, actor_id, action, payload)


def verify_action(entry: dict, public_key: VerifyKey | None = None) -> bool:
    """Verify a signed entry. Returns True/False; never raises.

    If ``public_key`` is None we pull the workspace key from env. In a mixed
    key-rotation world the caller should pass the pub key that matches
    ``entry["key_fingerprint"]``.
    """
    try:
        actor_kind = entry["actor_kind"]
        actor_id = entry["actor_id"]
        action = entry["action"]
        ts = entry["ts"]
        payload_hash = entry["payload_hash"]
        sig_b64 = entry["signature"]
    except (KeyError, TypeError):
        return False
    if "payload" in entry:
        try:
            if not hmac.compare_digest(_payload_hash(entry["payload"]), payload_hash):
                return False
        except Exception:
            return False
    if public_key is None:
        _, public_key = get_or_create_workspace_keys()
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        return False
    try:
        public_key.verify(
            sig,
            _signing_input(ts, actor_kind, actor_id, action, payload_hash),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
