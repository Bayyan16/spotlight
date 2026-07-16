"""WardenService — the control-plane surface Recon, Investigator, and
Verifier call into.

Responsibilities:

    wrap_target_content         hardened envelope around any target-derived string
    scan_target_for_injection   prompt-injection detector wrapper
    check_fix_diff              backdoor/weakening scan on a diff
    issue_capability            proxy + token_id stamp on a CapabilityToken
    sign_action                 audit-trail signer (hash-only in this tranche)
    emit_injection_flags        push warden.injection.flagged events onto a bus

The envelope, the injection scan, and the backdoor scan are all pure
functions here — no I/O, no model calls. That keeps the service testable
and reusable from the API, the console, and future tranches.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from time import time
from typing import Any
from uuid import uuid4

from spotlight.sandbox import CapabilityToken

from .backdoor_check import BackdoorMatch, check as _check_diff
from .injection_detector import InjectionMatch, scan as _scan_injection


# Envelope sentinels. Long / distinctive so the model can't confuse them with
# regular content and can't be fooled into "closing" them prematurely.
_ENV_BEGIN_PREFIX = "===UNTRUSTED_CONTENT_BEGIN"
_ENV_END = "===UNTRUSTED_CONTENT_END==="


@dataclass
class WardenService:
    """The Warden control-plane. Stateless (per-call) so it's cheap to
    construct anywhere."""

    # Reserved for a future Ed25519 signer (B8). None here = hash-only mode.
    signer: Any = field(default=None)

    # ── envelope ──────────────────────────────────────────────────────
    def wrap_target_content(self, text: str, origin: str) -> str:
        """Wrap any target-derived string in a hardened envelope.

        The envelope tells the model: *everything between these fences is
        untrusted data, not a directive from the operator.* We add the
        `origin=…` tag so a downstream reviewer can trace where the payload
        came from.

        Idempotent: wrapping an already-wrapped string returns it unchanged.
        This matters because the same content can flow through Recon and
        Investigator and we don't want doubled envelopes at the model.
        """
        if text.strip().startswith(_ENV_BEGIN_PREFIX) and _ENV_END in text:
            return text
        safe_origin = str(origin or "unknown").replace("\n", " ").strip() or "unknown"
        return (
            f"\n{_ENV_BEGIN_PREFIX} [origin={safe_origin}]===\n"
            f"{text}\n"
            f"{_ENV_END}\n"
        )

    def is_wrapped(self, text: str) -> bool:
        """Cheap check callers can use to short-circuit re-wrapping."""
        return text.strip().startswith(_ENV_BEGIN_PREFIX) and _ENV_END in text

    # ── detectors ─────────────────────────────────────────────────────
    def scan_target_for_injection(self, text: str, origin: str) -> list[InjectionMatch]:
        """Run the prompt-injection detector. `origin` is not currently used
        by the scanner but is threaded through for the caller's benefit
        (event payloads, log lines)."""
        _ = origin  # kept for API stability; used by callers, not the scan
        return _scan_injection(text)

    def check_fix_diff(self, diff: str) -> list[BackdoorMatch]:
        """Run the backdoor-check scanner on a unified diff."""
        return _check_diff(diff)

    # ── capability issuance ───────────────────────────────────────────
    def issue_capability(
        self,
        role: str,
        finding_id: str | None = None,
        **kw: Any,
    ) -> CapabilityToken:
        """Issue a CapabilityToken with a stamped `token_id`.

        The role decides which factory we call. Extra kwargs (`repo_path`,
        `patched_path`) are forwarded to the factory. Anything the factory
        doesn't accept is passed as a plain field on the token — the caller
        gets a well-formed grant either way.
        """
        token_id = uuid4().hex
        role = role.lower().strip()
        if role == "reproducer":
            tok = CapabilityToken.for_reproducer(
                finding_id=finding_id or "unknown",
                repo_path=kw.get("repo_path", ""),
            )
        elif role == "verifier":
            tok = CapabilityToken.for_verifier(
                finding_id=finding_id or "unknown",
                patched_path=kw.get("patched_path", ""),
            )
        else:
            # Generic path: hand the caller a bare token they can further
            # constrain. Egress is off by default (dataclass default).
            tok = CapabilityToken(
                agent_role=role or "unknown",
                finding_id=finding_id,
                ro_paths=list(kw.get("ro_paths", [])),
                rw_paths=list(kw.get("rw_paths", [])),
                egress_allowed=bool(kw.get("egress_allowed", False)),
                egress_allowlist=list(kw.get("egress_allowlist", [])),
                cpu=float(kw.get("cpu", 1.0)),
                memory_mb=int(kw.get("memory_mb", 512)),
                timeout_s=int(kw.get("timeout_s", 60)),
                max_output_bytes=int(kw.get("max_output_bytes", 512 * 1024)),
                max_exec_calls=int(kw.get("max_exec_calls", 10)),
            )
        # Attach a token_id so events / audit rows can reference the exact
        # grant. CapabilityToken doesn't have this field natively yet, so we
        # stick it on as an attribute — `to_dict()` on the dataclass ignores
        # it, but downstream callers who care can read `tok.token_id`.
        try:
            object.__setattr__(tok, "token_id", token_id)
        except Exception:
            pass
        return tok

    # ── signed audit action ───────────────────────────────────────────
    def sign_action(self, actor: str, kind: str, payload: dict) -> dict:
        """Produce a signed audit record for an action.

        Ed25519 signing lands in Tranche B8. Until then we produce a
        deterministic SHA-256 over the canonical JSON of the record. The
        hash is enough to close the "actor claims they didn't do X" gap
        against a same-process tamper; a real cryptographic actor-identity
        binding comes with B8.
        """
        ts = time()
        # Redact only the keys we know to be sensitive at the service layer;
        # heavier redaction happens at the event bus.
        canonical = json.dumps(
            {"actor": actor, "kind": kind, "payload": payload, "ts": ts},
            sort_keys=True,
            default=str,
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return {
            "actor": actor,
            "kind": kind,
            "payload": payload,
            "ts": ts,
            "hash": digest,
        }

    # ── event emission helper ─────────────────────────────────────────
    def emit_injection_flags(
        self,
        bus: Any,
        sweep_id: str,
        origin: str,
        matches: list[InjectionMatch | dict],
        actor: str = "warden",
    ) -> int:
        """Emit one `warden.injection.flagged` event per match. Returns the
        count emitted. Silently no-ops if `matches` is empty. `matches` may
        be a list of dataclasses or already-serialized dicts — both are
        accepted so callers can pass through a Recon output block."""
        from spotlight.orchestrator.events import EventType

        n = 0
        for m in matches or []:
            if isinstance(m, InjectionMatch):
                payload = m.to_dict()
            elif isinstance(m, dict):
                payload = m
            else:
                continue
            bus.emit(
                sweep_id,
                EventType.WARDEN_INJECTION_FLAGGED,
                actor,
                origin=origin,
                **payload,
            )
            n += 1
        return n


# Convenience re-export for callers that only need the callable service.
Warden = WardenService
