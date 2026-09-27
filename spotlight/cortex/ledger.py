"""The Experience Ledger — append-only, hash-chained, signed memory.

Everything the Cortex knows comes from this file, so the file is the attack
surface. If an experience row can be edited after the fact, then the policy
derived from it can be steered, and a steered policy is a way to make
Spotlight quietly stop reporting a class of vulnerability. That is the
highest-value attack against a security tool: not a crash, a blind spot.

Three properties defend it, and all three are checkable offline:

* **Append-only, hash-chained.** Every record carries ``prev_hash``, the
  ``record_hash`` of the row before it, and its own ``record_hash`` over
  ``(prev_hash, experience payload)``. Editing row *k* invalidates every row
  after it, and ``verify()`` names the first broken index.
* **Signed.** Each row is signed with the workspace Ed25519 key through the
  same `Signer` the chain of custody uses, so the ledger verifies against the
  key already published at ``/verify-key``. No new trust root.
* **Redacted on write.** Rows pass the redaction pipeline before they touch
  disk. A ledger is long-lived and gets replayed into prompts; a secret that
  lands here would outlive the sweep that leaked it.

The head hash is the ledger's identity at a point in time. Every policy the
Cortex derives pins the head it was derived from, which is what makes an
attestation replayable months later: same head, same rows, same policy, same
tier.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from spotlight.redaction import Redactor

from .experience import Experience

GENESIS = "0" * 64

_REDACTOR = Redactor()


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(prev_hash: str, experience: dict[str, Any]) -> str:
    """Chain link: sha256(prev_hash || canonical(experience))."""
    blob = f"{prev_hash}|{_canonical(experience)}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class LedgerVerification:
    """Result of an offline integrity check. Never raises — auditors read it."""

    ok: bool
    records: int
    head: str
    chain_ok: bool = True
    signatures_ok: bool = True
    signatures_checked: int = 0
    broken_at: int | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "head": self.head,
            "chain_ok": self.chain_ok,
            "signatures_ok": self.signatures_ok,
            "signatures_checked": self.signatures_checked,
            "broken_at": self.broken_at,
            "reason": self.reason,
        }


class ExperienceLedger:
    """JSONL-backed append-only ledger.

    One row per line: ``{seq, prev_hash, record_hash, experience, signature?}``.
    JSONL because it is append-cheap, human-greppable, and survives a partial
    write — a truncated final line is reported by ``verify()`` rather than
    corrupting the rows before it.
    """

    FILENAME = "experiences.jsonl"

    def __init__(self, root: str | Path, signer: Any = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / self.FILENAME
        self.lock_path = self.root / f"{self.FILENAME}.lock"
        self._signer = signer
        # Read cache, keyed on the file's (mtime_ns, size). Without it every
        # append re-parses the whole ledger to compute the head and to
        # de-duplicate, which is O(n) file reads per row and quietly turns a
        # year-old workspace into a slow one. The stat key means another process
        # appending is still noticed — the cache is a speed-up, never a source
        # of truth.
        self._cache: list[dict[str, Any]] | None = None
        self._cache_key: tuple[int, int] | None = None
        self._cache_ids: set[str] = set()
        self._local_lock = threading.Lock()

    # ── locking ──────────────────────────────────────────────────────
    @contextmanager
    def _exclusive(self):
        """Serialize read-head-then-append across threads AND processes.

        The API process and the durable worker both harvest, so two appends can
        interleave. Without a lock each would read the same head and write two
        rows carrying the same ``prev_hash`` — a forked chain that `verify()`
        would correctly report as broken, on a ledger nobody actually tampered
        with. A POSIX advisory lock on a sidecar file covers the cross-process
        case; a threading lock covers two threads in one process. Falls back to
        thread-only when `fcntl` is unavailable (Windows dev boxes).
        """
        with self._local_lock:
            handle = None
            try:
                import fcntl

                handle = self.lock_path.open("a+")
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except Exception:  # pragma: no cover — no fcntl, or unlockable fs
                if handle is not None:
                    handle.close()
                handle = None
            try:
                yield
            finally:
                if handle is not None:
                    try:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    except Exception:  # pragma: no cover
                        pass
                    handle.close()

    # ── write path ───────────────────────────────────────────────────
    def append(self, experience: Experience) -> dict[str, Any]:
        """Append one experience. Returns the written record.

        De-duplicates on ``experience_id`` (a content address over the
        semantic fields): re-running a sweep, or replaying a crashed worker's
        queue, must not inflate a cohort's counts. Silent no-op returns the
        existing record so callers stay simple.
        """
        payload = _REDACTOR.redact_dict(experience.to_dict())
        exp_id = payload.get("experience_id")
        with self._exclusive():
            return self._append_locked(payload, exp_id)

    def _append_locked(self, payload: dict[str, Any], exp_id: Any) -> dict[str, Any]:
        records = self.records()          # refreshes the cache under the lock
        if exp_id and exp_id in self._cache_ids:
            existing = self.find(exp_id)
            if existing is not None:
                return existing

        prev = str(records[-1].get("record_hash") or GENESIS) if records else GENESIS
        rec: dict[str, Any] = {
            "seq": len(records),
            "prev_hash": prev,
            "experience": payload,
        }
        rec["record_hash"] = record_hash(prev, payload)
        if self._signer is not None:
            try:
                rec["signature"] = self._signer.sign(
                    actor_kind="agent",
                    actor_id="cortex",
                    action="experience.recorded",
                    payload={"record_hash": rec["record_hash"], "seq": rec["seq"]},
                )
            except Exception as exc:  # pragma: no cover — signing is best-effort
                print(f"[cortex.ledger] signing failed: {exc!r}")
        self._append_line(rec)
        return rec

    def extend(self, experiences: Iterable[Experience]) -> list[dict[str, Any]]:
        return [self.append(e) for e in experiences]

    def _append_line(self, rec: dict[str, Any]) -> None:
        line = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        # Open-append-flush-fsync: a crash mid-sweep must leave a readable
        # ledger, not a half-written row that breaks the chain for good.
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        # Extend the cache in place rather than invalidating it: a sweep appends
        # one row per finding, and re-parsing the ledger between each would be
        # the very cost the cache exists to avoid.
        if self._cache is not None:
            self._cache.append(rec)
            exp_id = str((rec.get("experience") or {}).get("experience_id") or "")
            if exp_id:
                self._cache_ids.add(exp_id)
            try:
                stat = self.path.stat()
                self._cache_key = (stat.st_mtime_ns, stat.st_size)
            except OSError:  # pragma: no cover
                self._cache_key = None

    # ── read path ────────────────────────────────────────────────────
    def records(self) -> list[dict[str, Any]]:
        """Every record, newest last. Cached on the file's (mtime, size)."""
        try:
            stat = self.path.stat()
            key = (stat.st_mtime_ns, stat.st_size)
        except FileNotFoundError:
            self._cache, self._cache_key, self._cache_ids = [], None, set()
            return []
        if self._cache is not None and self._cache_key == key:
            return self._cache

        out: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                # A truncated tail line is a torn write, not a reason to lose
                # the rows before it. verify() reports it.
                continue
        self._cache = out
        self._cache_key = key
        self._cache_ids = {
            str((r.get("experience") or {}).get("experience_id") or "") for r in out
        }
        return out

    def __iter__(self) -> Iterator[Experience]:
        for rec in self.records():
            yield Experience.from_dict(rec.get("experience") or {})

    def experiences(self) -> list[Experience]:
        return list(self)

    def count(self) -> int:
        return len(self.records())

    def head(self) -> str:
        recs = self.records()
        return str(recs[-1].get("record_hash") or GENESIS) if recs else GENESIS

    def find(self, experience_id: str) -> dict[str, Any] | None:
        for rec in self.records():
            if (rec.get("experience") or {}).get("experience_id") == experience_id:
                return rec
        return None

    def latest_by_finding(self) -> dict[str, Experience]:
        """Most authoritative row per finding key.

        A finding gets re-judged on every sweep of the repo. For calibration
        we want one row per finding — the one whose label came from the
        strongest source — so a weekly CI sweep can't outvote the analyst who
        once marked it a false positive.
        """
        best: dict[str, Experience] = {}
        for exp in self:
            current = best.get(exp.finding_key)
            if current is None or exp.supersedes(current):
                best[exp.finding_key] = exp
            elif current.authority == exp.authority:
                # Same authority — keep the newer row so a re-confirmed
                # finding refreshes its tier/confidence snapshot.
                if exp.ts >= current.ts:
                    best[exp.finding_key] = exp
        return best

    # ── integrity ────────────────────────────────────────────────────
    def verify(self, public_key: Any = None) -> LedgerVerification:
        """Recompute the chain (and signatures when a key is available).

        Deliberately total: returns a report for every failure mode instead
        of raising, because this is what an auditor calls on a ledger they
        did not produce.
        """
        # Integrity checks always re-read from disk: a cache that agreed with a
        # tampered file would defeat the entire point of this method.
        self._cache, self._cache_key, self._cache_ids = None, None, set()
        raw_lines = (
            [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
            if self.path.exists()
            else []
        )
        recs = self.records()
        if len(recs) != len(raw_lines):
            return LedgerVerification(
                ok=False, records=len(recs), head=self.head(), chain_ok=False,
                broken_at=len(recs),
                reason="unparseable row (torn write) at end of ledger",
            )

        prev = GENESIS
        for idx, rec in enumerate(recs):
            if str(rec.get("prev_hash")) != prev:
                return LedgerVerification(
                    ok=False, records=len(recs), head=prev, chain_ok=False,
                    broken_at=idx, reason=f"prev_hash mismatch at seq {idx}",
                )
            expected = record_hash(prev, rec.get("experience") or {})
            if str(rec.get("record_hash")) != expected:
                return LedgerVerification(
                    ok=False, records=len(recs), head=prev, chain_ok=False,
                    broken_at=idx,
                    reason=f"record_hash mismatch at seq {idx} (row was edited)",
                )
            prev = expected

        sigs_checked = 0
        if public_key is not None:
            from spotlight.non_repudiation.signing import verify_action

            for idx, rec in enumerate(recs):
                entry = rec.get("signature")
                if not entry:
                    continue
                sigs_checked += 1
                if not verify_action(entry, public_key):
                    return LedgerVerification(
                        ok=False, records=len(recs), head=prev, chain_ok=True,
                        signatures_ok=False, signatures_checked=sigs_checked,
                        broken_at=idx, reason=f"invalid signature at seq {idx}",
                    )

        return LedgerVerification(
            ok=True, records=len(recs), head=prev,
            signatures_checked=sigs_checked, reason="chain intact",
        )

    # ── maintenance ──────────────────────────────────────────────────
    def snapshot(self, dest: str | Path) -> Path:
        """Copy the ledger to `dest` atomically (for offline audit / backup)."""
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = self.path.read_bytes() if self.path.exists() else b""
        fd, tmp = tempfile.mkstemp(dir=str(dest.parent))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, dest)
        finally:
            if os.path.exists(tmp):  # pragma: no cover
                os.unlink(tmp)
        return dest
