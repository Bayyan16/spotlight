"""Ledger integrity — the property the whole Cortex rests on.

If an experience row can be edited after the fact, the policy derived from it
can be steered, and a steered policy is a way to give Spotlight a blind spot.
These tests pin the detection of every way a row can be tampered with.
"""
from __future__ import annotations

import json

from spotlight.cortex.experience import (
    FALSE_POSITIVE,
    SOURCE_ANALYST,
    SOURCE_REPRODUCTION,
    SOURCE_UNLABELED,
    TRUE_POSITIVE,
    UNKNOWN,
    Experience,
)
from spotlight.cortex.ledger import GENESIS, ExperienceLedger


def _exp(key="fp1", label=TRUE_POSITIVE, source=SOURCE_REPRODUCTION, **kw) -> Experience:
    base = dict(
        sweep_id="sw_1",
        finding_key=key,
        class_="sqli",
        cohort="sqli|independent_agent",
        signature="independent_agent",
        tier="verified",
        confidence=0.9,
        label=label,
        label_source=source,
    )
    base.update(kw)
    return Experience(**base)


def test_first_record_chains_from_genesis(tmp_path):
    ledger = ExperienceLedger(tmp_path)
    rec = ledger.append(_exp())
    assert rec["prev_hash"] == GENESIS
    assert rec["seq"] == 0
    assert ledger.head() == rec["record_hash"]


def test_chain_links_each_row_to_the_previous(tmp_path):
    ledger = ExperienceLedger(tmp_path)
    first = ledger.append(_exp(key="a"))
    second = ledger.append(_exp(key="b"))
    assert second["prev_hash"] == first["record_hash"]
    assert ledger.verify().ok is True


def test_append_is_idempotent_on_identical_experience(tmp_path):
    """A crashed worker replaying its queue must not inflate cohort counts."""
    ledger = ExperienceLedger(tmp_path)
    ledger.append(_exp())
    ledger.append(_exp())
    assert ledger.count() == 1


def test_editing_a_row_breaks_verification_and_names_the_row(tmp_path):
    ledger = ExperienceLedger(tmp_path)
    ledger.append(_exp(key="a"))
    ledger.append(_exp(key="b", label=FALSE_POSITIVE, source=SOURCE_ANALYST))
    ledger.append(_exp(key="c"))

    lines = ledger.path.read_text().splitlines()
    row = json.loads(lines[1])
    # The attack: flip a human's false-positive verdict into a true positive so
    # the noisy cohort keeps promoting.
    row["experience"]["label"] = TRUE_POSITIVE
    lines[1] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    ledger.path.write_text("\n".join(lines) + "\n")

    report = ledger.verify()
    assert report.ok is False
    assert report.chain_ok is False
    assert report.broken_at == 1
    assert "record_hash mismatch" in report.reason


def test_deleting_a_row_breaks_the_chain(tmp_path):
    ledger = ExperienceLedger(tmp_path)
    ledger.append(_exp(key="a"))
    ledger.append(_exp(key="b"))
    ledger.append(_exp(key="c"))
    lines = ledger.path.read_text().splitlines()
    ledger.path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    report = ledger.verify()
    assert report.ok is False
    assert report.broken_at == 1


def test_torn_final_write_is_reported_not_silently_dropped(tmp_path):
    ledger = ExperienceLedger(tmp_path)
    ledger.append(_exp(key="a"))
    with ledger.path.open("a") as fh:
        fh.write('{"seq": 1, "prev_hash": "x", "experi')
    report = ledger.verify()
    assert report.ok is False
    assert "torn write" in report.reason


def test_signatures_verify_against_the_workspace_key(tmp_path):
    from spotlight.non_repudiation import Signer

    signer = Signer()
    ledger = ExperienceLedger(tmp_path, signer=signer)
    ledger.append(_exp(key="a"))
    ledger.append(_exp(key="b"))
    report = ledger.verify(signer.public_key)
    assert report.ok is True
    assert report.signatures_checked == 2


def test_a_forged_signature_is_caught(tmp_path):
    from spotlight.non_repudiation import Signer

    signer = Signer()
    ledger = ExperienceLedger(tmp_path, signer=signer)
    ledger.append(_exp(key="a"))
    lines = ledger.path.read_text().splitlines()
    row = json.loads(lines[0])
    row["signature"]["actor_id"] = "someone-else"
    lines[0] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    ledger.path.write_text("\n".join(lines) + "\n")
    # The chain still validates (the experience payload is untouched) — it is
    # the signature check that catches an actor swap.
    report = ledger.verify(signer.public_key)
    assert report.chain_ok is True
    assert report.signatures_ok is False
    assert report.ok is False


def test_secrets_are_redacted_before_they_reach_disk(tmp_path):
    """The ledger is long-lived and feeds prompts; a leaked key must not persist."""
    ledger = ExperienceLedger(tmp_path)
    ledger.append(
        _exp(label_reason="analyst pasted AKIAIOSFODNN7EXAMPLE into the review")
    )
    on_disk = ledger.path.read_text()
    assert "AKIAIOSFODNN7EXAMPLE" not in on_disk
    assert "REDACTED" in on_disk


def test_latest_by_finding_keeps_the_most_authoritative_row(tmp_path):
    ledger = ExperienceLedger(tmp_path)
    ledger.append(_exp(key="fp1", label=TRUE_POSITIVE, source=SOURCE_REPRODUCTION))
    ledger.append(_exp(key="fp1", label=FALSE_POSITIVE, source=SOURCE_ANALYST, sweep_id="sw_2"))
    ledger.append(_exp(key="fp1", label=UNKNOWN, source=SOURCE_UNLABELED, sweep_id="sw_3"))
    latest = ledger.latest_by_finding()
    assert len(latest) == 1
    assert latest["fp1"].label == FALSE_POSITIVE
    assert latest["fp1"].label_source == SOURCE_ANALYST


def test_latest_by_finding_refreshes_within_equal_authority(tmp_path):
    ledger = ExperienceLedger(tmp_path)
    ledger.append(_exp(key="fp1", tier="high-confidence", ts="2026-01-01T00:00:00.000000Z"))
    ledger.append(_exp(key="fp1", tier="verified", ts="2026-02-01T00:00:00.000000Z"))
    assert ledger.latest_by_finding()["fp1"].tier == "verified"


def test_empty_ledger_verifies_clean(tmp_path):
    report = ExperienceLedger(tmp_path).verify()
    assert report.ok is True
    assert report.records == 0
    assert report.head == GENESIS


def test_snapshot_copies_the_ledger(tmp_path):
    ledger = ExperienceLedger(tmp_path)
    ledger.append(_exp())
    dest = ledger.snapshot(tmp_path / "backup" / "experiences.jsonl")
    assert dest.read_text() == ledger.path.read_text()


# ── scale and concurrency ────────────────────────────────────────────────


def test_appending_many_rows_does_not_re_read_the_file_each_time(tmp_path, monkeypatch):
    """The cache is what keeps a year-old workspace fast.

    Without it, every append re-parses the whole ledger to find the head and to
    de-duplicate — O(n) file reads per row. This pins the behaviour by counting
    reads, not by timing, so it cannot flake on a slow runner.
    """
    ledger = ExperienceLedger(tmp_path)
    reads = {"n": 0}
    original = type(ledger.path).read_text

    def counting_read(self, *a, **kw):
        reads["n"] += 1
        return original(self, *a, **kw)

    monkeypatch.setattr(type(ledger.path), "read_text", counting_read)
    for i in range(40):
        ledger.append(_exp(key=f"k{i}"))
    assert ledger.count() == 40
    # One initial parse is fine; forty are not.
    assert reads["n"] <= 3, f"ledger re-read the file {reads['n']} times for 40 appends"


def test_concurrent_appends_keep_one_unbroken_chain(tmp_path):
    """The API process and the worker both harvest.

    Two appends that each read the same head would write two rows with the same
    prev_hash — a forked chain that verify() reports as broken on a ledger
    nobody tampered with.
    """
    import threading

    ledger = ExperienceLedger(tmp_path)
    errors: list[BaseException] = []

    def worker(start: int):
        try:
            for i in range(start, start + 15):
                ExperienceLedger(tmp_path).append(_exp(key=f"k{i}"))
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n * 15,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    report = ledger.verify()
    assert report.ok is True, report.reason
    assert report.records == 60


def test_a_second_writer_is_noticed_by_the_cache(tmp_path):
    """The cache is a speed-up, never a source of truth."""
    a = ExperienceLedger(tmp_path)
    b = ExperienceLedger(tmp_path)
    a.append(_exp(key="k1"))
    assert a.count() == 1
    b.append(_exp(key="k2"))
    # `a` has a warm cache from before b's write; it must still see 2.
    assert a.count() == 2
    assert a.verify().ok is True
