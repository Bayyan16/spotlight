"""Semgrep Signal Adapter — tests.

These cover the local invariants without touching the real semgrep CLI:
canonical class mapping, slice-shape normalisation, missing-executable
graceful degradation. A separate live-semgrep test lives behind an env
gate so CI doesn't slow down.
"""
from __future__ import annotations

import os
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from spotlight.signals.semgrep_adapter import (
    DEFAULT_CONFIG,
    _LATCH_TTL_S,
    ENV_CONFIG,
    ENV_MODE,
    STATUS_DISABLED,
    STATUS_OK,
    STATUS_ERROR,
    STATUS_SKIPPED,
    STATUS_TIMEOUT,
    STATUS_UNREACHABLE,
    SemgrepAdapter,
    SemgrepMatch,
    _canonical_class,
    _extract_matches,
    degraded_reason,
    reset_degraded_state,
)


# Captured at import, before the autouse fixture below scrubs it: the live
# test at the bottom of this file should run against the ruleset the
# operator actually deploys, while every mocked test runs on the default.
_AMBIENT_CONFIG = os.environ.get("SPOTLIGHT_SEMGREP_CONFIG", "").strip() or None


@pytest.fixture(autouse=True)
def _clean_semgrep_env(monkeypatch):
    """Each test starts from a healthy adapter on default settings.

    The top-level conftest turns Semgrep off for the rest of the suite; this
    file is where the switches themselves are under test, so it puts the
    adapter back on `auto` and clears the process-wide degradation latch
    both before and after every test.
    """
    monkeypatch.setenv(ENV_MODE, "auto")
    monkeypatch.delenv(ENV_CONFIG, raising=False)
    reset_degraded_state()
    yield
    reset_degraded_state()


def _fake_which(monkeypatch, path="/usr/local/bin/semgrep"):
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.shutil.which",
        lambda _cmd: path,
    )


def _is_probe(cmd) -> bool:
    """True for the config probe, which scans its own empty temp dir."""
    return any("spotlight-semgrep-probe-" in str(part) for part in cmd)


def _fake_proc(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=["semgrep"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


# ── canonical-class table ───────────────────────────────────────────────

def test_canonical_class_maps_sqli_variants():
    for check_id in [
        "python.flask.security.injection.tainted-sql-string",
        "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
        "javascript.express.sql-injection",
    ]:
        assert _canonical_class(check_id) == "sqli"


def test_canonical_class_maps_cmdi_variants():
    for check_id in [
        "python.lang.security.dangerous-subprocess",
        "javascript.node.dangerous-system-call",
    ]:
        assert _canonical_class(check_id) == "cmdi"


def test_canonical_class_maps_secrets_variants():
    for check_id in [
        "python.lang.security.hardcoded-password",
        "generic.secrets.hardcoded-token",
    ]:
        assert _canonical_class(check_id) == "secrets"


def test_canonical_class_returns_none_for_unknown():
    assert _canonical_class("style.python.line-too-long") is None
    assert _canonical_class("") is None


# ── extract_matches shape ───────────────────────────────────────────────

def test_extract_matches_parses_typical_output():
    fake = {
        "results": [
            {
                "check_id": "python.flask.security.injection.tainted-sql-string",
                "path": "app.py",
                "start": {"line": 42},
                "end": {"line": 44},
                "extra": {
                    "severity": "ERROR",
                    "message": "Tainted string reaches SQL execute.",
                    "lines": "cursor.execute(query)",
                },
            },
            # This one has no canonical mapping — should be filtered out.
            {
                "check_id": "style.python.line-too-long",
                "path": "app.py",
                "start": {"line": 100},
                "end": {"line": 100},
                "extra": {"severity": "INFO", "message": "line too long"},
            },
        ]
    }
    matches = _extract_matches(fake)
    assert len(matches) == 1
    m = matches[0]
    assert m.class_ == "sqli"
    assert m.file == "app.py"
    assert m.line == 42
    assert m.severity == "ERROR"
    assert m.origin == "signal:semgrep"


def test_extract_matches_empty_when_no_results():
    assert _extract_matches({}) == []
    assert _extract_matches({"results": []}) == []


# ── SemgrepMatch → slice-dict ──────────────────────────────────────────

def test_match_as_slice_dict_matches_datflowslice_shape():
    m = SemgrepMatch(
        file="app.py", line=42, end_line=42,
        check_id="python.flask.security.injection.tainted-sql-string",
        class_="sqli", severity="ERROR",
        message="Tainted string reaches SQL execute.",
        snippet="cursor.execute(query)",
    )
    d = m.as_slice_dict()
    assert d["file"] == "app.py"
    assert d["sink"]["class"] == "sqli"
    assert d["sink"]["line"] == 42
    assert d["sanitized"] is False
    assert d["external_signal"] is True
    assert d["source"]["origin"].startswith("signal:semgrep")
    assert "semgrep" in d["reason"]


# ── graceful degradation ────────────────────────────────────────────────

def test_adapter_returns_empty_when_semgrep_missing(monkeypatch):
    """When the CLI is not on PATH, .scan() returns [] and never raises."""
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.shutil.which",
        lambda _cmd: None,
    )
    a = SemgrepAdapter()
    assert a.available() is False
    assert a.scan(Path(".")) == []


def test_adapter_returns_empty_on_subprocess_timeout(monkeypatch, tmp_path):
    """Timeout mid-scan must not crash the sweep."""

    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=30)

    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.shutil.which",
        lambda _cmd: "/usr/local/bin/semgrep",
    )
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        boom,
    )
    assert SemgrepAdapter().scan(tmp_path) == []


# ── operator switches ───────────────────────────────────────────────────

def test_env_off_switch_makes_adapter_unavailable(monkeypatch, tmp_path):
    """SPOTLIGHT_SEMGREP=off short-circuits before any subprocess work."""
    _fake_which(monkeypatch)
    monkeypatch.setenv(ENV_MODE, "off")

    def never(*a, **kw):  # pragma: no cover - the point is that it never runs
        raise AssertionError("semgrep must not be invoked when switched off")

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", never)

    a = SemgrepAdapter()
    assert a.mode == "off"
    assert a.available() is False
    assert a.scan(tmp_path) == []
    assert a.status == STATUS_DISABLED
    assert a.usable() is False
    assert "off" in a.describe()


def test_env_off_switch_is_case_and_whitespace_tolerant(monkeypatch):
    _fake_which(monkeypatch)
    monkeypatch.setenv(ENV_MODE, "  OFF ")
    assert SemgrepAdapter().available() is False


def test_unknown_mode_falls_back_to_auto(monkeypatch):
    _fake_which(monkeypatch)
    monkeypatch.setenv(ENV_MODE, "maybe")
    a = SemgrepAdapter()
    assert a.mode == "auto"
    assert a.available() is True


def test_default_config_is_the_community_rulepack(monkeypatch):
    _fake_which(monkeypatch)
    assert SemgrepAdapter().config == DEFAULT_CONFIG


def test_env_config_override_points_at_local_rules(monkeypatch, tmp_path):
    """Air-gapped installs vendor a ruleset dir and skip the registry."""
    rules = tmp_path / "vendored-rules"
    rules.mkdir()
    monkeypatch.setenv(ENV_CONFIG, str(rules))
    _fake_which(monkeypatch)
    seen: list[list[str]] = []

    def capture(cmd, **kw):
        seen.append(cmd)
        return _fake_proc(stdout=json.dumps({"results": []}))

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", capture)

    a = SemgrepAdapter()
    assert a.config == str(rules)
    a.scan(tmp_path)
    assert seen and "--config" in seen[0]
    assert seen[0][seen[0].index("--config") + 1] == str(rules)
    assert DEFAULT_CONFIG not in seen[0]


def test_explicit_config_argument_beats_env(monkeypatch):
    monkeypatch.setenv(ENV_CONFIG, "/etc/spotlight/rules")
    _fake_which(monkeypatch)
    assert SemgrepAdapter(config="p/ci").config == "p/ci"


def test_extra_configs_ride_alongside_the_base_config(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    seen: list[list[str]] = []

    def capture(cmd, **kw):
        seen.append(cmd)
        return _fake_proc(stdout=json.dumps({"results": []}))

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", capture)
    SemgrepAdapter().scan(tmp_path, extra_configs=["/tmp/plan-rules.yml"])
    assert seen[0].count("--config") == 2
    assert "/tmp/plan-rules.yml" in seen[0]


def test_version_check_is_disabled_on_every_invocation(monkeypatch, tmp_path):
    """The semgrep.dev version ping has no timeout of its own and blocks
    the whole scan on a proxied or air-gapped box, rules or no rules."""
    _fake_which(monkeypatch)
    seen: list[list[str]] = []

    def capture(cmd, **kw):
        seen.append(cmd)
        return _fake_proc(stdout=json.dumps({"results": []}))

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", capture)
    SemgrepAdapter().scan(tmp_path)
    assert "--disable-version-check" in seen[0]
    assert "--metrics=off" in seen[0]


# ── fast failure: latch, don't re-pay ───────────────────────────────────

def test_timeout_is_not_retried_for_every_subsequent_scan(monkeypatch, tmp_path, capsys):
    """One timeout takes Semgrep out for the rest of the process.

    This is the whole point: Recon builds a fresh adapter per sweep, so
    without the latch every sweep pays `timeout_s + 15` seconds of dead
    wait for a registry that is never coming back.
    """
    _fake_which(monkeypatch)
    calls = {"n": 0}

    def boom(*a, **kw):
        calls["n"] += 1
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=30)

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", boom)

    first = SemgrepAdapter()
    assert first.scan(tmp_path) == []
    assert first.status == STATUS_TIMEOUT
    # The scan, plus the config probe that establishes this is the
    # install's problem and not the target's (here the probe times out
    # too, so the ruleset genuinely cannot load).
    assert calls["n"] == 2
    spent = calls["n"]

    # A brand-new adapter — i.e. the next sweep — must not shell out again.
    for _ in range(3):
        nxt = SemgrepAdapter()
        assert nxt.available() is False
        assert nxt.scan(tmp_path) == []
        assert nxt.status == STATUS_SKIPPED
    assert calls["n"] == spent
    assert degraded_reason()


def test_timeout_logs_one_line_and_only_one(monkeypatch, tmp_path, capsys):
    _fake_which(monkeypatch)

    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=30)

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", boom)

    SemgrepAdapter().scan(tmp_path)
    SemgrepAdapter().scan(tmp_path)
    lines = [ln for ln in capsys.readouterr().out.splitlines() if "[semgrep]" in ln]
    assert len(lines) == 1
    assert "registry unreachable" in lines[0]
    assert "continuing without external signals" in lines[0]


def test_registry_error_on_stderr_degrades_without_a_timeout(monkeypatch, tmp_path, capsys):
    """A 403 through a proxy fails fast — and must still latch."""
    _fake_which(monkeypatch)
    stderr = "Failed to download config from https://semgrep.dev/c/p/default: 403 Forbidden"
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stderr=stderr, returncode=2),
    )
    a = SemgrepAdapter()
    assert a.scan(tmp_path) == []
    assert a.status == STATUS_UNREACHABLE
    assert "semgrep.dev" in (degraded_reason() or "")
    assert "registry unreachable" in capsys.readouterr().out


def test_local_config_failure_does_not_claim_the_registry_is_down(monkeypatch, tmp_path, capsys):
    _fake_which(monkeypatch)
    monkeypatch.setenv(ENV_CONFIG, "/opt/rules")

    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=30)

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", boom)
    SemgrepAdapter().scan(tmp_path)
    out = capsys.readouterr().out
    assert "scan failed" in out
    assert "registry unreachable" not in out


def test_silent_slow_registry_failure_still_degrades(monkeypatch, tmp_path, capsys):
    """`--quiet` swallows semgrep's error text: a blocked registry can
    surface as nothing but exit 2 and an empty stdout after a ~98s stall.
    That must still latch, or every sweep re-pays the fetch."""
    _fake_which(monkeypatch)
    # Pretend every subprocess in this test was slow, without sleeping.
    monkeypatch.setattr("spotlight.signals.semgrep_adapter._SLOW_FAILURE_S", 0.0)
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stdout="", stderr="", returncode=2),
    )
    a = SemgrepAdapter()
    assert a.scan(tmp_path) == []
    assert a.status == STATUS_UNREACHABLE
    assert degraded_reason()
    assert "registry unreachable" in capsys.readouterr().out

    nxt = SemgrepAdapter()
    assert nxt.available() is False
    assert nxt.status == STATUS_SKIPPED


def test_fast_failure_is_reported_but_not_latched(monkeypatch, tmp_path):
    """A malformed planner rulepack fails in milliseconds. Re-running it
    costs nothing, so it must not take Semgrep out for the whole process —
    the latch is there to avoid dead waits, not to punish config bugs."""
    _fake_which(monkeypatch)
    calls = {"n": 0}

    def fail_fast(*a, **kw):
        calls["n"] += 1
        return _fake_proc(stderr="invalid rule schema in rules.yml", returncode=2)

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", fail_fast)

    a = SemgrepAdapter()
    assert a.scan(tmp_path, extra_configs=["/tmp/plan-rules.yml"]) == []
    assert a.status == STATUS_ERROR
    assert "invalid rule schema" in a.status_detail
    assert degraded_reason() is None

    nxt = SemgrepAdapter()
    assert nxt.available() is True
    nxt.scan(tmp_path)
    assert calls["n"] == 2


def test_exit_zero_with_unparseable_output_does_not_latch(monkeypatch, tmp_path):
    """Odd, but not an infrastructure failure — don't take Semgrep out."""
    _fake_which(monkeypatch)
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stdout="not json", returncode=0),
    )
    a = SemgrepAdapter()
    assert a.scan(tmp_path) == []
    assert a.usable() is False
    assert degraded_reason() is None


def test_target_specific_timeout_does_not_disable_later_sweeps(monkeypatch, tmp_path):
    """A slow repository is that repository's problem.

    Spotlight scans repositories it does not control. A target crafted to
    exhaust semgrep's time budget must not suppress this worker's
    independent security signal for every later sweep of every other
    target — that would trade a slow scan for lost coverage everywhere
    else. The config probe is what tells the two apart.
    """
    _fake_which(monkeypatch)
    scans = {"n": 0}

    def scan_times_out_probe_is_fine(cmd, **kw):
        if _is_probe(cmd):
            # The ruleset resolves cleanly, so the install is healthy.
            return _fake_proc(stdout=json.dumps({"results": []}))
        scans["n"] += 1
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=30)

    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        scan_times_out_probe_is_fine,
    )

    hostile = SemgrepAdapter()
    assert hostile.scan(tmp_path) == []
    assert hostile.status == STATUS_TIMEOUT
    assert "target-specific" in hostile.status_detail
    # Nothing latched, so the next target is scanned normally.
    assert degraded_reason() is None

    nxt = SemgrepAdapter()
    assert nxt.available() is True
    assert nxt.scan(tmp_path) == []
    assert scans["n"] == 2, "the second sweep must still have run semgrep"


def test_rejected_extra_ruleset_does_not_cost_the_sweep_its_base_coverage(
    monkeypatch, tmp_path
):
    """A malformed planner rulepack must not zero out Semgrep entirely.

    Measured against semgrep 1.178: one rejected entry among the
    `--config` values drops EVERY rule, so `--config healthy --config
    broken` returns no results at all even though `--config healthy` alone
    matches. Recon feeds the planner's LLM-generated YAML through
    `extra_configs`, so this is reachable on any sweep where the planner
    emits something semgrep refuses.
    """
    _fake_which(monkeypatch)
    BAD = "/tmp/planner-rules.yml"
    seen: list[list[str]] = []
    hit = {
        "check_id": "python.flask.security.injection.tainted-sql-string",
        "path": "app.py",
        "start": {"line": 7},
        "end": {"line": 7},
        "extra": {"severity": "ERROR", "message": "sqli", "lines": "x"},
    }

    def semgrep(cmd, **kw):
        seen.append(cmd)
        if _is_probe(cmd):
            # The base config resolves; the planner rulepack does not.
            return _fake_proc(
                stdout=json.dumps({"results": []}),
                returncode=7 if BAD in cmd else 0,
            )
        if BAD in cmd:
            # The poisoned run: parseable JSON, non-zero, and no results.
            return _fake_proc(
                stdout=json.dumps(
                    {"results": [], "errors": [{"message": "invalid configuration file found"}]}
                ),
                returncode=7,
            )
        return _fake_proc(stdout=json.dumps({"results": [hit]}))

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", semgrep)

    a = SemgrepAdapter()
    matches = a.scan(tmp_path, extra_configs=[BAD])
    # The retry without the extras recovers what the base rules do find.
    assert len(matches) == 1
    assert matches[0].class_ == "sqli"
    assert a.status == STATUS_OK
    # Nothing latched: the extras are ephemeral (a fresh mkdtemp per sweep,
    # so no identity worth latching) and the base config is innocent.
    assert degraded_reason() is None
    # One retry, not a loop.
    assert sum(1 for c in seen if not _is_probe(c)) == 2


def test_extras_induced_timeout_is_blamed_on_the_extras(monkeypatch, tmp_path):
    """Probing only the base config called this "target-specific", so the
    same stall was paid again every sweep. The probe must cover the config
    set actually run."""
    _fake_which(monkeypatch)
    BAD = "/tmp/planner-rules.yml"
    scans: list[list[str]] = []

    def semgrep(cmd, **kw):
        if _is_probe(cmd):
            if BAD in cmd:
                raise subprocess.TimeoutExpired(cmd="semgrep", timeout=5)
            return _fake_proc(stdout=json.dumps({"results": []}))
        scans.append(cmd)
        if BAD in cmd:
            raise subprocess.TimeoutExpired(cmd="semgrep", timeout=30)
        return _fake_proc(stdout=json.dumps({"results": []}))

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", semgrep)

    a = SemgrepAdapter()
    assert a.scan(tmp_path, extra_configs=[BAD]) == []
    # Blamed on the extras, and the base-only retry succeeded.
    assert a.status == STATUS_OK
    assert len(scans) == 2 and BAD not in scans[1]
    # The innocent base config must not be latched over this.
    assert degraded_reason() is None
    assert SemgrepAdapter().available() is True


def test_latch_applies_only_to_the_config_that_failed(monkeypatch, tmp_path):
    """Switching to a healthy local ruleset restores scanning without a
    process restart."""
    _fake_which(monkeypatch)
    monkeypatch.setattr("spotlight.signals.semgrep_adapter._SLOW_FAILURE_S", 0.0)
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stdout="", stderr="", returncode=2),
    )
    broken = SemgrepAdapter(config="p/default")
    assert broken.scan(tmp_path) == []
    assert degraded_reason()

    assert SemgrepAdapter(config="p/default").available() is False
    # A different ruleset was never implicated.
    assert SemgrepAdapter(config=str(tmp_path / "vendored")).available() is True


def test_a_second_failing_config_latches_on_its_own(monkeypatch, tmp_path):
    """One config already being latched must not stop another from latching.

    With a single latch slot, whichever ruleset failed first blocked the
    other from ever recording its own failure — so the second config
    re-paid its dead wait on every sweep.
    """
    _fake_which(monkeypatch)
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="semgrep", timeout=30)
        ),
    )
    first = SemgrepAdapter(config="p/default")
    first.scan(tmp_path)
    assert SemgrepAdapter(config="p/default").available() is False

    second = SemgrepAdapter(config="p/ci")
    assert second.available() is True
    second.scan(tmp_path)
    # Its own failure is now recorded, rather than swallowed because some
    # other config got there first.
    assert SemgrepAdapter(config="p/ci").available() is False
    assert SemgrepAdapter(config="p/default").available() is False


def test_success_on_one_config_leaves_another_latched(monkeypatch, tmp_path):
    """A reachable ruleset says nothing about an unreachable one."""
    _fake_which(monkeypatch)
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="semgrep", timeout=30)
        ),
    )
    SemgrepAdapter(config="p/default").scan(tmp_path)
    assert SemgrepAdapter(config="p/default").available() is False

    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stdout=json.dumps({"results": []})),
    )
    healthy = SemgrepAdapter(config=str(tmp_path / "vendored"))
    assert healthy.scan(tmp_path) == []
    assert healthy.status == STATUS_OK
    # The broken registry config stays latched.
    assert SemgrepAdapter(config="p/default").available() is False


def test_latch_expires(monkeypatch, tmp_path):
    """A transient outage must recover on its own, not wait for a restart."""
    _fake_which(monkeypatch)
    # Drive the clock from the start, so the latch timestamp and the later
    # reading come from the same fake one.
    clock = [1000.0]
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.time.monotonic", lambda: clock[0]
    )
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="semgrep", timeout=30)
        ),
    )
    SemgrepAdapter().scan(tmp_path)
    assert degraded_reason()
    assert SemgrepAdapter().available() is False

    clock[0] += _LATCH_TTL_S - 1
    assert degraded_reason(), "must still hold just inside the window"

    clock[0] += 2
    assert degraded_reason() is None
    assert SemgrepAdapter().available() is True


def test_successful_scan_clears_the_latch(monkeypatch, tmp_path):
    """Including a forced `on` run — otherwise a successful recovery probe
    leaves Semgrep suppressed for everyone still on `auto`."""
    _fake_which(monkeypatch)
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="semgrep", timeout=30)
        ),
    )
    SemgrepAdapter().scan(tmp_path)
    assert degraded_reason()

    monkeypatch.setenv(ENV_MODE, "on")
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stdout=json.dumps({"results": []})),
    )
    forced = SemgrepAdapter()
    assert forced.scan(tmp_path) == []
    assert forced.status == STATUS_OK
    assert degraded_reason() is None

    monkeypatch.setenv(ENV_MODE, "auto")
    assert SemgrepAdapter().available() is True


def test_mode_on_retries_despite_the_latch(monkeypatch, tmp_path):
    """`on` is the escape hatch for operators who want a retry per sweep."""
    _fake_which(monkeypatch)
    calls = {"n": 0}

    def boom(*a, **kw):
        calls["n"] += 1
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=30)

    monkeypatch.setattr("spotlight.signals.semgrep_adapter.subprocess.run", boom)
    SemgrepAdapter().scan(tmp_path)
    spent = calls["n"]
    assert spent  # scan + config probe

    monkeypatch.setenv(ENV_MODE, "on")
    forced = SemgrepAdapter()
    assert forced.available() is True
    forced.scan(tmp_path)
    assert calls["n"] > spent


def test_successful_run_is_not_degraded(monkeypatch, tmp_path):
    _fake_which(monkeypatch)
    payload = {
        "results": [
            {
                "check_id": "python.flask.security.injection.tainted-sql-string",
                "path": "app.py",
                "start": {"line": 7},
                "end": {"line": 7},
                "extra": {"severity": "ERROR", "message": "sqli", "lines": "x"},
            }
        ]
    }
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stdout=json.dumps(payload)),
    )
    a = SemgrepAdapter()
    matches = a.scan(tmp_path)
    assert len(matches) == 1
    assert a.status == STATUS_OK
    assert a.usable() is True
    assert a.match_count == 1
    assert degraded_reason() is None
    assert "1 matches" in a.describe()


def test_nonzero_exit_with_parseable_json_is_not_reported_as_ok(monkeypatch, tmp_path):
    """Semgrep can fail and still print valid JSON.

    Reproduced against semgrep 1.178: one malformed file in a ruleset
    directory drops every rule in that config and exits 7 with
    `{"results": [], "errors": [...]}`. Reporting that as `ok — 0 matches`
    is the same lie this adapter exists to stop telling, so the exit code
    decides, not the parse.
    """
    _fake_which(monkeypatch)
    payload = {
        "results": [],
        "errors": [
            {"level": "error", "message": None},
            {
                "level": "error",
                "message": "invalid configuration file found (1 configs were invalid)",
            },
        ],
    }
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stdout=json.dumps(payload), returncode=7),
    )
    a = SemgrepAdapter()
    assert a.scan(tmp_path) == []
    assert a.status == STATUS_ERROR
    assert a.usable() is False
    # The operator needs to know WHICH knob is wrong, so semgrep's own
    # errors array is preferred over the bare exit code; the null-message
    # entry beside it must not crowd out the useful one.
    assert "invalid configuration file found" in a.status_detail
    # A config typo fails fast and costs nothing to retry, so it must not
    # take Semgrep out for the whole process.
    assert degraded_reason() is None


def test_nonzero_exit_still_returns_the_matches_it_found(monkeypatch, tmp_path):
    """A partial run's matches are real evidence — report them, but don't
    call the run clean. Discarding them would lose findings in a security
    scanner over one bad rule."""
    _fake_which(monkeypatch)
    payload = {
        "results": [
            {
                "check_id": "python.flask.security.injection.tainted-sql-string",
                "path": "app.py",
                "start": {"line": 7},
                "end": {"line": 7},
                "extra": {"severity": "ERROR", "message": "sqli", "lines": "x"},
            }
        ],
        "errors": [{"level": "error", "message": "some rules did not run"}],
    }
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stdout=json.dumps(payload), returncode=7),
    )
    a = SemgrepAdapter()
    matches = a.scan(tmp_path)
    assert len(matches) == 1
    assert matches[0].class_ == "sqli"
    assert a.status == STATUS_ERROR
    assert a.usable() is False
    assert "1 matches kept" in a.describe()
    assert degraded_reason() is None


def test_zero_matches_with_a_clean_run_is_not_degraded(monkeypatch, tmp_path):
    """A genuinely clean repo must not take Semgrep out of the process."""
    _fake_which(monkeypatch)
    monkeypatch.setattr(
        "spotlight.signals.semgrep_adapter.subprocess.run",
        lambda *a, **kw: _fake_proc(stdout=json.dumps({"results": []})),
    )
    a = SemgrepAdapter()
    assert a.scan(tmp_path) == []
    assert a.status == STATUS_OK
    assert degraded_reason() is None


def test_missing_binary_is_reported_as_unavailable_not_degraded(monkeypatch, tmp_path):
    _fake_which(monkeypatch, path=None)
    a = SemgrepAdapter()
    assert a.available() is False
    assert a.scan(tmp_path) == []
    assert a.usable() is False
    assert "unavailable" in a.describe()
    # Not on PATH is a deployment fact, not a transient failure — nothing
    # to latch, and nothing to log every sweep.
    assert degraded_reason() is None


# ── live end-to-end (env-gated) ─────────────────────────────────────────

@pytest.mark.skipif(
    not shutil.which("semgrep") or not os.environ.get("SPOTLIGHT_TEST_SEMGREP"),
    reason="requires SPOTLIGHT_TEST_SEMGREP=1 + semgrep on PATH",
)
def test_live_semgrep_scan_produces_sqli_on_vuln_bank_api():
    root = Path(__file__).resolve().parents[2] / "targets" / "vuln-bank-api"
    # `_AMBIENT_CONFIG` rather than the default: on an air-gapped box the
    # operator's ruleset is a vendored local directory, and `p/default`
    # could never resolve there.
    adapter = SemgrepAdapter(timeout_s=45, config=_AMBIENT_CONFIG)
    matches = adapter.scan(root)
    assert adapter.usable(), f"semgrep did not produce a usable run: {adapter.describe()}"
    assert any(m.class_ == "sqli" for m in matches), (
        f"expected at least one sqli match, got {[m.check_id for m in matches]}"
    )
