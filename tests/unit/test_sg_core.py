"""sg-core unit tests.

These are the fact-layer tests. They must pass for both the positive fixture
(vuln-bank-api: SQLi reachable) and the negative fixture (clean-bank-api:
parameterized, unreachable). This is what stops the "yes machine" failure
mode.
"""
from pathlib import Path

import pytest

from spotlight.sg_core import CodeGraph

ROOT = Path(__file__).resolve().parents[2]
VULN_APP = ROOT / "targets" / "vuln-bank-api" / "app.py"
CLEAN_APP = ROOT / "targets" / "clean-bank-api" / "app.py"


def test_vuln_fixture_produces_reachable_sqli_slice():
    graph = CodeGraph.build([VULN_APP])
    reachable = graph.reachable_slices()
    sqli = [s for s in reachable if s.sink.class_ == "sqli"]
    assert len(sqli) == 1, f"expected exactly 1 reachable SQLi slice, got {len(sqli)}"
    slice_ = sqli[0]
    assert slice_.function == "get_account"
    assert slice_.source.name == "username"
    assert slice_.source.origin.startswith("param:")
    assert "execute" in slice_.sink.callee
    assert not slice_.sanitized


def test_clean_fixture_produces_zero_reachable_sqli_slices():
    """The precision negative — parameterized query must NOT be reported."""
    graph = CodeGraph.build([CLEAN_APP])
    reachable = graph.reachable_slices()
    sqli = [s for s in reachable if s.sink.class_ == "sqli"]
    assert sqli == [], (
        f"parameterized query was flagged as reachable: {[s.to_dict() for s in sqli]}"
    )


def test_clean_fixture_sees_sink_but_marks_it_sanitized():
    """We should still SEE the sink; we just don't PROMOTE it. That's the
    difference between grep and sg-core."""
    graph = CodeGraph.build([CLEAN_APP])
    all_slices = graph.slices()
    sqli = [s for s in all_slices if s.sink.class_ == "sqli"]
    assert len(sqli) == 1
    assert sqli[0].sanitized is True
    assert "parameterized" in sqli[0].reason


def test_slice_serializes_to_dict():
    graph = CodeGraph.build([VULN_APP])
    slices = graph.reachable_slices()
    d = slices[0].to_dict()
    assert set(d) == {"file", "function", "source", "sink", "sanitized", "reason"}
    assert d["sink"]["class"] == "sqli"


def test_route_detection():
    from spotlight.sg_core.parser import parse_python

    pf = parse_python(VULN_APP)
    assert "get_account" in pf.route_decorators
    assert pf.route_decorators["get_account"] == ["/accounts/<username>"]
