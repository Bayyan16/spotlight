"""sg-core JS/TS unit tests.

Same precision + recall bar we hold Python to. Vuln-node-api must produce
exactly one reachable SQLi slice; clean-node-api must produce zero.
"""
from pathlib import Path

from spotlight.sg_core import CodeGraph
from spotlight.sg_core.js_parser import _is_parameterized_sql_call, parse_js_ts

ROOT = Path(__file__).resolve().parents[2]
VULN_JS = ROOT / "targets" / "vuln-node-api" / "app.js"
CLEAN_JS = ROOT / "targets" / "clean-node-api" / "app.js"


def test_js_vuln_produces_reachable_sqli_slice():
    slices = parse_js_ts(VULN_JS)
    sqli = [s for s in slices if s.sink.class_ == "sqli" and not s.sanitized]
    assert len(sqli) == 1, f"expected 1 reachable SQLi slice, got {len(sqli)}: {[s.to_dict() for s in sqli]}"
    slice_ = sqli[0]
    assert "accounts" in slice_.function
    assert slice_.source.origin.startswith("express:")
    assert "prepare" in slice_.sink.callee or "execute" in slice_.sink.callee


def test_js_clean_produces_zero_reachable_sqli_slices():
    slices = parse_js_ts(CLEAN_JS)
    sqli = [s for s in slices if s.sink.class_ == "sqli" and not s.sanitized]
    assert sqli == [], f"clean fixture flagged: {[s.to_dict() for s in sqli]}"


def test_js_clean_sees_sink_but_marks_it_sanitized():
    """Either the slice is emitted and sanitized, OR the parameterized
    prepare()...all(bound) pattern is recognized statically as safe and no
    slice is emitted. Both are 'not reachable' — that's the guarantee."""
    slices = parse_js_ts(CLEAN_JS)
    sqli = [s for s in slices if s.sink.class_ == "sqli"]
    if sqli:
        assert all(s.sanitized for s in sqli)


def test_codegraph_dispatches_js_and_py_together(tmp_path):
    graph = CodeGraph.build([VULN_JS, ROOT / "targets" / "vuln-bank-api" / "app.py"])
    reachable = [s for s in graph.reachable_slices() if s.sink.class_ == "sqli"]
    files = {Path(s.file).name for s in reachable}
    assert "app.js" in files
    assert "app.py" in files


def test_parameterized_heuristic_detects_bound_params():
    assert _is_parameterized_sql_call('"SELECT * FROM t WHERE x = ?", [id]') is True
    assert _is_parameterized_sql_call("`SELECT * FROM t WHERE x = ?`, [id]") is True
    # Template with interpolation is NOT parameterized:
    assert _is_parameterized_sql_call("`SELECT * WHERE x = ${x}`, []") is False
    # Concat is not parameterized:
    assert _is_parameterized_sql_call('"SELECT * WHERE x = " + x, []') is False
    # Single-arg literal is not parameterized (no bound params):
    assert _is_parameterized_sql_call('"SELECT * FROM t"') is False
