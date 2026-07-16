"""Cognition Sweep — OWASP LLM Top 10 static analysis for AI-layer code.

Exports:
  * `CognitionScanner` — the scanner entrypoint. Recon calls this after the
    classic code graph is built.
  * `CognitionFinding` — the finding shape emitted by the scanner.
  * `AgenticDataFlow` — the underlying slice shape (mirror of
    `sg_core.DataFlowSlice`) so Investigators can consume it identically.
"""
from .dataflow import AgenticDataFlow, find_agentic_dataflow
from .scanner import CognitionFinding, CognitionScanner

__all__ = [
    "CognitionScanner",
    "CognitionFinding",
    "AgenticDataFlow",
    "find_agentic_dataflow",
]
