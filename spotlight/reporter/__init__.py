"""Spotlight Reporter — Attestation v2.

Turns a completed sweep into three shipping artifacts:

- ``attestation.json`` — the full structured attestation (rich, with meta,
  threat model, findings, exploit paths, Warden self-defense record, chain of
  custody, sandbox proofs, and metrics).
- ``report.md`` — a human-readable Markdown report the bank auditor can read
  end-to-end without the console.
- ``report.pdf`` — a printable PDF rendered from that Markdown so the same
  report can be attached to a PR, an email, or a compliance ticket.

Public surface:

- :class:`Reporter`
- :func:`render_json`
- :func:`render_markdown`
- :func:`render_pdf`
- :class:`PdfRenderError` — raised only from :func:`render_pdf` when the
  optional ReportLab dependency is missing; the sweep never crashes on this
  path (the orchestrator catches + logs).
"""
from .pdf import PdfRenderError, render_pdf
from .reporter import Reporter, render_json, render_markdown

__all__ = [
    "PdfRenderError",
    "Reporter",
    "render_json",
    "render_markdown",
    "render_pdf",
]
