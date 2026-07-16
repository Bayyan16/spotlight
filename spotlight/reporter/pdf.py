"""PDF renderer — takes a Markdown string and produces a printable PDF.

We deliberately keep this thin: ReportLab's Platypus is enough to give a
title page, a ToC, and section flowables that stack top-to-bottom on Letter
paper. Fonts are stock Helvetica so the PDF renders identically on every
platform without shipping font files.

If ReportLab isn't installed we raise :class:`PdfRenderError` instead of
crashing the whole sweep — the orchestrator catches this, logs it, and
continues writing JSON + Markdown. That way a lean deploy can skip the PDF
dep without losing the rest of the report.
"""
from __future__ import annotations

import io
import re


class PdfRenderError(RuntimeError):
    """Raised when the PDF cannot be produced (e.g. reportlab not installed).

    Callers should catch this at the orchestrator boundary — we never want a
    missing optional dependency to fail a sweep whose real work already
    completed.
    """


# Regex helpers — kept module-level so we don't recompile per call. The
# renderer walks the Markdown line-by-line and matches these; we don't need
# a full CommonMark parser for the shape of Markdown the reporter produces.
_H1 = re.compile(r"^# (.+)$")
_H2 = re.compile(r"^## (.+)$")
_H3 = re.compile(r"^### (.+)$")
_BULLET = re.compile(r"^- (.+)$")
_TABLE_ROW = re.compile(r"^\|(.+)\|$")


def _reportlab_or_raise():
    """Import ReportLab lazily so the base install doesn't need it.

    We import inside the render function so a project that never touches
    the PDF path pays zero import cost. If ReportLab is truly missing we
    raise a clean, actionable error the caller can log.
    """
    try:
        from reportlab.lib.pagesizes import letter  # noqa: F401
        from reportlab.lib.styles import getSampleStyleSheet  # noqa: F401
        from reportlab.platypus import (  # noqa: F401
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            PageBreak,
            Table,
            TableStyle,
        )
        from reportlab.lib import colors  # noqa: F401
    except ImportError as exc:  # pragma: no cover — exercised only in lean envs
        raise PdfRenderError("reportlab not installed") from exc
    import reportlab

    return reportlab


def _html_escape(text: str) -> str:
    """ReportLab's Paragraph parser treats input as a mini-HTML subset —
    ``<`` and ``&`` in raw text will explode it. Escape them defensively."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _inline_md_to_rl(text: str) -> str:
    """Turn `**bold**` and `_italic_` into ReportLab's <b> / <i> tags.

    Deliberately narrow: we only translate the two markers the Reporter
    actually emits. Full inline Markdown would be nice-to-have but isn't
    needed here — the auditor gets the same content via the Markdown file.
    """
    text = _html_escape(text)
    # Bold — non-greedy so `**a** **b**` stays as two separate runs.
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    # Italic — underscore-form so we don't collide with `*` in code snippets.
    text = re.sub(r"(?<!\w)_(.+?)_(?!\w)", r"<i>\1</i>", text)
    # Inline code — plain grey in PDF, using a monospace font for the run.
    text = re.sub(r"`([^`]+)`", r"<font face='Courier'>\1</font>", text)
    return text


def render_pdf(markdown: str) -> bytes:
    """Render Markdown → PDF bytes. Raises :class:`PdfRenderError` on missing dep.

    The template is: title page (first H1 as book title), then a ToC page
    listing every H2, then the flowables in order. Tables in the Markdown
    become real ReportLab Tables; bullets become spaced paragraphs.
    """
    _reportlab_or_raise()

    # Imports done AFTER the check so callers can rely on the exception
    # rather than an ImportError.
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        PageBreak,
        Table,
        TableStyle,
    )
    from reportlab.lib import colors

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    h2_style = styles["Heading2"]
    h3_style = styles["Heading3"]
    body_style = styles["BodyText"]
    bullet_style = styles["BodyText"]

    story = []
    lines = markdown.splitlines()
    h1: str | None = None
    h2_list: list[str] = []
    # Two-pass: first pull the H1 (title) + all H2s (ToC entries).
    for line in lines:
        m1 = _H1.match(line)
        if m1 and h1 is None:
            h1 = m1.group(1).strip()
            continue
        m2 = _H2.match(line)
        if m2:
            h2_list.append(m2.group(1).strip())

    # ── title page ───────────────────────────────────────────────────────
    story.append(Paragraph(_html_escape(h1 or "Spotlight Attestation"), title_style))
    story.append(Spacer(1, 24))
    story.append(
        Paragraph(
            "Generated by spotlight.reporter — Attestation v2",
            body_style,
        )
    )
    story.append(PageBreak())

    # ── ToC ──────────────────────────────────────────────────────────────
    story.append(Paragraph("Table of Contents", h2_style))
    story.append(Spacer(1, 12))
    for i, heading in enumerate(h2_list, start=1):
        story.append(Paragraph(f"{i}. {_html_escape(heading)}", body_style))
    story.append(PageBreak())

    # ── body ─────────────────────────────────────────────────────────────
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            story.append(Spacer(1, 6))
            i += 1
            continue

        if _H1.match(line):
            # Already rendered as title on cover — skip in body.
            i += 1
            continue

        m2 = _H2.match(line)
        if m2:
            story.append(Spacer(1, 12))
            story.append(Paragraph(_html_escape(m2.group(1).strip()), h2_style))
            i += 1
            continue

        m3 = _H3.match(line)
        if m3:
            story.append(Spacer(1, 8))
            story.append(Paragraph(_html_escape(m3.group(1).strip()), h3_style))
            i += 1
            continue

        # Table detection: two or more consecutive `| ... |` lines.
        if _TABLE_ROW.match(line):
            table_lines: list[str] = []
            while i < len(lines) and _TABLE_ROW.match(lines[i]):
                table_lines.append(lines[i])
                i += 1
            table = _lines_to_table(table_lines, Table, TableStyle, colors)
            if table is not None:
                story.append(table)
                story.append(Spacer(1, 8))
            continue

        m_bullet = _BULLET.match(line)
        if m_bullet:
            story.append(
                Paragraph(
                    "• " + _inline_md_to_rl(m_bullet.group(1).strip()),
                    bullet_style,
                )
            )
            i += 1
            continue

        # Plain paragraph (or blockquote — treat `> …` as body for now).
        text = line.lstrip("> ").rstrip()
        story.append(Paragraph(_inline_md_to_rl(text), body_style))
        i += 1

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        title=h1 or "Spotlight Attestation",
        author="Spotlight",
    )
    doc.build(story)
    return buf.getvalue()


def _lines_to_table(
    md_lines: list[str],
    Table,  # noqa: N803 — ReportLab class, kept PascalCase
    TableStyle,  # noqa: N803
    colors,
):
    """Convert a block of Markdown table lines into a ReportLab Table.

    We skip the separator row (the `|---|---|` one) and treat the first
    remaining row as the header. Returns None if there's no meaningful body,
    which lets the caller silently drop the block instead of raising.
    """
    rows: list[list[str]] = []
    for line in md_lines:
        stripped = line.strip().strip("|")
        cells = [c.strip() for c in stripped.split("|")]
        # Separator row = every cell is dashes.
        if cells and all(set(c) <= {"-", ":", " "} and c for c in cells):
            continue
        rows.append(cells)
    if len(rows) < 2:
        return None
    tbl = Table(rows, hAlign="LEFT")
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return tbl
