"""Live architecture-doc hosting.

Serves `docs/SPOTLIGHT_ARCHITECTURE.md` as an HTML page under a stable
URL. The doc bundles into the API image via `COPY docs ./docs`; every
push to main triggers a Railway rebuild-and-deploy, so the same URL
always shows the latest committed version — a "live link" in the
deploy-on-push sense.

Routes:
  GET /docs/architecture                        — rendered HTML
  GET /docs/architecture.md                     — raw markdown
  GET /docs/architecture/diagrams/{filename}    — diagram assets
  GET /docs/architecture/meta                   — build metadata JSON

All public (no auth required); the content is a description of the
system's design, not sensitive.
"""
from __future__ import annotations

import hashlib
import html
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import markdown as md
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse


router = APIRouter()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _doc_path() -> Path:
    return _repo_root() / "docs" / "SPOTLIGHT_ARCHITECTURE.md"


def _diagrams_root() -> Path:
    return _repo_root() / "docs" / "diagrams"


# Pandoc attribute syntax like `{ width=100% }` after images — standard
# markdown doesn't parse this; strip it before rendering so the alt-text
# and the attribute don't both appear.
_PANDOC_ATTR = re.compile(r"\){[^}]*}")

# Rewrite relative diagram references so the browser fetches them from
# the sibling asset endpoint instead of a broken relative path.
_DIAGRAM_REF = re.compile(r"(!\[[^\]]*\]\()diagrams/([^)\s]+)")


def _load_and_normalize() -> tuple[str, dict[str, Any]]:
    """Return (markdown_text, meta) — meta includes size, mtime, and
    a stable sha256 of the source content."""
    path = _doc_path()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="architecture doc not present in this deployment")
    raw = path.read_text(encoding="utf-8")
    normalized = _PANDOC_ATTR.sub(")", raw)
    normalized = _DIAGRAM_REF.sub(r"\1/docs/architecture/diagrams/\2", normalized)
    stat = path.stat()
    meta = {
        "source_path": "docs/SPOTLIGHT_ARCHITECTURE.md",
        "byte_size": stat.st_size,
        "mtime_iso": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "content_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        # GIT_SHA is optionally injected at build time by CI. Absent in
        # dev; a "dev" placeholder makes it clear the build wasn't pinned.
        "git_sha": os.environ.get("GIT_SHA", "dev"),
    }
    return normalized, meta


_HTML_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Spotlight — Architecture</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #ffffff; --fg: #111; --muted: #667; --accent: #0b5fff;
      --code-bg: #f5f5f7; --border: #e5e5ea;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{ --bg: #0e0f13; --fg: #e7e7ea; --muted: #9aa; --accent: #6ea1ff;
              --code-bg: #1a1c22; --border: #2a2c33; }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; padding: 0; background: var(--bg); color: var(--fg);
      font: 16px/1.55 -apple-system, "SF Pro", "Segoe UI", system-ui, sans-serif;
    }}
    header.meta {{
      position: sticky; top: 0; z-index: 10;
      padding: 10px 20px; background: var(--bg);
      border-bottom: 1px solid var(--border);
      font-size: 12px; color: var(--muted); display: flex; gap: 16px; flex-wrap: wrap;
    }}
    header.meta a {{ color: var(--accent); text-decoration: none; }}
    header.meta code {{ background: var(--code-bg); padding: 1px 6px; border-radius: 4px; font-size: 11px; }}
    main {{ max-width: 960px; margin: 0 auto; padding: 32px 24px 96px; }}
    h1, h2, h3, h4 {{ line-height: 1.25; margin-top: 1.6em; }}
    h1 {{ font-size: 2rem; }} h2 {{ font-size: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: .2em; }}
    p, li {{ color: var(--fg); }}
    a {{ color: var(--accent); }}
    code {{ font-family: "SF Mono", ui-monospace, Menlo, monospace; background: var(--code-bg); padding: 2px 5px; border-radius: 4px; font-size: 92%; }}
    pre {{ background: var(--code-bg); padding: 14px 18px; border-radius: 8px; overflow-x: auto; }}
    pre code {{ background: transparent; padding: 0; }}
    img {{ max-width: 100%; height: auto; display: block; margin: 20px auto; }}
    table {{ border-collapse: collapse; margin: 20px 0; }}
    th, td {{ border: 1px solid var(--border); padding: 6px 10px; text-align: left; }}
    blockquote {{ border-left: 4px solid var(--border); margin: 12px 0; padding: 4px 16px; color: var(--muted); }}
    hr {{ border: 0; border-top: 1px solid var(--border); margin: 32px 0; }}
    .yaml-frontmatter {{ display: none; }}
  </style>
</head>
<body>
  <header class="meta">
    <span>Spotlight architecture</span>
    <span>build <code>{git_sha}</code></span>
    <span>updated {mtime_iso}</span>
    <span>sha256 <code>{sha256_short}</code></span>
    <span style="margin-left: auto;">
      <a href="/docs/architecture.md">source (.md)</a> ·
      <a href="/docs/architecture/meta">meta (json)</a>
    </span>
  </header>
  <main>{body}</main>
</body>
</html>
"""


def _render_html(markdown_text: str, meta: dict[str, Any]) -> str:
    # Strip YAML frontmatter if present — pandoc uses `---` fenced blocks
    # for metadata that shouldn't render.
    text = markdown_text
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            text = text[end + 5:]
    body = md.markdown(
        text,
        extensions=["fenced_code", "tables", "toc", "attr_list", "sane_lists"],
        output_format="html5",
    )
    return _HTML_SHELL.format(
        body=body,
        git_sha=html.escape(str(meta["git_sha"])),
        mtime_iso=html.escape(meta["mtime_iso"]),
        sha256_short=html.escape(meta["content_sha256"][:12]),
    )


@router.get("/docs/architecture", response_class=HTMLResponse)
def get_architecture_html() -> HTMLResponse:
    text, meta = _load_and_normalize()
    return HTMLResponse(_render_html(text, meta))


@router.get("/docs/architecture.md", response_class=PlainTextResponse)
def get_architecture_markdown() -> PlainTextResponse:
    path = _doc_path()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="architecture doc not present in this deployment")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown; charset=utf-8")


@router.get("/docs/architecture/meta")
def get_architecture_meta() -> JSONResponse:
    _, meta = _load_and_normalize()
    return JSONResponse(meta)


_ALLOWED_DIAGRAM_EXTS = {".svg", ".png", ".dot", ".jpg", ".jpeg"}
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@router.get("/docs/architecture/diagrams/{filename}")
def get_architecture_diagram(filename: str) -> FileResponse:
    # Whitelist filename characters and length — refuses `..`, `/`, `\`,
    # URL-decoded traversal, and anything with a slash smuggled in.
    if not _SAFE_FILENAME.fullmatch(filename):
        raise HTTPException(status_code=400, detail="invalid diagram filename")
    root = _diagrams_root().resolve()
    candidate = (root / filename).resolve()
    # Belt-and-braces: even after the regex, verify the resolved path
    # stays inside the diagrams dir.
    if root not in candidate.parents:
        raise HTTPException(status_code=400, detail="invalid diagram path")
    if candidate.suffix.lower() not in _ALLOWED_DIAGRAM_EXTS:
        raise HTTPException(status_code=400, detail="unsupported diagram type")
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="diagram not found")
    media_type = {
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".dot": "text/vnd.graphviz",
    }[candidate.suffix.lower()]
    return FileResponse(candidate, media_type=media_type)
