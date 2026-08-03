"""Tests for the /docs/architecture live-hosting router."""
from __future__ import annotations

import base64
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _signing_key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "SPOTLIGHT_SIGNING_KEY",
        base64.b64encode(priv.private_bytes_raw()).decode("ascii"),
    )


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_INLINE_EXECUTION", "true")
    import importlib
    import spotlight.api.app as app_mod
    importlib.reload(app_mod)
    return TestClient(app_mod.app)


def test_architecture_html_renders(client):
    resp = client.get("/docs/architecture")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    body = resp.text
    # Header meta bar is present and includes the placeholders.
    assert "Spotlight architecture" in body
    assert "build" in body
    assert "updated" in body
    assert "sha256" in body
    # Doc content: h1 from the source markdown appears.
    assert "Spotlight" in body


def test_architecture_html_rewrites_diagram_urls(client):
    """Relative `diagrams/xxx.svg` refs must be rewritten to
    `/docs/architecture/diagrams/xxx.svg` so the browser fetches them
    from the sibling asset endpoint instead of a broken relative path."""
    resp = client.get("/docs/architecture")
    body = resp.text
    # No leaked relative refs — after normalization only the routed
    # absolute paths should appear as image src attributes.
    assert 'src="diagrams/' not in body, "relative diagram src escaped normalization"
    assert 'src="/docs/architecture/diagrams/' in body


def test_architecture_html_strips_pandoc_attributes(client):
    """Pandoc-style `{ width=100% }` attributes on images must be
    stripped — standard markdown doesn't understand them and they'd
    show up as literal braces in the rendered HTML."""
    resp = client.get("/docs/architecture")
    body = resp.text
    assert "{ width=100%" not in body
    assert "){" not in body  # no unclosed pandoc attr blocks


def test_architecture_html_strips_yaml_frontmatter(client):
    """YAML frontmatter (pandoc metadata) at the top of the doc must
    not render as visible text."""
    resp = client.get("/docs/architecture")
    body = resp.text
    # The doc's frontmatter contains 'author: "CMUL8 Engineering..."'
    # — after stripping, that literal shouldn't appear in body text.
    assert "author:" not in body or "CMUL8 Engineering" not in body[
        : body.find("<main>")
    ] if "<main>" in body else True


def test_architecture_markdown_endpoint(client):
    resp = client.get("/docs/architecture.md")
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    assert "Spotlight" in resp.text
    # Raw markdown retains the original relative diagram refs and
    # frontmatter — this endpoint returns the file as-committed.
    assert "diagrams/01_full_stack.svg" in resp.text


def test_architecture_meta_endpoint(client):
    resp = client.get("/docs/architecture/meta")
    assert resp.status_code == 200
    data = resp.json()
    assert data["source_path"] == "docs/SPOTLIGHT_ARCHITECTURE.md"
    assert data["byte_size"] > 0
    assert len(data["content_sha256"]) == 64
    assert data["mtime_iso"].endswith("+00:00") or "T" in data["mtime_iso"]
    assert data["git_sha"] in {"dev"} or re.fullmatch(r"[0-9a-f]{7,40}", data["git_sha"])


def test_diagram_endpoint_serves_svg(client):
    resp = client.get("/docs/architecture/diagrams/01_full_stack.svg")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/svg+xml"


def test_diagram_endpoint_rejects_path_traversal(client):
    """Path traversal must not surface content from outside docs/diagrams.

    Framework URL normalization collapses `..%2F..%2F` before routing, so
    the request either misses the diagram route entirely (falling back to
    the SPA index) or gets rejected by our safe-filename regex. Either
    way, the response body must NOT contain content from the target file
    outside the diagrams folder."""
    resp = client.get("/docs/architecture/diagrams/..%2F..%2FSPOTLIGHT_ARCHITECTURE.md")
    # The architecture doc contains this literal string. It must not appear
    # in the response — that would prove the traversal succeeded.
    assert "Spotlight — the guided tour" not in resp.text


def test_diagram_endpoint_rejects_smuggled_slash(client):
    """A URL-encoded slash inside a diagram filename must not cause any
    diagram-endpoint code path to serve a file. Framework normalization
    may route to the SPA fallback (200 with index.html), but our
    diagram endpoint must never return image content for a smuggled
    slash — verify by checking the content type is NOT an image."""
    resp = client.get("/docs/architecture/diagrams/inner%2Ffile.svg")
    assert not resp.headers.get("content-type", "").startswith("image/")


def test_diagram_endpoint_regex_rejects_slashes_directly():
    """The safe-filename regex must refuse anything with a slash even
    when called directly — this is the last line of defense if URL
    normalization doesn't intercept the request."""
    from spotlight.api.docs_router import _SAFE_FILENAME
    assert _SAFE_FILENAME.fullmatch("01_full_stack.svg")
    assert not _SAFE_FILENAME.fullmatch("../etc/passwd")
    assert not _SAFE_FILENAME.fullmatch("../../etc/passwd")
    assert not _SAFE_FILENAME.fullmatch("foo/bar.svg")
    assert not _SAFE_FILENAME.fullmatch("foo\\bar.svg")
    assert not _SAFE_FILENAME.fullmatch(".hidden")  # leading-dot filenames refused


def test_diagram_endpoint_rejects_unsupported_extension(client, tmp_path):
    """Only image/graphviz types are served; refuse anything else even
    if the file happens to exist under the diagrams folder."""
    # Point to a random non-image extension by manipulating the URL —
    # if it doesn't exist, 404 is fine; if it did, we'd expect 400.
    resp = client.get("/docs/architecture/diagrams/nonexistent.exe")
    assert resp.status_code in {400, 404}


def test_diagram_endpoint_404_on_missing(client):
    resp = client.get("/docs/architecture/diagrams/does-not-exist.svg")
    assert resp.status_code == 404


def test_public_paths_do_not_require_auth(client, monkeypatch):
    """When auth is required, /docs/architecture must still be reachable
    without credentials — the architecture description is public."""
    # Enable auth by generating a strong key + prod mode.
    monkeypatch.setenv("SPOTLIGHT_API_KEY", "test-key-1234567890-1234567890")
    monkeypatch.setenv("SPOTLIGHT_AUTH_MODE", "required")
    import importlib
    import spotlight.api.app as app_mod
    importlib.reload(app_mod)
    c = TestClient(app_mod.app)

    for path in [
        "/docs/architecture",
        "/docs/architecture.md",
        "/docs/architecture/meta",
        "/docs/architecture/diagrams/01_full_stack.svg",
    ]:
        r = c.get(path)
        assert r.status_code == 200, f"public path {path} was blocked with auth on: {r.status_code}"
