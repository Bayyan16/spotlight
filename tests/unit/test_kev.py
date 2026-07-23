import hashlib
import json

import httpx
import pytest

from spotlight.intel import kev


CATALOG = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "test-1",
    "dateReleased": "2026-07-22T00:00:00.0000Z",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Example",
            "product": "Widget",
            "vulnerabilityName": "Example vulnerability",
            "dateAdded": "2026-07-01",
            "shortDescription": "Example",
            "requiredAction": "Apply vendor mitigations.",
            "dueDate": "2026-07-22",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-78"],
        }
    ],
}


def _install_catalog(tmp_path, monkeypatch):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps(CATALOG))
    monkeypatch.setenv("SPOTLIGHT_KEV_CACHE", str(path))
    kev.load_catalog.cache_clear()


# ---------- Correlation invariants (pre-existing behavior) ----------


def test_exact_cve_correlation_adds_known_exploited_metadata(tmp_path, monkeypatch):
    _install_catalog(tmp_path, monkeypatch)
    finding = {"id": "SPOT-X", "class": "cmdi", "cve": ["CVE-2024-0001"]}

    enriched = kev.enrich_finding(finding)

    assert enriched["intelligence"]["known_exploited"] is True
    assert enriched["intelligence"]["correlation"] == "exact-cve-id"
    assert finding.get("intelligence") is None


def test_cwe_or_class_alone_never_creates_kev_match(tmp_path, monkeypatch):
    _install_catalog(tmp_path, monkeypatch)
    finding = {"id": "SPOT-X", "class": "cmdi", "cwe": "CWE-78"}

    assert kev.enrich_finding(finding) is finding


def test_invalid_catalog_count_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps({**CATALOG, "count": 2}))
    monkeypatch.setenv("SPOTLIGHT_KEV_CACHE", str(path))
    kev.load_catalog.cache_clear()

    assert kev.load_catalog() is None
    assert kev.kev_status()["available"] is False


# ---------- P4.1a: provenance + content hash ----------


def _mock_httpx_client(*, catalog_json: str, etag: str | None = None, last_modified: str | None = None):
    """Return a class we can substitute for httpx.Client that yields a
    deterministic response containing catalog_json + given headers."""
    class _Response:
        content = catalog_json.encode("utf-8")
        headers = {}
        if etag is not None:
            headers["ETag"] = etag
        if last_modified is not None:
            headers["Last-Modified"] = last_modified

        def raise_for_status(self):
            pass

        def json(self):
            return json.loads(catalog_json)

    class _Client:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, headers=None):
            return _Response()

    return _Client


def test_sync_writes_provenance_sidecar_with_expected_fields(tmp_path, monkeypatch):
    catalog_json = json.dumps(CATALOG)
    monkeypatch.setattr(kev, "httpx", type("H", (), {"Client": _mock_httpx_client(
        catalog_json=catalog_json,
        etag='"abc-123"',
        last_modified="Mon, 22 Jul 2026 15:12:01 GMT",
    )}))
    target = tmp_path / "kev.json"
    monkeypatch.setenv("SPOTLIGHT_KEV_CACHE", str(target))
    kev.load_catalog.cache_clear()

    kev.sync_catalog()

    provenance = kev.load_provenance()
    assert provenance is not None
    assert provenance["source_url"] == kev.KEV_URL
    assert provenance["http_etag"] == '"abc-123"'
    assert provenance["http_last_modified"] == "Mon, 22 Jul 2026 15:12:01 GMT"
    assert provenance["catalog_version"] == "test-1"
    assert provenance["date_released"] == "2026-07-22T00:00:00.0000Z"
    assert provenance["count"] == 1
    assert provenance["byte_size"] > 0
    assert len(provenance["content_sha256"]) == 64  # SHA-256 hex length
    # fetched_at is a valid ISO timestamp
    from datetime import datetime
    datetime.fromisoformat(provenance["fetched_at"])


def test_sync_records_sha256_that_matches_file_bytes(tmp_path, monkeypatch):
    catalog_json = json.dumps(CATALOG)
    monkeypatch.setattr(kev, "httpx", type("H", (), {"Client": _mock_httpx_client(
        catalog_json=catalog_json,
    )}))
    target = tmp_path / "kev.json"
    monkeypatch.setenv("SPOTLIGHT_KEV_CACHE", str(target))
    kev.load_catalog.cache_clear()

    kev.sync_catalog()

    on_disk = target.read_bytes()
    expected = hashlib.sha256(on_disk).hexdigest()
    provenance = kev.load_provenance()
    assert provenance["content_sha256"] == expected


def test_provenance_absent_when_never_synced(tmp_path, monkeypatch):
    _install_catalog(tmp_path, monkeypatch)  # writes catalog but not provenance
    assert kev.load_provenance() is None


def test_verify_integrity_returns_verified_after_sync(tmp_path, monkeypatch):
    catalog_json = json.dumps(CATALOG)
    monkeypatch.setattr(kev, "httpx", type("H", (), {"Client": _mock_httpx_client(
        catalog_json=catalog_json,
    )}))
    target = tmp_path / "kev.json"
    monkeypatch.setenv("SPOTLIGHT_KEV_CACHE", str(target))
    kev.load_catalog.cache_clear()
    kev.sync_catalog()

    verdict = kev.verify_catalog_integrity()

    assert verdict["verified"] is True
    assert verdict["expected"] == verdict["actual"]


def test_verify_integrity_flags_tampered_catalog(tmp_path, monkeypatch):
    """Post-sync, modifying the catalog file must be caught by the
    SHA-256 comparison against the provenance record."""
    catalog_json = json.dumps(CATALOG)
    monkeypatch.setattr(kev, "httpx", type("H", (), {"Client": _mock_httpx_client(
        catalog_json=catalog_json,
    )}))
    target = tmp_path / "kev.json"
    monkeypatch.setenv("SPOTLIGHT_KEV_CACHE", str(target))
    kev.load_catalog.cache_clear()
    kev.sync_catalog()

    # Tamper: append a byte to the catalog file.
    tampered = target.read_bytes() + b"\n"
    target.write_bytes(tampered)

    verdict = kev.verify_catalog_integrity()

    assert verdict["verified"] is False
    assert "sha256 mismatch" in verdict["reason"]
    assert verdict["expected"] != verdict["actual"]


def test_verify_integrity_reports_missing_provenance(tmp_path, monkeypatch):
    """Deployments that haven't run the new sync path yet have a catalog
    but no sidecar. Verification says 'no provenance sidecar' rather
    than crashing."""
    _install_catalog(tmp_path, monkeypatch)
    verdict = kev.verify_catalog_integrity()
    assert verdict["verified"] is False
    assert verdict["reason"] == "no provenance sidecar"


def test_verify_integrity_reports_missing_catalog(tmp_path, monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_KEV_CACHE", str(tmp_path / "does-not-exist.json"))
    kev.load_catalog.cache_clear()
    verdict = kev.verify_catalog_integrity()
    assert verdict["verified"] is False
    assert verdict["reason"] == "catalog file missing"


def test_kev_status_exposes_provenance_and_integrity(tmp_path, monkeypatch):
    catalog_json = json.dumps(CATALOG)
    monkeypatch.setattr(kev, "httpx", type("H", (), {"Client": _mock_httpx_client(
        catalog_json=catalog_json, etag='"xyz"',
    )}))
    target = tmp_path / "kev.json"
    monkeypatch.setenv("SPOTLIGHT_KEV_CACHE", str(target))
    kev.load_catalog.cache_clear()
    kev.sync_catalog()

    status = kev.kev_status()

    assert status["available"] is True
    assert status["provenance"] is not None
    assert status["provenance"]["http_etag"] == '"xyz"'
    assert status["integrity"]["verified"] is True


def test_kev_status_provenance_null_when_never_synced(tmp_path, monkeypatch):
    _install_catalog(tmp_path, monkeypatch)  # catalog only
    status = kev.kev_status()
    assert status["available"] is True
    assert status["provenance"] is None
    assert status["integrity"]["verified"] is False
    assert status["integrity"]["reason"] == "no provenance sidecar"


def test_provenance_path_sits_next_to_cache_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SPOTLIGHT_KEV_CACHE", str(tmp_path / "kev.json"))
    assert kev.provenance_path() == tmp_path / "kev.json.provenance.json"
