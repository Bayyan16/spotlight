import json

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
