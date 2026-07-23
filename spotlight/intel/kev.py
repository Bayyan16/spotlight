"""CISA Known Exploited Vulnerabilities catalog cache and exact-ID lookup."""
from __future__ import annotations

import argparse
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MAX_CATALOG_BYTES = 20 * 1024 * 1024


def cache_path() -> Path:
    configured = os.environ.get("SPOTLIGHT_KEV_CACHE", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "known_exploited_vulnerabilities.json"


def _validate_catalog(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("invalid CISA KEV catalog shape")
    count = data.get("count")
    if count is not None and int(count) != len(data["vulnerabilities"]):
        raise ValueError("CISA KEV count does not match vulnerability array")
    for item in data["vulnerabilities"]:
        if not isinstance(item, dict) or not _CVE_ID.fullmatch(str(item.get("cveID") or "")):
            raise ValueError("CISA KEV entry has an invalid cveID")
    return data


def sync_catalog(destination: Path | None = None) -> dict[str, Any]:
    target = destination or cache_path()
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        response = client.get(KEV_URL, headers={"User-Agent": "Spotlight-KEV/1.0"})
        response.raise_for_status()
        if len(response.content) > _MAX_CATALOG_BYTES:
            raise ValueError("CISA KEV catalog exceeded size limit")
        catalog = _validate_catalog(response.json())
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(catalog, sort_keys=True, separators=(",", ":")))
    temporary.replace(target)
    load_catalog.cache_clear()
    return catalog


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any] | None:
    path = cache_path()
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > _MAX_CATALOG_BYTES:
            return None
        return _validate_catalog(json.loads(path.read_text()))
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        return None


def _index() -> dict[str, dict[str, Any]]:
    catalog = load_catalog() or {}
    return {
        str(item["cveID"]).upper(): item
        for item in catalog.get("vulnerabilities", [])
    }


def get_kev_entry(cve_id: str) -> dict[str, Any] | None:
    normalized = cve_id.strip().upper()
    if not _CVE_ID.fullmatch(normalized):
        return None
    item = _index().get(normalized)
    return dict(item) if item else None


def kev_status() -> dict[str, Any]:
    catalog = load_catalog()
    path = cache_path()
    return {
        "available": catalog is not None,
        "source": KEV_URL,
        "catalog_version": catalog.get("catalogVersion") if catalog else None,
        "date_released": catalog.get("dateReleased") if catalog else None,
        "count": len(catalog.get("vulnerabilities", [])) if catalog else 0,
        "cache_updated_at": path.stat().st_mtime if path.is_file() else None,
    }


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Attach KEV metadata only for exact CVE IDs already on the finding.

    CWE, class, vendor-name, or fuzzy text matching is deliberately forbidden:
    KEV changes remediation priority; it is not evidence of reachability.
    """
    raw_ids = finding.get("cve") or finding.get("cves") or []
    if isinstance(raw_ids, str):
        raw_ids = [raw_ids]
    matches = [entry for cve in raw_ids if (entry := get_kev_entry(str(cve)))]
    if not matches:
        return finding
    enriched = dict(finding)
    intel = dict(enriched.get("intelligence") or {})
    intel["cisa_kev"] = matches
    intel["known_exploited"] = True
    intel["correlation"] = "exact-cve-id"
    enriched["intelligence"] = intel
    return enriched


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronize the official CISA KEV catalog")
    parser.add_argument("command", choices=("sync", "status"))
    args = parser.parse_args()
    if args.command == "sync":
        sync_catalog()
    print(json.dumps(kev_status(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
