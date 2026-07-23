"""CISA Known Exploited Vulnerabilities catalog cache and exact-ID lookup."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import httpx


log = logging.getLogger("spotlight.intel.kev")


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MAX_CATALOG_BYTES = 20 * 1024 * 1024


def cache_path() -> Path:
    configured = os.environ.get("SPOTLIGHT_KEV_CACHE", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "known_exploited_vulnerabilities.json"


def provenance_path() -> Path:
    """Sidecar file recording where/when/how the catalog was fetched.
    Sits next to the catalog itself so a mounted persistent volume
    carries both together."""
    return cache_path().with_suffix(cache_path().suffix + ".provenance.json")


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
        etag = response.headers.get("ETag")
        last_modified = response.headers.get("Last-Modified")
    target.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(catalog, sort_keys=True, separators=(",", ":"))
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(serialized)
    temporary.replace(target)

    provenance = {
        "source_url": KEV_URL,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "http_etag": etag,
        "http_last_modified": last_modified,
        "content_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "byte_size": len(serialized.encode("utf-8")),
        "catalog_version": catalog.get("catalogVersion"),
        "date_released": catalog.get("dateReleased"),
        "count": len(catalog.get("vulnerabilities", [])),
    }
    _write_provenance(provenance, path=target)
    load_catalog.cache_clear()
    return catalog


def _write_provenance(provenance: dict[str, Any], *, path: Path) -> None:
    """Persist provenance alongside the catalog. Atomic replace so a
    partial write never survives."""
    sidecar = path.with_suffix(path.suffix + ".provenance.json")
    temporary = sidecar.with_suffix(sidecar.suffix + ".tmp")
    temporary.write_text(json.dumps(provenance, sort_keys=True, indent=2))
    temporary.replace(sidecar)


def load_provenance() -> dict[str, Any] | None:
    """Read the provenance sidecar if present. Missing / malformed
    provenance is not fatal — the catalog still serves lookups; the
    status endpoint will simply lack provenance detail."""
    path = provenance_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def verify_catalog_integrity() -> dict[str, Any]:
    """Recompute the SHA-256 of the cached catalog and compare it to the
    provenance-recorded hash. Returns a dict with `verified`, `expected`,
    `actual`, and `reason` (populated when verification fails or is
    unavailable). Used by /intel/kev/status and by monitoring."""
    catalog_file = cache_path()
    provenance = load_provenance()
    if not catalog_file.is_file():
        return {"verified": False, "reason": "catalog file missing"}
    if provenance is None:
        return {"verified": False, "reason": "no provenance sidecar"}
    expected = provenance.get("content_sha256")
    if not expected:
        return {"verified": False, "reason": "provenance missing content_sha256"}
    actual = hashlib.sha256(catalog_file.read_bytes()).hexdigest()
    if actual != expected:
        return {
            "verified": False,
            "reason": "sha256 mismatch — catalog may have been tampered with or partially written",
            "expected": expected,
            "actual": actual,
        }
    return {"verified": True, "expected": expected, "actual": actual}


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
    provenance = load_provenance()
    return {
        "available": catalog is not None,
        "source": KEV_URL,
        "catalog_version": catalog.get("catalogVersion") if catalog else None,
        "date_released": catalog.get("dateReleased") if catalog else None,
        "count": len(catalog.get("vulnerabilities", [])) if catalog else 0,
        "cache_updated_at": path.stat().st_mtime if path.is_file() else None,
        # Provenance & integrity — added in P4.1a so an auditor can
        # verify catalog freshness AND that the file on disk matches
        # what we recorded fetching from CISA. Omitted for older
        # deployments that never ran the new sync path.
        "provenance": provenance,
        "integrity": verify_catalog_integrity() if catalog is not None else None,
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


# ---------- P4.1b: scheduled refresh ----------


def refresh_enabled() -> bool:
    """Env-gate the refresh loop. Default: enabled. Tests and single-shot
    runs set SPOTLIGHT_KEV_REFRESH_ENABLED=false to opt out."""
    return os.environ.get("SPOTLIGHT_KEV_REFRESH_ENABLED", "true").strip().lower() in {
        "1", "true", "yes", "on"
    }


def refresh_interval_hours() -> float:
    """Interval between refresh attempts. Default 24h; environment override
    for staging/tests that want a shorter cadence."""
    try:
        return float(os.environ.get("SPOTLIGHT_KEV_REFRESH_INTERVAL_HOURS", "24"))
    except (TypeError, ValueError):
        return 24.0


def boot_refresh_enabled() -> bool:
    """Whether to sync at scheduler start. Default false — the on-disk
    cache is a first-class artifact bundled with the deployment, and we
    don't want every process boot to hit CISA. Enable in staging where
    the cache may be stale relative to deploy cadence."""
    return os.environ.get("SPOTLIGHT_KEV_BOOT_REFRESH", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }


def start_scheduler(
    *,
    interval_hours: float | None = None,
    stop_event: threading.Event | None = None,
    boot_refresh: bool | None = None,
    on_error: Callable[[Exception], None] | None = None,
    sync_fn: Callable[[], Any] | None = None,
) -> tuple[threading.Thread, threading.Event]:
    """Spawn a background thread that periodically calls sync_catalog().

    Returns (thread, stop_event). Call `stop_event.set()` for a clean
    shutdown; the thread checks it in its sleep window.

    Failures are logged, not fatal — the last-known catalog persists on
    disk and continues to serve exact-ID lookups. Enrichment remains a
    prioritization metadata step; a stale KEV never blocks a sweep.

    Injectable `sync_fn` exists for tests — production always uses
    `sync_catalog`.
    """
    interval = interval_hours if interval_hours is not None else refresh_interval_hours()
    if interval <= 0:
        raise ValueError("refresh interval must be positive")
    stop = stop_event or threading.Event()
    sync = sync_fn or sync_catalog
    do_boot = boot_refresh if boot_refresh is not None else boot_refresh_enabled()

    def _loop() -> None:
        # Optional boot-time sync.
        if do_boot:
            _run_once(sync, on_error)
        interval_seconds = interval * 3600.0
        while not stop.wait(timeout=interval_seconds):
            _run_once(sync, on_error)

    thread = threading.Thread(
        target=_loop, daemon=True, name="kev-refresh",
    )
    thread.start()
    log.info(
        "KEV scheduler started: interval=%.2fh boot_refresh=%s",
        interval, do_boot,
    )
    return thread, stop


def _run_once(
    sync_fn: Callable[[], Any],
    on_error: Callable[[Exception], None] | None,
) -> None:
    try:
        sync_fn()
        log.info("KEV catalog refresh succeeded")
    except Exception as exc:  # noqa: BLE001 — scheduler must never die
        log.warning("KEV catalog refresh failed: %r", exc)
        if on_error is not None:
            try:
                on_error(exc)
            except Exception:  # noqa: BLE001
                log.exception("on_error callback for KEV refresh raised")


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
