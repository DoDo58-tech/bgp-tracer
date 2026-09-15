"""
RPKI ROA loader — local cache fallback.

Reads pre-fetched ROA JSON files from ``data/rpki/roa_cache/`` (historical
snapshots). When called with a date before the oldest cached snapshot, falls
back to the earliest available file.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

from utils.logger import logger

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = PROJECT_ROOT / "data" / "rpki" / "roa_cache"


class _RpkiLoader:
    """Lazy loader for cached RPKI ROA snapshots."""

    def __init__(self):
        self._cache: Dict[str, Dict[str, Dict]] = {}
        self._files: list[Path] = sorted(CACHE_DIR.glob("roa_prefixes_*.json"))

    def _snapshots(self) -> list[tuple[datetime, Path]]:
        out = []
        for p in self._files:
            try:
                stem = p.stem.replace("roa_prefixes_", "")
                dt = datetime.strptime(stem, "%Y%m%d")
                out.append((dt, p))
            except ValueError:
                continue
        return out

    def fetch_roa_data(self, target_date: Optional[datetime] = None) -> Dict:
        """Return ROA mapping ``prefix -> {"asn": str, "max_length": int, ...}``.

        Picks the snapshot dated closest to ``target_date`` (not after it,
        falling back to the earliest available snapshot).
        """
        snaps = self._snapshots()
        if not snaps:
            logger.info("[rpki_loader] no ROA snapshots found in %s", CACHE_DIR)
            return {}

        if target_date is None:
            chosen = snaps[-1][1]
        else:
            eligible = [(d, p) for d, p in snaps if d <= target_date]
            chosen = (eligible[-1][1] if eligible else snaps[0][1])

        key = str(chosen)
        if key in self._cache:
            return self._cache[key]

        try:
            with open(chosen, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            logger.warning("[rpki_loader] failed to read %s: %s", chosen, e)
            return {}

        # Some dumps store ROAs as list of dicts; normalise to dict by prefix.
        if isinstance(raw, list):
            mapping: Dict[str, Dict] = {}
            for roa in raw:
                if isinstance(roa, dict) and roa.get("prefix"):
                    mapping[roa["prefix"]] = roa
            self._cache[key] = mapping
        elif isinstance(raw, dict):
            self._cache[key] = raw
        else:
            self._cache[key] = {}
        logger.debug("[rpki_loader] loaded %d ROAs from %s", len(self._cache[key]), chosen.name)
        return self._cache[key]

    def fetch_latest(self) -> Dict:
        """Shortcut: fetch the newest available snapshot."""
        return self.fetch_roa_data(target_date=None)


_LOADER: Optional[_RpkiLoader] = None


def get_rpki_loader() -> _RpkiLoader:
    """Return the process-wide RPKI loader (singleton)."""
    global _LOADER
    if _LOADER is None:
        _LOADER = _RpkiLoader()
    return _LOADER


def merge_roa_with_prefix2as(prefix2as: Dict[str, str], roa_data: Optional[Dict] = None) -> Dict[str, str]:
    """Tag a prefix2as dict with ROA annotations; returns the unchanged mapping.

    The hijack detector reads ROA data via ``rpki_loader.fetch_roa_data()``
    separately; this helper is kept for callers that want a single merged view.
    """
    return dict(prefix2as)


__all__ = ["get_rpki_loader", "merge_roa_with_prefix2as"]
