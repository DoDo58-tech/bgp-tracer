"""IPv6 prefix loader — loads per-AS IPv6 prefix lists from the local cache
at ``data/prefix2as/ipv6_cache/ipv6_prefixes_AS<asn>.json``.

Each cache file is a JSON object of the form::

    {"asn": "10753", "prefixes": ["2400:8a20:...", ...]}

If a cache file is missing for the requested ASN, the loader returns an
empty list (same fallback as before) so downstream code proceeds without
errors.  A single one-shot INFO message is logged the first time a cache
hit happens (and again the first time a miss happens after a hit so
operators can see whether the cache is covering their workload).
"""
from __future__ import annotations

import os
from typing import Dict, Iterable, List

from utils.logger import logger

_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "data", "prefix2as", "ipv6_cache",
)
_CACHE_DIR = os.path.normpath(_CACHE_DIR)

_HIT_LOGGED = False
_MISS_LOGGED = False


def _strip_asn(asn) -> str:
    s = str(asn).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return s


def _cache_path(asn: str) -> str:
    return os.path.join(_CACHE_DIR, f"ipv6_prefixes_AS{asn}.json")


def load_ipv6_prefixes_for_as(asn) -> List[str]:
    """Return IPv6 prefixes originated by ``asn`` from the local cache.

    Returns ``[]`` if no cache file is found, so downstream code proceeds
    cleanly.  Cache files contain a JSON object ``{"asn": ..., "prefixes":
    [...]}``; only the ``prefixes`` list is returned.
    """
    global _HIT_LOGGED, _MISS_LOGGED
    asn_clean = _strip_asn(asn)
    path = _cache_path(asn_clean)
    if not os.path.exists(path):
        if not _MISS_LOGGED:
            logger.info(
                f"[ipv6_prefix_loader] no cache file for AS{asn_clean} "
                f"(dir={_CACHE_DIR})"
            )
            _MISS_LOGGED = True
        return []

    try:
        import json
        with open(path) as f:
            data = json.load(f)
        prefixes = data.get("prefixes") or []
    except Exception as e:
        logger.warning(f"[ipv6_prefix_loader] failed to parse {path}: {e}")
        return []

    if not _HIT_LOGGED:
        n_cached = len([n for n in os.listdir(_CACHE_DIR) if n.startswith("ipv6_prefixes_AS")])
        logger.info(
            f"[ipv6_prefix_loader] IPv6 cache hit: {len(prefixes)} prefixes "
            f"for AS{asn_clean} ({n_cached} total ASes cached at {_CACHE_DIR})"
        )
        _HIT_LOGGED = True
    return prefixes


def merge_prefix2as_with_ipv6(
    prefix2as: Dict[str, Iterable[str]],
    ipv6_prefixes: Iterable[str] = (),
    asn=None,
) -> Dict[str, List[str]]:
    """Merge an IPv6 prefix list into a ``prefix -> [asn]`` mapping.

    The ``prefix2as`` argument uses *list values* (CAIDA's exported schema),
    so we extend the existing list rather than overwriting it.
    """
    asn_clean = _strip_asn(asn) if asn is not None else None
    for pfx in ipv6_prefixes:
        pfx = str(pfx).strip()
        if not pfx:
            continue
        existing = prefix2as.get(pfx, [])
        if isinstance(existing, list):
            if asn_clean and asn_clean not in existing:
                existing.append(asn_clean)
        else:
            # Defensive: coerce to list if someone passed a set/str.
            new = [existing] if existing else []
            if asn_clean and asn_clean not in new:
                new.append(asn_clean)
            existing = new
        prefix2as[pfx] = existing
    return prefix2as


__all__ = ["load_ipv6_prefixes_for_as", "merge_prefix2as_with_ipv6"]
