"""
IPv6 prefix loader — stub.

This module exists as a compatibility shim. IPv6 prefix data is not currently
shipped with the project (RIPE prefix2as covers both v4 and v6 in newer
archives). When loaded, the helpers return empty data so downstream code
proceeds without errors and the warning is emitted exactly once per run.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from utils.logger import logger

_WARNED = False


def load_ipv6_prefixes_for_as(asn) -> List[str]:
    """Return IPv6 prefixes originated by ``asn`` (empty if not available)."""
    global _WARNED
    if not _WARNED:
        logger.debug("[ipv6_prefix_loader] IPv6 prefixes not loaded (no local cache); returning empty")
        _WARNED = True
    return []


def merge_prefix2as_with_ipv6(prefix2as: Dict[str, str]) -> Dict[str, str]:
    """Return ``prefix2as`` unchanged (IPv6 overlay not available)."""
    return dict(prefix2as)


__all__ = ["load_ipv6_prefixes_for_as", "merge_prefix2as_with_ipv6"]
