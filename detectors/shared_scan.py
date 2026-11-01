"""One read of the BGP update stream, three detectors.

Every detector used to open the update stream itself: the hijack
detector streamed it, the leak detector streamed it again, and the
outage detector read the decoded text files a third time.  For a
24-hour baseline that is three passes over the same data, and the text
pass alone moved ~17 GB.

This module reads the window once and hands every chunk to the three
detectors.  The detectors keep their own logic; only the *reading* is
shared, so a detector that is not needed for an event costs nothing.

The three detectors do not want the same window.  Hijack and leak score
the event window; outage compares the event window against a baseline
that may start a day earlier.  The scan therefore reads the *union* of
the windows once and routes each chunk by timestamp: the detectors that
only want the event window are given the event chunks, and the outage
detector is given every chunk so it can build its baseline.

Usage::

    scan = SharedUpdateScan(start, end, target_asns=[...])
    results = scan.run()
    results["hijack"], results["leak"], results["outage"]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence

import polars as pl

from utils.logger import logger


@dataclass
class SharedUpdateScan:
    """Read a window once and dispatch it to the detectors.

    ``detectors`` names the detectors to run.  An empty list runs none;
    ``"all"`` runs hijack, leak and outage.  Forging is not evaluated.

    ``baseline_start`` widens the scan for the detectors that need a
    baseline (outage).  Chunks outside the event window are given to the
    outage detector only.
    """

    start: datetime
    end: datetime
    target_asns: Sequence[str] = field(default_factory=list)
    detectors: Sequence[str] = ("hijack", "leak", "outage")
    baseline_start: Optional[datetime] = None
    include_withdrawals: bool = True
    max_leaks: int = 5000

    # Populated by ``run``.
    hijack_result: Optional[dict] = None
    leak_result: Optional[dict] = None
    outage_result: Optional[dict] = None

    # Internals.
    _hijack_prepared: Optional[dict] = field(default=None, init=False)
    _leak_prepared: Optional[dict] = field(default=None, init=False)
    _hijack_alerts: List[dict] = field(default_factory=list, init=False)
    _leak_chunks: List[dict] = field(default_factory=list, init=False)
    _outage_extractors: Dict[str, object] = field(default_factory=dict, init=False)
    _chunks_read: int = field(default=0, init=False)
    _rows_read: int = field(default=0, init=False)
    _chunks_outside_event: int = field(default=0, init=False)

    def requested(self):
        if not self.detectors:
            return set()
        if "all" in self.detectors:
            return {"hijack", "leak", "outage"}
        return set(self.detectors)

    @property
    def scan_start(self):
        """The beginning of the range that has to be read."""
        if self.baseline_start and self.baseline_start < self.start:
            return self.baseline_start
        return self.start

    # ── setup ──────────────────────────────────────────────────────────
    def setup(self, requested: set):
        if "hijack" in requested:
            self._hijack_prepared = self.prepare_hijack()
        if "leak" in requested:
            self._leak_prepared = self.prepare_leak()
        if "outage" in requested:
            for asn in self.target_asns:
                from detectors.outage.outage_features_parquet import (
                    ParquetOutageFeatureExtractor,
                )
                self._outage_extractors[str(asn)] = ParquetOutageFeatureExtractor(
                    self.asn_int(asn)
                )

    def prepare_hijack(self):
        from detectors.hijack.hijack_prefix_processor import (
            get_target_prefixes_batch,
        )
        from detectors.hijack.hijack_detector import build_covered_subnet_set
        from detectors.hijack import hijack_chunk_api

        cleaned = [str(a).replace("AS", "").replace("as", "") for a in self.target_asns]

        prefix_to_as, as_relationships_data = self.load_hijack_context(cleaned)
        if prefix_to_as is None:
            logger.warning("[shared-scan] hijack prefix map unavailable; skipping hijack")
            return None

        prefixes_by_as = get_target_prefixes_batch(cleaned, prefix_to_as)
        union = set()
        for s in prefixes_by_as.values():
            union |= set(s)
        # `build_covered_subnet_set` returns (count, set).
        _, covered = build_covered_subnet_set(union)

        return hijack_chunk_api.prepare(
            cleaned,
            prefix_to_as,
            covered,
            as_relationships_data=as_relationships_data,
            skip_forge=True,
            prefixes_by_as={asn: set(s) for asn, s in prefixes_by_as.items()},
        )

    def load_hijack_context(self, cleaned_as_list):
        """Load the prefix-to-AS map and the AS relationship data.

        These depend on the AS, not on the updates, so they are loaded
        once per scan and shared by every chunk.

        The IPv6 overlay and the RPKI ROA set are folded in here for the
        same reason the batch detector folds them in: without them a
        prefix the target legitimately holds is read as "owned by someone
        else", which turns the target's own traffic into a hijack
        accusation against it.
        """
        import json
        import os

        from detectors.hijack.hijack_detector import (
            process_asrel,
            process_prefix2as,
            load_prefix2as_json,
        )

        as_relationships_data = {}
        try:
            asrel_result = process_asrel(self.start)
            if isinstance(asrel_result, str) and asrel_result and os.path.exists(asrel_result):
                with open(asrel_result, "r", encoding="utf-8") as fh:
                    as_relationships_data = json.load(fh)
        except (AttributeError, OSError, ValueError) as exc:
            logger.debug(f"[shared-scan] AS relationship data unavailable: {exc!r}")

        prefix_to_as = {}
        try:
            prefix2as_path = process_prefix2as(self.start)
            prefix_to_as = load_prefix2as_json(prefix2as_path) or {}
        except (AttributeError, OSError, ValueError) as exc:
            logger.debug(f"[shared-scan] prefix-to-AS map unavailable: {exc!r}")

        if not prefix_to_as:
            return None, as_relationships_data

        try:
            from data.ipv6_prefix_loader import (
                load_ipv6_prefixes_for_as,
                merge_prefix2as_with_ipv6,
            )
            for asn in cleaned_as_list:
                ipv6_prefixes = load_ipv6_prefixes_for_as(asn)
                if ipv6_prefixes:
                    prefix_to_as = merge_prefix2as_with_ipv6(
                        prefix_to_as, ipv6_prefixes, asn
                    )
        except AttributeError as exc:
            logger.warning(f"[shared-scan] IPv6 overlay skipped: {exc}")

        try:
            from data.rpki_roa_loader import get_rpki_loader, merge_roa_with_prefix2as
            rpki_loader = get_rpki_loader()
            rpki_data = rpki_loader.fetch_roa_data(self.start)
            if rpki_data:
                prefix_to_as = merge_roa_with_prefix2as(prefix_to_as, rpki_data)
        except AttributeError as exc:
            logger.warning(f"[shared-scan] RPKI ROA overlay skipped: {exc}")

        return prefix_to_as, as_relationships_data

    def prepare_leak(self):
        from detectors.leak import leak_chunk_api
        from detectors.leak.leak_detector import find_pathprob_file
        from config import DEFAULT_LEAK_THRESHOLD

        pathprob_file = find_pathprob_file()
        if pathprob_file is None:
            logger.warning("[shared-scan] no PathProb table; skipping leak")
            return None
        asrelprob, targets = leak_chunk_api.prepare(pathprob_file, self.target_asns)
        if asrelprob is None:
            return None
        return {
            "asrelprob": asrelprob,
            "targets": targets,
            "threshold": DEFAULT_LEAK_THRESHOLD,
            "pathprob_file": pathprob_file,
        }

    @staticmethod
    def asn_int(asn):
        try:
            text = str(asn).strip()
            if text.upper().startswith("AS"):
                text = text[2:]
            return int(text)
        except (TypeError, ValueError):
            return int(asn)

    # ── the scan ───────────────────────────────────────────────────────
    def iter_chunks(self):
        from data.parquet_cache import iter_window_chunks

        return iter_window_chunks(
            self.scan_start,
            self.end,
            on_missing="skip",
            include_withdrawals=self.include_withdrawals,
        )

    @staticmethod
    def chunk_is_in_event(chunk: pl.DataFrame, start: datetime, end: datetime):
        """True when the chunk overlaps the event window.

        The outage detector needs the baseline, so it gets every chunk;
        the event-only detectors get the chunks that overlap the event.
        """
        if "ts" not in chunk.columns or chunk.is_empty():
            return True
        ts = chunk.get_column("ts")
        lo = ts.min()
        hi = ts.max()
        if lo is None or hi is None:
            return True
        return not (hi < start or lo > end)

    def consume(self, chunk: pl.DataFrame, requested: set, in_event: bool):
        if not in_event:
            # Baseline chunk: only the outage detector has any use for it.
            if "outage" in requested:
                for extractor in self._outage_extractors.values():
                    extractor.consume(chunk)
            return

        if "hijack" in requested and self._hijack_prepared:
            from detectors.hijack import hijack_chunk_api
            alerts = hijack_chunk_api.consume_chunk(chunk, self._hijack_prepared)
            if alerts:
                self._hijack_alerts.append(alerts)

        if "leak" in requested and self._leak_prepared:
            from detectors.leak import leak_chunk_api
            res = leak_chunk_api.consume_chunk(
                chunk,
                self._leak_prepared["asrelprob"],
                self._leak_prepared["threshold"],
                self._leak_prepared["targets"],
            )
            self._leak_chunks.append(res)

        if "outage" in requested:
            for extractor in self._outage_extractors.values():
                extractor.consume(chunk)

    # ── public entry point ─────────────────────────────────────────────
    def run(self):
        """Execute the scan and return one result per detector."""
        requested = self.requested()
        if not requested:
            return {}

        self.setup(requested)

        for chunk in self.iter_chunks():
            if chunk is None or chunk.is_empty():
                continue
            self._chunks_read += 1
            self._rows_read += chunk.height
            in_event = self.chunk_is_in_event(chunk, self.start, self.end)
            if not in_event:
                self._chunks_outside_event += 1
            self.consume(chunk, requested, in_event)

        logger.info(
            "[shared-scan] %d chunks / %d rows read once for %s "
            "(%d chunks outside the event window)",
            self._chunks_read,
            self._rows_read,
            ", ".join(sorted(requested)),
            self._chunks_outside_event,
        )

        if "hijack" in requested:
            self.hijack_result = self.finalize_hijack()
        if "leak" in requested:
            self.leak_result = self.finalize_leak()
        if "outage" in requested:
            self.outage_result = self.finalize_outage()

        return {
            "hijack": self.hijack_result,
            "leak": self.leak_result,
            "outage": self.outage_result,
            "chunks_read": self._chunks_read,
            "rows_read": self._rows_read,
        }

    def finalize_hijack(self):
        if not self._hijack_prepared:
            return None
        from detectors.hijack import hijack_chunk_api
        return hijack_chunk_api.finalize(self._hijack_prepared, self._hijack_alerts)

    def finalize_leak(self):
        if not self._leak_prepared:
            return None
        from detectors.leak import leak_chunk_api
        return leak_chunk_api.finalize(self._leak_chunks, max_leaks=self.max_leaks)

    def finalize_outage(self):
        """The per-AS feature series, one per target AS.

        The outage detector consumes these directly, so the series is
        built once here rather than once inside the detector.
        """
        return {
            asn: extractor.finalize()
            for asn, extractor in self._outage_extractors.items()
        }
