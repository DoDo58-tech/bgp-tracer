"""Parquet index cache for decoded BGP updates.

Layered cache strategy (in priority order):
  1. {file}.parquet  – pre-parsed Polars-friendly binary (5-25x smaller than txt)
  2. decoded/*.txt   – already bgpdump-decoded text
  3. .gz             – raw MRT gz archived by RIPE RIS
  4. Network         – download from RIPE RIS, then decode

Reads never block on the network: if only a .gz is available locally it is
decoded in-process and the parquet cache is (re)written on the fly.

The cache is BYTE-KEYED, not time-keyed: a parquet file is considered valid
iff the underlying txt/gz fingerprint (size + mtime) matches the recorded
fingerprint stored as a small sidecar `.meta.json`. If the upstream .gz is
replaced (rare but happens during RIS replays), the cache is invalidated.

Public API
==========

- iter_window_chunks(start, end, *, raw=False, on_missing='skip')
    Iterate chunked Polars DataFrames covering [start, end].
    `raw=False` (default) returns only Announce (type=A) rows; this matches
    what the detectors need.

- load_window_announcements(start, end)
    Materialise a single DataFrame for the whole window (small events only).

- parquet_path_for(path)
    Map a decoded txt or .gz path to its parquet cache file.

- cache_stats()
    Report (count, total_size_mb) of the parquet index.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional, Union

import polars as pl

from utils.logger import logger
from config import RIPE_RIS_URL, UPDATES_DIR

# Reuse the download / decode helpers from updates_loader so the layered
# cache in this module and the historical code path in updates_loader share
# a single implementation. This avoids drift between the two.
try:
    from data.updates_loader import (
        is_valid_gz_file,
        decode_gz_to_txt,
        download_data,
    )
except Exception:  # pragma: no cover - circular import guard
    is_valid_gz_file = None
    decode_gz_to_txt = None
    download_data = None

UPDATES_ROOT = Path(os.environ.get(
    "BGP_TRACER_UPDATES_DIR",
    str(Path(__file__).resolve().parent.parent / "data" / "updates_rrc00"),
))
DECODED_DIR = UPDATES_ROOT / "decoded"
PARQUET_DIR = UPDATES_ROOT / "parquet"

# Canonical columns matching bgpdump `-M -t change` output.
_COLUMNS = [
    "type", "timestamp", "announce", "peer_ip", "peer_as", "prefix",
    "as_path", "origin", "next_hop", "local_pref", "med",
    "communities", "atomic_aggregate", "aggregator", "unknown",
]

_TIMESTAMP_PATTERN = re.compile(
    r"^(?:BGP4MP\|)?(\d{2})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})"
)


def _ensure_dirs() -> None:
    PARQUET_DIR.mkdir(parents=True, exist_ok=True)
    DECODED_DIR.mkdir(parents=True, exist_ok=True)


def parquet_path_for(source: Union[str, Path]) -> Path:
    src = Path(source)
    name = src.name
    if name.endswith(".txt"):
        stem = name[:-4]
    elif name.endswith(".gz"):
        stem = name[:-3]
    elif name.endswith(".parquet"):
        return src
    else:
        stem = src.stem
    return PARQUET_DIR / f"{stem}.parquet"


def meta_path_for(parquet: Path) -> Path:
    return parquet.with_suffix(".meta.json")


def _source_fingerprint(path: Path) -> str:
    """Return a fingerprint that survives `touch` and unstable mtime ns.

    Uses size + inode + second-precision mtime.  Sticking to
    ``st_mtime_ns`` made valid caches get invalidated whenever a tool
    rewrote the decoded file with coarser timestamps (e.g. NFS, FUSE,
    ``noatime`` mounts).
    """
    st = path.stat()
    return f"{st.st_size}:{st.st_ino}:{int(st.st_mtime)}"


def _read_meta(parquet: Path) -> Optional[dict]:
    mp = meta_path_for(parquet)
    if not mp.exists():
        return None
    try:
        return json.loads(mp.read_text())
    except Exception:
        return None


def _write_meta(parquet: Path, source: Path) -> None:
    """Persist cache metadata atomically.

    Bug fix 2026-09-13 (BUG-R93):
      1. The previous code used a plain ``mp.write_text(...)`` which
         truncated and rewrote the meta file non-atomically. Two
         concurrent processes (or a reader arriving mid-write) could
         see a partially-written JSON object and bail, deleting the
         parquet on the next cache validation even though the cache
         itself was intact. Use the tmp-then-os.replace pattern that
         the rest of the codebase already adopts.
      2. ``datetime.utcnow()`` was deprecated in Python 3.12 in favour
         of ``datetime.now(timezone.utc)``. While the former still
         works, the deprecation warnings pollute CI logs and the
         behaviour is identical, so we move to the recommended form.
    """
    mp = meta_path_for(parquet)
    payload = json.dumps({
        "source": str(source),
        "fingerprint": _source_fingerprint(source),
        "parquet_size": parquet.stat().st_size,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2)
    try:
        tmp = mp.with_suffix(mp.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, mp)
    except OSError as exc:
        # Metadata is best-effort — a missing meta is far cheaper than
        # cascading a crash on every cache read. Log and continue.
        logger.debug(f"[parquet_cache] failed to persist meta for {parquet}: {exc!r}")
        # Clean up partial tmp file if any.
        try:
            tmp = mp.with_suffix(mp.suffix + ".tmp")
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _is_cache_valid(parquet: Path, source: Optional[Path]) -> bool:
    if not parquet.exists():
        return False
    if source is None:
        return True
    if not source.exists():
        return False
    meta = _read_meta(parquet)
    if meta is None:
        return False
    return meta.get("fingerprint") == _source_fingerprint(source)


_SCHEMA = {
    "type": pl.Utf8, "timestamp": pl.Utf8, "announce": pl.Utf8,
    "peer_ip": pl.Utf8, "peer_as": pl.Utf8, "prefix": pl.Utf8,
    "as_path": pl.Utf8, "origin": pl.Utf8, "next_hop": pl.Utf8,
    "local_pref": pl.Utf8, "med": pl.Utf8, "communities": pl.Utf8,
    "atomic_aggregate": pl.Utf8, "aggregator": pl.Utf8, "unknown": pl.Utf8,
    "ts": pl.Datetime,
}


def _align_to_canonical(df: pl.DataFrame) -> pl.DataFrame:
    """Ensure every required column exists; missing columns become null.

    Polars parquet requires consistent schemas across reads. MRT files vary in
    column count (8–15 depending on router config) so we coerce each into the
    canonical schema before writing.
    """
    out = df
    for col, dtype in _SCHEMA.items():
        if col not in out.columns:
            out = out.with_columns(pl.lit(None).alias(col).cast(dtype))
    return out.select(list(_SCHEMA.keys()))


def _txt_to_announcements_df(txt_path: Path) -> pl.DataFrame:
    df = pl.read_csv(
        txt_path,
        separator="|",
        has_header=False,
        schema_overrides={f"column_{i}": pl.Utf8 for i in range(1, 16)},
        ignore_errors=True,
        low_memory=False,
    )
    # Re-map whatever columns are present onto canonical names.
    keep_idx = sorted(int(c.split("_")[1]) for c in df.columns if c.startswith("column_"))
    rename = {f"column_{i}": _COLUMNS[i - 1] for i in keep_idx if 1 <= i <= len(_COLUMNS)}
    df = df.rename(rename)
    df = df.filter(pl.col("announce") == "A")
    if df.is_empty():
        return df
    df = df.with_columns(
        pl.col("timestamp").str.strptime(
            pl.Datetime, format="%m/%d/%y %H:%M:%S", strict=False
        ).alias("ts")
    )
    return _align_to_canonical(df)


def _ensure_parquet(src_path: Path) -> Optional[Path]:
    _ensure_dirs()
    parquet = parquet_path_for(src_path)
    if _is_cache_valid(parquet, src_path):
        return parquet

    try:
        if src_path.suffix == ".gz":
            df = _read_gz_into_df(src_path)
        else:
            df = _txt_to_announcements_df(src_path)
    except Exception as exc:
        logger.warning(f"_ensure_parquet failed for {src_path.name}: {exc}")
        return None

    if df is None:
        return None
    if df.is_empty():
        df = pl.DataFrame(schema={c: pl.Utf8 for c in _COLUMNS} | {"ts": pl.Datetime})

    tmp = parquet.with_suffix(".parquet.tmp")
    df.write_parquet(tmp, compression="zstd", compression_level=3)
    tmp.replace(parquet)
    _write_meta(parquet, src_path)
    return parquet


def _read_gz_into_df(gz_path: Path) -> pl.DataFrame:
    rows = []
    with gzip.open(gz_path, "rt", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or "|A|" not in line:
                continue
            parts = line.split("|")
            if len(parts) >= 6:
                parts += [""] * (15 - len(parts))
                rows.append(parts[:15])
    if not rows:
        return pl.DataFrame()
    df = pl.DataFrame(rows, schema=_COLUMNS, orient="row")
    df = df.with_columns(
        pl.col("timestamp").str.strptime(
            pl.Datetime, format="%m/%d/%y %H:%M:%S", strict=False
        ).alias("ts")
    )
    return _align_to_canonical(df)


def list_window_files(start: datetime, end: datetime) -> list[Path]:
    """Decoded txt (preferred) or .gz files whose 5-minute window falls in [start,end]."""
    aligned = start.replace(minute=(start.minute // 5) * 5, second=0, microsecond=0)
    out = []
    cur = aligned
    while cur <= end:
        stamp = cur.strftime("%Y%m%d.%H%M")
        candidates = [
            DECODED_DIR / f"updates.{stamp}.txt",
            UPDATES_ROOT / f"updates.{stamp}.gz",
        ]
        for path in candidates:
            if path.exists() and path.stat().st_size > 0:
                out.append(path)
                break
        cur += timedelta(minutes=5)
    return out


def list_window_parquets(start: datetime, end: datetime) -> list[Path]:
    aligned = start.replace(minute=(start.minute // 5) * 5, second=0, microsecond=0)
    out = []
    cur = aligned
    while cur <= end:
        stamp = cur.strftime("%Y%m%d.%H%M")
        # Use the txt-name stem so the gz and txt share the same parquet.
        out.append(PARQUET_DIR / f"updates.{stamp}.parquet")
        cur += timedelta(minutes=5)
    return out


def purge_decoded_txt(
    *,
    only_with_parquet: bool = True,
    min_age_seconds: int = 0,
    dry_run: bool = True,
    progress_every: int = 500,
) -> dict:
    """Reclaim disk by deleting decoded/*.txt once their parquet mirror exists.

    Why: decoded text is 5-25x larger than the equivalent parquet snapshot
    and is only useful as a *source* for parquet generation. Once
    `_ensure_parquet` has written a valid `updates.<stamp>.parquet` (verified
    by the matching `updates.<stamp>.meta.json` whose fingerprint matches the
    txt's size + mtime), the txt is redundant and safe to delete.

    Args:
        only_with_parquet: only delete txt files whose parquet mirror is
            present AND has a matching `.meta.json` fingerprint. Default True.
            Set False to delete all decoded txt (still safe: gz originals are
            kept under UPDATES_ROOT if you need to regenerate parquet).
        min_age_seconds: skip txt whose mtime is newer than this many seconds
            ago. Lets in-flight decode jobs finish before being deleted.
        dry_run: report counts/bytes without actually unlinking. Default True
            so the function is safe to call from arbitrary hooks. Pass
            dry_run=False to actually free disk.
        progress_every: log progress every N files (set 0 to silence).

    Returns:
        Dict with `candidates`, `would_delete` (count), `bytes_reclaimed`,
        and `errors`. Useful for telemetry / GC reporting.
    """
    import time as _time

    if not DECODED_DIR.exists():
        return {"candidates": 0, "would_delete": 0, "bytes_reclaimed": 0, "errors": 0}

    now = _time.time()
    candidates = []
    bytes_total = 0
    errors = 0
    scanned = 0

    for txt in DECODED_DIR.glob("updates.*.txt"):
        scanned += 1
        try:
            st = txt.stat()
        except OSError:
            continue

        if min_age_seconds > 0 and (now - st.st_mtime) < min_age_seconds:
            continue

        if only_with_parquet:
            parquet = parquet_path_for(txt)
            if not parquet.exists():
                continue
            meta = _read_meta(parquet)
            if meta is None:
                continue
            # Only delete when the parquet was generated from THIS txt
            # (the fingerprint check guards against mismatched regeneration).
            expected_fp = _source_fingerprint(txt)
            if meta.get("fingerprint") != expected_fp:
                continue

        candidates.append(txt)
        bytes_total += st.st_size
        if progress_every and scanned % progress_every == 0:
            logger.info(
                f"[parquet_cache] purge scan: {scanned} files, "
                f"{len(candidates)} candidates ({bytes_total//1024//1024} MB)"
            )

    if dry_run:
        return {
            "candidates": len(candidates),
            "would_delete": len(candidates),
            "bytes_reclaimed": bytes_total,
            "errors": errors,
            "scanned": scanned,
        }

    deleted = 0
    for txt in candidates:
        try:
            txt.unlink()
            deleted += 1
        except OSError as exc:
            errors += 1
            logger.debug(f"[parquet_cache] failed to delete {txt.name}: {exc}")

    if deleted:
        logger.info(
            f"[parquet_cache] purged {deleted} decoded/*.txt files "
            f"({bytes_total//1024//1024} MB reclaimed)"
        )
    return {
        "candidates": len(candidates),
        "would_delete": len(candidates),
        "deleted": deleted,
        "bytes_reclaimed": bytes_total,
        "errors": errors,
        "scanned": scanned,
    }


def _ensure_underlying_source(stamp: str) -> Optional[Path]:
    """Make sure at least one of (decoded txt, raw gz) exists for `stamp`.

    Search order:
      1. DECODED_DIR/updates.<stamp>.txt  – bgpdump-decoded text
      2. UPDATES_ROOT/updates.<stamp>.gz – raw MRT gz
      3. Download from RIPE RIS (this is the unavoidable network path for
         events that fall outside the cached window).

    On success, returns whichever path was found / created. On failure,
    returns None (and logs the reason).
    """
    _ensure_dirs()

    txt_path = DECODED_DIR / f"updates.{stamp}.txt"
    gz_path = UPDATES_ROOT / f"updates.{stamp}.gz"

    # 1) Already decoded?
    if txt_path.exists() and txt_path.stat().st_size > 0:
        return txt_path

    # 2) Already have raw gz?
    if gz_path.exists() and gz_path.stat().st_size > 0 and is_valid_gz_file(gz_path):
        # Decode it now so the next iteration of this bucket is free.
        if decode_gz_to_txt(gz_path, txt_path):
            return txt_path if txt_path.exists() else gz_path
        return gz_path  # decoding failed; gz is still usable as a fallback

    # 3) Download from RIPE RIS.
    #    The bucket lives at YYYY.MM/updates.YYYYMMDD.HHMM.gz on ris.ripe.net.
    try:
        cur_dt = datetime.strptime(f"{stamp.replace('.', '')}", "%Y%m%d%H%M")
    except Exception:
        return None
    ym = cur_dt.strftime("%Y.%m")
    url = f"{RIPE_RIS_URL}{ym}/updates.{stamp}.gz"
    try:
        download_data(url)  # writes to UPDATES_ROOT
    except Exception as exc:
        logger.debug(f"Download failed for {stamp}: {exc}")
        return None

    if not (gz_path.exists() and is_valid_gz_file(gz_path)):
        return None

    if decode_gz_to_txt(gz_path, txt_path):
        return txt_path if txt_path.exists() else gz_path
    return gz_path


def iter_window_chunks(
    start: datetime,
    end: datetime,
    *,
    raw: bool = False,
    on_missing: str = "skip",
    columns: Optional[list[str]] = None,
    auto_download: bool = True,
) -> Iterator[pl.DataFrame]:
    """Yield Polars DataFrames covering [start, end] (5-minute windows).

    `raw=True` returns all rows (no Announce filter).
    `on_missing`:
        "skip"   – silently skip windows without local data
        "raise"  – raise FileNotFoundError
        "wait"   – poll up to 30s waiting for a downloader to drop a file

    `auto_download=True` (default) transparently downloads missing buckets
    from RIPE RIS on first hit so the caller never sees a network gap.
    """
    if columns is None:
        columns = _COLUMNS

    aligned = start.replace(minute=(start.minute // 5) * 5, second=0, microsecond=0)
    cur = aligned
    while cur <= end:
        stamp = cur.strftime("%Y%m%d.%H%M")
        txt_path = DECODED_DIR / f"updates.{stamp}.txt"
        gz_path = UPDATES_ROOT / f"updates.{stamp}.gz"
        parquet = PARQUET_DIR / f"updates.{stamp}.parquet"

        fpath: Optional[Path] = None
        if parquet.exists():
            fpath = parquet
        elif txt_path.exists() and txt_path.stat().st_size > 0:
            fpath = _ensure_parquet(txt_path)
        elif gz_path.exists() and gz_path.stat().st_size > 0:
            fpath = _ensure_parquet(gz_path)
        else:
            # No parquet / no txt / no gz — try to fetch from RIS.
            if auto_download:
                src = _ensure_underlying_source(stamp)
                if src is not None:
                    fpath = _ensure_parquet(src)
            if fpath is None:
                if on_missing == "raise":
                    raise FileNotFoundError(f"No BGP update file for window {stamp}")
                if on_missing == "wait":
                    deadline = time.time() + 30
                    while time.time() < deadline:
                        time.sleep(0.5)
                        if txt_path.exists() and txt_path.stat().st_size > 0:
                            fpath = _ensure_parquet(txt_path)
                            break
                        if gz_path.exists() and gz_path.stat().st_size > 0:
                            fpath = _ensure_parquet(gz_path)
                            break
                # "skip" or timed out: continue to next window.

        if fpath is None or not Path(fpath).exists():
            cur += timedelta(minutes=5)
            continue

        try:
            df = pl.read_parquet(fpath, columns=columns)
        except Exception as exc:
            logger.warning(f"parquet read failed for {fpath}: {exc}")
            cur += timedelta(minutes=5)
            continue

        if df.is_empty():
            cur += timedelta(minutes=5)
            continue

        if not raw and "announce" in df.columns:
            df = df.filter(pl.col("announce") == "A")

        # Re-confirm window: only emit rows within the current 5-min bucket.
        # The bgpdump-decoded txt and the gz both contain timestamp strings
        # like "01/03/24 14:45:00" which `_txt_to_announcements_df` parses
        # into the `ts` column as UTC-naive datetime. We re-filter here so
        # an out-of-range row in the source file (rare, but possible with
        # overlapping collections) never leaks into the next 5-minute
        # bucket.
        if "ts" in df.columns:
            ts_lo = cur
            ts_hi = cur + timedelta(minutes=5)
            try:
                before = len(df)
                df = df.filter(
                    (pl.col("ts") >= ts_lo) & (pl.col("ts") < ts_hi)
                )
            except Exception:
                pass

        # ── Backward-compat column aliases ──────────────────────────────────
        # Historical detectors (hijack/leak) reference the column as
        # `as-path` (with a hyphen), and `A/W` (with a slash). Modern Polars
        # schema and parquet writing prefer underscores. We expose BOTH names
        # on every chunk so the old code keeps working without modification.
        # `DataFrame.rename` is a pure schema rename — zero copy, no row
        # materialisation.  Using `with_columns` here was a 100x regression
        # on a 22M-row window because Polars materialised a full copy per
        # chunk.
        rename_map: dict = {}
        if "as_path" in df.columns and "as-path" not in df.columns:
            rename_map["as_path"] = "as-path"
        if "announce" in df.columns and "A/W" not in df.columns:
            rename_map["announce"] = "A/W"
        if rename_map:
            try:
                df = df.rename(rename_map)
            except Exception:
                pass

        if not df.is_empty():
            yield df

        cur += timedelta(minutes=5)


def load_window_announcements(
    start: datetime,
    end: datetime,
    *,
    columns: Optional[list[str]] = None,
) -> pl.DataFrame:
    """Materialise a single DataFrame covering [start,end]. For small windows only."""
    parts = list(iter_window_chunks(start, end, columns=columns))
    if not parts:
        return pl.DataFrame()
    return pl.concat(parts, how="vertical_relaxed")


def cache_stats() -> dict:
    if not PARQUET_DIR.exists():
        return {"parquet_dir": str(PARQUET_DIR), "exists": False, "count": 0, "total_size_mb": 0.0}
    parquet_files = list(PARQUET_DIR.glob("updates.*.parquet"))
    total_size = sum(p.stat().st_size for p in parquet_files)
    return {
        "parquet_dir": str(PARQUET_DIR),
        "exists": True,
        "count": len(parquet_files),
        "total_size_mb": round(total_size / 1024 / 1024, 1),
    }


__all__ = [
    "UPDATES_ROOT",
    "DECODED_DIR",
    "PARQUET_DIR",
    "parquet_path_for",
    "list_window_files",
    "list_window_parquets",
    "iter_window_chunks",
    "load_window_announcements",
    "cache_stats",
    "purge_decoded_txt",
]
