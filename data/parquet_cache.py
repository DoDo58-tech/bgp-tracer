"""Parquet index cache for decoded BGP updates."""

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
try:
    from data.updates_loader import (
        is_valid_gz_file,
        decode_gz_to_txt,
        download_data,
    )
except (ValueError):  # pragma: no cover - circular import guard
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

# The parsed timestamp is read alongside the raw columns so that the
# per-bucket window filter can actually run.  It is kept out of
# ``_COLUMNS`` because that list doubles as the raw MRT field order.
_READ_COLUMNS = _COLUMNS + ["ts"]

_TIMESTAMP_PATTERN = re.compile(
    r"^(?:BGP4MP\|)?(\d{2})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})"
)

# The decoded MRT feed writes its timestamp as "YYYY-MM-DD HH:MM:SS".
# Older archives used bgpdump's "MM/DD/YY HH:MM:SS".  Both are accepted
# here because the parquet cache is built from whatever archive the
# bucket came from, and a strict single format silently nulls the whole
# `ts` column for one of the two eras.
_TS_FORMATS = ["%Y-%m-%d %H:%M:%S", "%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S"]


def parse_timestamp_expr():
    """Parse the MRT timestamp column, tolerating both archive formats.

    Polars' ``strptime`` takes a single format string, so the formats are
    tried in order and the first one that yields a value wins per row.
    A strict single format silently nulls the whole column for the other
    era, and a null ``ts`` disables the per-bucket window filter.
    """
    expr = pl.lit(None, dtype=pl.Datetime)
    for fmt in _TS_FORMATS:
        parsed = pl.col("timestamp").str.strptime(
            pl.Datetime, format=fmt, strict=False
        )
        expr = pl.coalesce([expr, parsed])
    return expr

# Cache schema version.  Bumping it invalidates every existing parquet
# file, because version 1 stored announcements only and version 2 stores
# withdrawals as well.
_PARQUET_SCHEMA_VERSION = 2


def ensure_dirs():
    PARQUET_DIR.mkdir(parents=True, exist_ok=True)
    DECODED_DIR.mkdir(parents=True, exist_ok=True)


def parquet_path_for(source: Union[str, Path]):
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


def meta_path_for(parquet):
    return parquet.with_suffix(".meta.json")


def source_fingerprint(path):
    """Return a fingerprint that survives `touch` and unstable mtime ns.

    The source may have been pruned since the cache was built, in which
    case there is nothing to fingerprint and the cache's own size is
    used instead.
    """
    try:
        st = path.stat()
    except OSError:
        return "source_missing"
    return f"{st.st_size}:{st.st_ino}:{int(st.st_mtime)}"


def read_meta(parquet):
    mp = meta_path_for(parquet)
    if not mp.exists():
        return None
    try:
        return json.loads(mp.read_text())
    except (ValueError):
        return None


def write_meta(parquet, source, rows: Optional[int] = None):
    """Persist cache metadata atomically.

    The row count is recorded with it, so a later check can tell a
    hollow cache from a real one without reading the file's data.
    """
    mp = meta_path_for(parquet)
    try:
        size = parquet.stat().st_size
    except OSError:
        size = 0
    payload = json.dumps({
        "source": str(source),
        "fingerprint": source_fingerprint(source),
        "parquet_size": size,
        "schema_version": _PARQUET_SCHEMA_VERSION,
        "rows": rows,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2)
    try:
        # The temporary name carries the pid, so two builders writing the
        # same window's metadata cannot clobber each other's file.
        tmp = mp.with_suffix(f"{mp.suffix}.{os.getpid()}.tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, mp)
    except OSError as exc:
        # Metadata is best-effort — a missing meta is far cheaper than
        # cascading a crash on every cache read. Log and continue.
        logger.debug(f"[parquet_cache] failed to persist meta for {parquet}: {exc!r}")
        # Clean up partial tmp file if any.
        try:
            tmp = mp.with_suffix(f"{mp.suffix}.{os.getpid()}.tmp")
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def parquet_version_matches(parquet) -> bool:
    """True when the cached parquet carries the current schema version."""
    meta = read_meta(parquet)
    if meta is None:
        return False
    return meta.get("schema_version") == _PARQUET_SCHEMA_VERSION


def parquet_is_hollow(parquet) -> bool:
    """Whether the cached parquet holds no rows at all.

    The binary ``.gz`` path used to write an empty frame for every
    window it could not read as text, and its metadata carried the
    current schema version, so the version check admitted it from then
    on.  The scan then read zero rows and reported "no routing
    activity" for a window that had never been measured.

    The row count is the authority.  The file's size cannot stand in
    for it: an empty parquet and a parquet with a single row differ by
    about a kilobyte, and a window with one announcement is a real
    measurement.

    The metadata carries the count when the cache was written by this
    version of the builder, so the common case costs a metadata read
    rather than a read of the data.  A cache without the count is read.
    """
    try:
        meta = read_meta(parquet)
    except Exception:  # noqa: BLE001 - an unreadable cache is not usable
        return True
    if isinstance(meta, dict) and meta.get("rows") is not None:
        try:
            return int(meta["rows"]) == 0
        except (TypeError, ValueError):
            pass
    try:
        frame = pl.read_parquet(parquet, columns=["announce"])
    except Exception:  # noqa: BLE001 - an unreadable cache is not usable
        return True
    return frame.height == 0


def parquet_is_usable(parquet) -> bool:
    """Whether the cached parquet can be read as a measurement.

    The conditions are the file's own existence, the schema version
    and the rows.  A cache with no rows is useless whatever its
    metadata says, so the row count is checked before the version is
    trusted.
    """
    if not Path(parquet).exists():
        return False
    if not parquet_version_matches(parquet):
        return False
    return not parquet_is_hollow(parquet)


def is_cache_valid(parquet, source):
    if not parquet.exists():
        return False
    meta = read_meta(parquet)
    if meta is None:
        return False
    # A cache written by an older schema version cannot be reused: the
    # withdrawal records it lacks are exactly what the outage detector
    # needs, and a stale file would silently score every event as
    # "no withdrawal, therefore no outage".
    if meta.get("schema_version") != _PARQUET_SCHEMA_VERSION:
        return False
    if source is None:
        return True
    if not source.exists():
        return False
    return meta.get("fingerprint") == source_fingerprint(source)


_SCHEMA = {
    "type": pl.Utf8, "timestamp": pl.Utf8, "announce": pl.Utf8,
    "peer_ip": pl.Utf8, "peer_as": pl.Utf8, "prefix": pl.Utf8,
    "as_path": pl.Utf8, "origin": pl.Utf8, "next_hop": pl.Utf8,
    "local_pref": pl.Utf8, "med": pl.Utf8, "communities": pl.Utf8,
    "atomic_aggregate": pl.Utf8, "aggregator": pl.Utf8, "unknown": pl.Utf8,
    "ts": pl.Datetime,
}


def align_to_canonical(df):
    """Ensure every required column exists; missing columns become null."""
    out = df
    for col, dtype in _SCHEMA.items():
        if col not in out.columns:
            out = out.with_columns(pl.lit(None).alias(col).cast(dtype))
    return out.select(list(_SCHEMA.keys()))


def txt_to_announcements_df(txt_path, include_withdrawals: bool = False):
    """Read a decoded MRT file into the canonical frame.

    ``include_withdrawals`` keeps the ``W`` records.  They are dropped by
    default because every existing consumer (leak, hijack) only reasons
    about announcements, and keeping them would inflate the frame for no
    benefit.  The outage detector needs them -- a withdrawal is the
    physical signature of a route loss -- so it asks for them explicitly.
    """
    df = pl.read_csv(
        txt_path,
        separator="|",
        has_header=False,
        schema_overrides={f"column_{i}": pl.Utf8 for i in range(1, 16)},
        ignore_errors=True,
        # A decoded MRT file occasionally carries a line with more
        # pipe-separated fields than the schema declares.  Without this
        # the whole file fails to parse, which loses every update in
        # the window -- not just the offending line.
        truncate_ragged_lines=True,
        low_memory=False,
    )
    # Re-map whatever columns are present onto canonical names.
    keep_idx = sorted(int(c.split("_")[1]) for c in df.columns if c.startswith("column_"))
    rename = {f"column_{i}": _COLUMNS[i - 1] for i in keep_idx if 1 <= i <= len(_COLUMNS)}
    df = df.rename(rename)
    if not include_withdrawals:
        df = df.filter(pl.col("announce") == "A")
    if df.is_empty():
        return df
    df = df.with_columns(
        parse_timestamp_expr().alias("ts")
    )
    return align_to_canonical(df)


def ensure_parquet(src_path):
    ensure_dirs()
    parquet = parquet_path_for(src_path)
    if is_cache_valid(parquet, src_path):
        return parquet

    df = None
    try:
        if src_path.suffix == ".gz":
            df = read_gz_into_df(src_path)
        else:
            df = txt_to_announcements_df(src_path, include_withdrawals=True)
    except (AttributeError) as exc:
        logger.warning(f"_ensure_parquet failed for {src_path.name}: {exc}")
        return None

    if df is None:
        return None
    if df.is_empty():
        # An empty frame here means the source held no usable updates.
        # Writing it out would replace a good cache with a hollow one,
        # and the hollow file passes the version check from then on.
        return None

    tmp = parquet.with_suffix(f".parquet.{os.getpid()}.tmp")
    df.write_parquet(tmp, compression="zstd", compression_level=3)
    tmp.replace(parquet)
    write_meta(parquet, src_path, rows=df.height)
    return parquet


def read_gz_into_df(gz_path):
    """Read a binary MRT update file into the canonical frame.

    The archive's ``.gz`` files are **binary** MRT, not the pipe-separated
    text that ``bgpdump`` writes.  Reading them as text yields no line
    that contains ``|A|``, so the frame comes back empty and the cache
    is written hollow -- a file that claims to hold a window and holds
    nothing.  The binary form therefore has to be decoded first.

    The decode goes through ``bgpdump``, the same tool that produced the
    text files in the decoded directory, so both paths yield the same
    rows for the same window.
    """
    if decode_gz_to_txt is None:
        return None

    decoded = DECODED_DIR / f"{gz_path.stem}.txt"
    if not (decoded.exists() and decoded.stat().st_size > 0):
        if not decode_gz_to_txt(gz_path, decoded):
            return None
    return txt_to_announcements_df(decoded, include_withdrawals=True)


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
    
    Returns:
    Dict with `candidates`, `would_delete` (count), `bytes_reclaimed`,
    and `errors`. Useful for telemetry / GC reporting."""
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
            meta = read_meta(parquet)
            if meta is None:
                continue
            # Only delete when the parquet was generated from THIS txt
            # (the fingerprint check guards against mismatched regeneration).
            expected_fp = source_fingerprint(txt)
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


def ensure_underlying_source(stamp_str):
    """Make sure at least one of (decoded txt, raw gz) exists for `stamp`."""
    stamp = stamp_str  # NOTE: parameter is `stamp_str`; body below uses `stamp`.
    ensure_dirs()

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
    except (ValueError):
        return None
    ym = cur_dt.strftime("%Y.%m")
    url = f"{RIPE_RIS_URL}{ym}/updates.{stamp}.gz"
    try:
        download_data(url)  # writes to UPDATES_ROOT
    except (AttributeError) as exc:
        logger.debug(f"Download failed for {stamp}: {exc}")
        return None

    if not (gz_path.exists() and is_valid_gz_file(gz_path)):
        return None

    if decode_gz_to_txt(gz_path, txt_path):
        return txt_path if txt_path.exists() else gz_path
    return gz_path


def rebuild_hollow(stamp, txt_path: Path, gz_path: Path) -> Optional[Path]:
    """Replace a cache with no rows by one built from the source.

    A hollow cache is a window that was never measured, so it is
    rebuilt from the raw file rather than read.  The source is the
    decoded text when it is there and the archive's binary gzip
    otherwise.
    """
    for source in (txt_path, gz_path):
        if not (source.exists() and source.stat().st_size > 0):
            continue
        try:
            built = ensure_parquet(source)
        except Exception as exc:  # noqa: BLE001 - the rebuild is best effort
            logger.debug(f"[parquet_cache] rebuild failed for {source}: {exc}")
            continue
        if built is not None and not parquet_is_hollow(built):
            return built
    return None


def iter_window_chunks(
    start: datetime,
    end: datetime,
    *,
    raw: bool = False,
    on_missing: str = "skip",
    columns: Optional[list[str]] = None,
    auto_download: bool = True,
    include_withdrawals: bool = False,
) -> Iterator[pl.DataFrame]:
    """Yield Polars DataFrames covering [start, end] (5-minute windows).

    ``include_withdrawals`` keeps the ``W`` records alongside the ``A``
    ones.  The default drops them, which is what the leak and hijack
    detectors want; the outage detector asks for them because a
    withdrawal is the physical signature of a route loss.
    """
    if columns is None:
        columns = _READ_COLUMNS

    aligned = start.replace(minute=(start.minute // 5) * 5, second=0, microsecond=0)
    cur = aligned
    while cur <= end:
        stamp = cur.strftime("%Y%m%d.%H%M")
        txt_path = DECODED_DIR / f"updates.{stamp}.txt"
        gz_path = UPDATES_ROOT / f"updates.{stamp}.gz"
        parquet = PARQUET_DIR / f"updates.{stamp}.parquet"

        fpath: Optional[Path] = None
        # A parquet file is only usable when its schema version matches the
        # current one.  An older file holds announcements only, so reusing
        # it would silently strip the withdrawals the outage detector needs.
        #
        # A hollow file is not usable either: it carries the current
        # schema version but holds no rows, and reading it would report
        # "no routing activity" for a window that was never measured.
        # The rows are checked by the read below rather than by a second
        # read here, because a read of one column costs as much as a read
        # of all of them.
        if parquet.exists() and parquet_version_matches(parquet):
            fpath = parquet
        elif txt_path.exists() and txt_path.stat().st_size > 0:
            fpath = ensure_parquet(txt_path)
        elif gz_path.exists() and gz_path.stat().st_size > 0:
            fpath = ensure_parquet(gz_path)
        else:
            # No parquet / no txt / no gz — try to fetch from RIS.
            if auto_download:
                src = ensure_underlying_source(stamp)
                if src is not None:
                    fpath = ensure_parquet(src)
            if fpath is None:
                if on_missing == "raise":
                    raise FileNotFoundError(f"No BGP update file for window {stamp}")
                if on_missing == "wait":
                    deadline = time.time() + 30
                    while time.time() < deadline:
                        time.sleep(0.5)
                        if txt_path.exists() and txt_path.stat().st_size > 0:
                            fpath = ensure_parquet(txt_path)
                            break
                        if gz_path.exists() and gz_path.stat().st_size > 0:
                            fpath = ensure_parquet(gz_path)
                            break
                # "skip" or timed out: continue to next window.

        if fpath is None or not Path(fpath).exists():
            cur += timedelta(minutes=5)
            continue

        try:
            df = pl.read_parquet(fpath, columns=columns)
        except (AttributeError) as exc:
            logger.warning(f"parquet read failed for {fpath}: {exc}")
            cur += timedelta(minutes=5)
            continue

        if df.is_empty():
            # A cache with no rows is a window that was never measured.
            # The source may still be there, so the window is rebuilt
            # rather than reported as empty.
            if fpath == parquet and auto_download:
                rebuilt = rebuild_hollow(stamp, txt_path, gz_path)
                if rebuilt is not None:
                    try:
                        df = pl.read_parquet(rebuilt, columns=columns)
                    except (AttributeError) as exc:
                        logger.warning(
                            f"parquet rebuild read failed for {rebuilt}: {exc}")
                        df = None
            if df is None or df.is_empty():
                cur += timedelta(minutes=5)
                continue

        if not raw and "announce" in df.columns:
            if include_withdrawals:
                # "STATE" lines are collector state changes, not BGP
                # updates; they carry no prefix and mean nothing to any
                # detector.
                df = df.filter(pl.col("announce").is_in(["A", "W"]))
            else:
                df = df.filter(pl.col("announce") == "A")

        # Re-confirm window: only emit rows within the current 5-min bucket.
        #
        # The parquet stores naive UTC timestamps, so the bounds have to be
        # naive too.  Aware bounds against a naive column are a schema
        # error in polars, not a comparison that happens to work.
        if "ts" in df.columns:
            ts_lo = cur
            ts_hi = cur + timedelta(minutes=5)
            dtype = df.schema["ts"]
            if getattr(dtype, "time_zone", None) is None:
                ts_lo = ts_lo.replace(tzinfo=None)
                ts_hi = ts_hi.replace(tzinfo=None)
            else:
                ts_lo = ts_lo.replace(tzinfo=timezone.utc)
                ts_hi = ts_hi.replace(tzinfo=timezone.utc)
            try:
                df = df.filter(
                    (pl.col("ts") >= ts_lo) & (pl.col("ts") < ts_hi)
                )
            except (ValueError):
                pass

        # ── Backward-compat column aliases ──────────────────────────────────
        rename_map: dict = {}
        if "as_path" in df.columns and "as-path" not in df.columns:
            rename_map["as_path"] = "as-path"
        if "announce" in df.columns and "A/W" not in df.columns:
            rename_map["announce"] = "A/W"
        if rename_map:
            try:
                df = df.rename(rename_map)
            except (ValueError):
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


def cache_stats():
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