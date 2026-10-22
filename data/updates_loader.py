import os
import re
import sys
import gc
import subprocess
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urljoin
from dateutil.relativedelta import relativedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np
import polars as pl
import psutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import UPDATES_DIR, RIPE_RIS_URL, DOWNLOAD_TIMEOUT, GZ_MIN_SIZE

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

BGPDUMP_BIN = "/usr/bin/bgpdump"


def is_valid_gz_file(filepath, min_size = GZ_MIN_SIZE):
    if not isinstance(filepath, Path):
        filepath = Path(filepath)
    if not filepath.exists():
        return False
    if filepath.stat().st_size < min_size:
        return False
    try:
        with gzip.open(filepath, 'rb') as f:
            f.read(1)
        return True
    except Exception:
        return False


def _convert_timestamp(line):
    """bgpdump  MM/DD/YY HH:MM:SS， decoded txt ，。"""
    return line


def decode_gz_to_txt(gz_path, txt_path):
    """ bgpdump  MRT gz  decoded ，。"""
    proc = None
    try:
        proc = subprocess.Popen(
            ["bgpdump", "-M", "-t", "change", str(gz_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=65536,
        )
        written = 0
        # Stream decode → write → close → wait to avoid zombie bgpdump
        # if the consumer raises mid-stream.
        with proc:
            with open(txt_path, 'w', encoding='utf-8') as out:
                try:
                    assert proc.stdout is not None
                    for line in proc.stdout:
                        decoded_line = line.decode('utf-8', errors='ignore').strip()
                        if decoded_line:
                            converted = _convert_timestamp(decoded_line)
                            out.write(converted + '\n')
                            written += 1
                finally:
                    if proc.stdout is not None:
                        proc.stdout.close()
            retcode = proc.wait()
            if retcode != 0:
                raise subprocess.CalledProcessError(retcode, "bgpdump")
        logger.debug(f"Decoded {gz_path.name} -> {txt_path.name} ({written} lines)")
        return True
    except Exception as e:
        logger.error(f"Failed to decode {gz_path.name}: {e}")
        # If the process is still running, terminate it before returning
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
        if txt_path.exists():
            txt_path.unlink()
        return False


def pull_list(year_month):
    target_url = urljoin(RIPE_RIS_URL, f"{year_month}/")
    res = subprocess.check_output(["curl", "-s", target_url]).decode()
    archive_list = re.findall(
        r'\<a href="(updates\.(\d{4})(\d{2})(\d{2})\.(\d{4})\.gz)"\>', res
        )
    return target_url, archive_list


def get_archive_list(start, end):
    start_ym = start.strftime("%Y.%m")
    end_ym = end.strftime("%Y.%m")
    target_url1, archive_list1 = pull_list(start_ym)
    target_url2, archive_list2 = pull_list(end_ym)

    if not archive_list1 or not archive_list2:
        logger.error(f"Unable to get data list: {start} {end}")
        return []

    time_list1 = ["".join(i[1:]) for i in archive_list1]
    time_list2 = ["".join(i[1:]) for i in archive_list2]
    t1 = start.strftime("%Y%m%d%H%M")
    t2 = end.strftime("%Y%m%d%H%M")
    idx1 = max(0, np.searchsorted(time_list1, t1, side="left") - 1)
    idx2 = np.searchsorted(time_list2, t2, side="right")
    
    data = []
    if start_ym == end_ym:
        data = [urljoin(target_url1, i[0]) for i in archive_list1[idx1:idx2]]
    else:
        data = [urljoin(target_url1, i[0]) for i in archive_list1[idx1:]]
        current_month = datetime(start.year, start.month, 1)
        current_month += relativedelta(months=1)
        upper_bound = datetime(end.year, end.month, 1)

        while current_month < upper_bound:
            cur_ym = current_month.strftime("%Y.%m")
            cur_target_url, cur_archive_list = pull_list(cur_ym)
            data += [urljoin(cur_target_url, i[0]) for i in cur_archive_list]
            current_month += relativedelta(months=1)
        
        data += [urljoin(target_url2, i[0]) for i in archive_list2[:idx2]]
    
    return data


def download_data(url, max_retries=3, retry_delay=5):
    fname = url.split("/")[-1].strip()
    outpath = UPDATES_DIR / fname

    if outpath.exists() and not is_valid_gz_file(outpath):
        logger.warning(f"Removing invalid file: {outpath}")
        outpath.unlink()

    if outpath.exists():
        # Bug fix 2026-09-13 (BUG-R72): ``is_valid_gz_file`` only checks the
        try:
            import gzip as _gzip
            with _gzip.open(outpath, "rb") as _gzf:
                while _gzf.read(1 << 20):
                    pass
        except Exception as _exc:
            logger.warning(
                f"Removing partial/unreadable gz (probe failed): {outpath}: {_exc}"
            )
            try:
                outpath.unlink()
            except OSError:
                pass
        if outpath.exists():
            return outpath

    os.makedirs(outpath.parent, exist_ok=True)

    for attempt in range(max_retries):
        try:
            subprocess.check_call(
                ["wget", "-q", "-c", "-T", "120", url, "-O", str(outpath)],
                timeout=150
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"Download timeout (attempt {attempt+1}/{max_retries}): {fname}")
            if outpath.exists():
                outpath.unlink()
            if attempt < max_retries - 1:
                import time
                time.sleep(retry_delay)
            continue
        except Exception as e:
            logger.warning(f"Failed to download (attempt {attempt+1}/{max_retries}): {fname}: {e}")
            if outpath.exists():
                outpath.unlink()
            if attempt < max_retries - 1:
                import time
                time.sleep(retry_delay)
            continue

        if not is_valid_gz_file(outpath):
            logger.warning(f"Downloaded file is invalid (attempt {attempt+1}/{max_retries}): {outpath}")
            outpath.unlink()
            if attempt < max_retries - 1:
                import time
                time.sleep(retry_delay)
            continue
        return outpath

    raise ValueError(f"Download failed after {max_retries} attempts: {fname}")


def _disk_busy(threshold = 80, sample_seconds = 0.2):
    try:
        c1 = psutil.disk_io_counters()
        if not c1:
            return False
        import time
        time.sleep(sample_seconds)
        c2 = psutil.disk_io_counters()
        if not c2:
            return False
        busy_delta = c2.busy_time - c1.busy_time
        pct = (busy_delta / (sample_seconds * 1000)) * 100
        return pct >= threshold
    except Exception:
        return False


#  (500MB)，
LARGE_FILE_THRESHOLD = 500 * 1024 * 1024  # 500MB

def read_updates_file(filepath, columns):
    """
    Read a BGP update file into a Polars DataFrame.

    Uses pl.read_csv() with explicit column count to avoid predicate-pushdown
    column pruning that breaks files with fewer columns than expected.

    For large files (>500MB), uses chunked reading to prevent OOM.
    Falls back to manual line parsing if read fails.
    """
    try:
        separator = '|'
        
        # ，
        file_size = file_path.stat().st_size if isinstance(file_path, Path) else Path(file_path).stat().st_size
        if file_size > LARGE_FILE_THRESHOLD:
            logger.debug(f"Large file detected ({file_size/1024/1024:.0f}MB), using chunked reading: {file_path.name}")
            return _read_updates_chunked(file_path, columns, separator)
        
        df = pl.read_csv(
            file_path,
            separator=separator,
            has_header=False,
            dtypes={str(i): pl.Utf8 for i in range(len(columns))},
            ignore_errors=True,
            low_memory=True,
        )
        # Filter for Announce messages only
        df = df.filter(pl.col('column_3') == 'A')
        # Rename columns — only alias columns that actually exist in the file
        # (MRT files can have 8 or 15+ columns depending on router config)
        df = df.select([
            pl.col(f'column_{i}').alias(col)
            for i, col in enumerate(columns, start=1)
            if f'column_{i}' in df.columns
        ])

        if df.is_empty():
            return None
        return df

    except Exception as e:
        # Fallback: manual line-by-line parsing
        logger.debug(f"read_csv failed for {file_path}, using fallback: {e}")
        return _read_updates_line_by_line(file_path, columns)


def _read_updates_chunked(file_path, columns, separator='|', chunk_size=50000):
    """
    ，chunk_size，。
    ，yield。
    """
    try:
        opener = gzip.open if (isinstance(file_path, Path) and file_path.suffix == '.gz') or (isinstance(file_path, str) and file_path.endswith('.gz')) else open
        with opener(file_path, 'rt', encoding='utf-8') as f:
            data = []
            line_count = 0
            for line in f:
                line = line.strip()
                if not line or '|A|' not in line:
                    continue
                parts = line.split('|')
                if len(parts) >= 6:
                    parts.extend([''] * (len(columns) - len(parts)))
                    data.append(parts[:len(columns)])
                    line_count += 1
                    
                    if len(data) >= chunk_size:
                        # chunk_sizeyield，
                        chunk_df = pl.DataFrame(data, schema=columns, strict=False)
                        yield chunk_df
                        data = []
                        gc.collect()
            
            if data:
                chunk_df = pl.DataFrame(data, schema=columns, strict=False)
                yield chunk_df
                del data
                gc.collect()
    except Exception as e:
        logger.error(f"Chunked reading failed for {file_path}: {e}")
        return


def _read_updates_line_by_line(file_path, columns):
    """fallback"""
    data = []
    try:
        opener = gzip.open if (isinstance(file_path, Path) and file_path.suffix == '.gz') or (isinstance(file_path, str) and file_path.endswith('.gz')) else open
        with opener(file_path, 'rt', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or '|A|' not in line:
                    continue
                parts = line.split('|')
                if len(parts) >= 6:
                    parts.extend([''] * (len(columns) - len(parts)))
                    data.append(parts[:len(columns)])
        if not data:
            return None
        df = pl.DataFrame(data, schema=columns, strict=False)
        return df if not df.is_empty() else None
    except Exception as inner:
        logger.error(f"Line-by-line fallback also failed for {file_path}: {inner}")
        return None


def get_updates_streaming(start_time, end_time, workers = 16, io_busy_threshold = 85, auto_download = True):
    """Stream BGP announcements for [start_time, end_time] as Polars DataFrames.

    Single-source-of-truth backed by `data.parquet_cache`, which already
    implements a four-layer cache:

        1. {file}.parquet  – pre-parsed binary (5-25x smaller than txt)
        2. decoded/*.txt   – already bgpdump-decoded text
        3. .gz             – raw MRT gz archived by RIPE RIS
        4. Network         – download from RIPE RIS, then decode

    On first hit that misses every layer the function transparently downloads
    the missing .gz files into UPDATES_DIR, decodes them into DECODED_DIR, and
    relies on `parquet_cache.iter_window_chunks` to populate the parquet index
    on the fly. Subsequent runs hit layer 1 and skip network entirely.

    Each yielded DataFrame carries the canonical schema:
        type, timestamp, A/W, peer_ip, peer_as, prefix,
        as-path, origin, next-hop, local-pref, med,
        communities, atomic-aggregate, aggregator, unknown, ts

    Args:
        start_time, end_time: window (UTC, datetime).
        workers: thread-pool size for the in-process decode fallback only
            (most chunks are already cached; workers is unused on warm cache).
        io_busy_threshold / auto_download: kept for backward compatibility.
    """
    from data.parquet_cache import (
        iter_window_chunks,
        list_window_files,
        UPDATES_ROOT,
        DECODED_DIR,
    )

    start_time = _to_utc_naive(start_time)
    end_time = _to_utc_naive(end_time)
    if start_time is None and end_time is None:
        # Both bounds missing — caller is in an error state. Bail out
        return
    if end_time is not None and start_time is not None and end_time < start_time:
        return

    # 1) figure out which 5-minute buckets fall inside the requested window
    files_to_ensure = list_window_files(start_time, end_time)
    missing_buckets: list[datetime] = []
    for p in files_to_ensure:
        if not p.exists() or p.stat().st_size == 0:
            missing_buckets.append(_bucket_start_from_path(p))

    # 2) download + decode whatever is missing
    if missing_buckets and auto_download:
        logger.info(f"Auto-downloading {len(missing_buckets)} missing BGP buckets for {start_time}→{end_time}")
        _download_and_decode_buckets(missing_buckets)

    # 3) stream through the cache; on_missing='skip' returns nothing for
    if workers <= 1 or not auto_download:
        for chunk in iter_window_chunks(start_time, end_time, on_missing="skip"):
            if "announce" in chunk.columns and "A/W" not in chunk.columns:
                chunk = chunk.rename({"announce": "A/W"})
            yield chunk
        return

    import queue as _queue
    import threading as _threading

    # Cap workers to avoid pathological spawn on tiny windows.
    effective_workers = max(2, min(int(workers), 32))

    sentinel = object()
    # Queue depth of 2× workers keeps the consumer fed even when a large
    q: _queue.Queue = _queue.Queue(maxsize=effective_workers * 2)

    def _producer():
        try:
            for chunk in iter_window_chunks(start_time, end_time, on_missing="skip"):
                if "announce" in chunk.columns and "A/W" not in chunk.columns:
                    chunk = chunk.rename({"announce": "A/W"})
                q.put(chunk)
        except Exception as exc:
            logger.error(f"[updates_loader] producer error: {exc}")
        finally:
            q.put(sentinel)

    _t = _threading.Thread(target=_producer, daemon=True, name="bgp-parquet-prefetch")
    _t.start()
    try:
        while True:
            chunk = q.get()
            if chunk is sentinel:
                break
            yield chunk
    finally:
        # Make sure the producer doesn't outlive a partially-consumed stream
        if _t.is_alive():
            _t.join(timeout=1.0)


def _to_utc_naive(dt):
    """Normalise any datetime into a UTC-naive datetime.

    The cache layer stores timestamps as UTC-naive `Datetime` columns. Mixing
    tz-aware and tz-naive values in Polars filters silently returns zero rows,
    so we force UTC + drop tzinfo before handing the window to the cache.
    """
    if dt is None:
        return None
    try:
        from datetime import datetime as _dt
        if isinstance(dt, _dt):
            if dt.tzinfo is not None:
                from datetime import timezone
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
    except Exception:
        pass
    return dt


def _bucket_start_from_path(filepath):
    """Parse updates.YYYYMMDD.HHMM.{txt,gz} -> datetime at bucket start (UTC)."""
    from datetime import datetime as _dt
    name = Path(filepath).name
    stem = name.rsplit(".", 1)[0]              # updates.YYYYMMDD.HHMM
    parts = stem.split(".")
    return _dt.strptime(f"{parts[1]}{parts[2]}", "%Y%m%d%H%M")


def _download_and_decode_buckets(buckets):
    """ bucket。

    ： (16 ),  (4 workers,  bgpdump CPU )。
    decode ， bgpdump  fork 。
    Each bucket is independent so failures don't cascade.
    """
    decoded_dir = UPDATES_DIR / "decoded"
    decoded_dir.mkdir(parents=True, exist_ok=True)

    # First: parallel download all missing gz files
    todo = []
    for file_time in buckets:
        ym = file_time.strftime("%Y.%m")
        time_str = file_time.strftime("%Y%m%d.%H%M")
        url = f"{RIPE_RIS_URL}{ym}/updates.{time_str}.gz"
        gz_path = UPDATES_DIR / f"updates.{time_str}.gz"
        todo.append((file_time, url, gz_path))

    download_workers = min(8, len(todo))
    logger.info(f"[backfill] parallel downloading {len(todo)} gz files (workers={download_workers})")
    with ThreadPoolExecutor(max_workers=download_workers) as ex:
        futs = [ex.submit(download_data, url) for (_, url, _) in todo]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:
                logger.debug(f"[backfill] download sub-task failed: {e}")

    # Second: parallel decode (bgpdump-bound; 4 workers = ~ ok on 2-core VM)
    decode_workers = min(4, max(1, (os.cpu_count() or 2)))
    ok = err = 0
    if decode_workers == 1:
        # No ThreadPool overhead
        for (_, _, gz_path) in todo:
            time_str = gz_path.stem.replace("updates.", "")
            txt_path = decoded_dir / f"updates.{time_str}.txt"
            try:
                if decode_gz_to_txt(gz_path, txt_path):
                    ok += 1
                else:
                    err += 1
            except Exception as e:
                logger.debug(f"decode {gz_path.name} failed: {e}")
                err += 1
    else:
        logger.info(f"[backfill] parallel decoding {len(todo)} gz files (workers={decode_workers})")
        def _decode_one(args):
            _, _, gz_path = args
            time_str = gz_path.stem.replace("updates.", "")
            txt_path = decoded_dir / f"updates.{time_str}.txt"
            try:
                return (True, decode_gz_to_txt(gz_path, txt_path))
            except Exception as e:
                return (False, e)

        with ThreadPoolExecutor(max_workers=decode_workers) as ex:
            for ok_, res in ex.map(_decode_one, todo):
                if ok_ and res:
                    ok += 1
                else:
                    err += 1

    logger.info(f"Bucket download/decode: ok={ok}, err={err}")


def _read_files_sequential(files_to_process, columns):
    file_count = 0
    for file_path in sorted(files_to_process):
        try:
            result = read_updates_file(file_path, columns)
            if result is None:
                continue
            
            # generator
            if hasattr(result, '__iter__') and not isinstance(result, pl.DataFrame):
                for chunk_df in result:
                    if chunk_df is not None and not chunk_df.is_empty():
                        file_count += 1
                        yield chunk_df
                        if file_count % 10 == 0:
                            del chunk_df
                            gc.collect()
            else:
                if not result.is_empty():
                    file_count += 1
                    yield result
                    if file_count % 10 == 0:
                        del result
                        gc.collect()
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            continue
    gc.collect()


def ensure_updates_available_for_event(event_start, event_end, pre_days = 7, post_days = 0, max_workers = 16):
    if event_end <= event_start:
        logger.error("event_end must be after event_start")
        return []
    window_start = event_start - timedelta(days=pre_days)
    window_end = event_end + timedelta(days=post_days)

    logger.info(
        f"Ensuring updates for window: {window_start.strftime('%Y-%m-%d %H:%M')} to {window_end.strftime('%Y-%m-%d %H:%M')} (pre_days={pre_days}, post_days={post_days}, workers={max_workers})"
    )
    if max_workers > 16:
        effective_workers = 16
        logger.info(f"Limiting workers to {effective_workers} to avoid server rate limiting")
    else:
        effective_workers = max_workers

    urls = get_archive_list(window_start, window_end)
    if not urls:
        logger.warning("No archive URLs resolved for the requested window.")
        return []

    existing = {}
    todo_urls = []
    for url in urls:
        fname = url.split("/")[-1].strip()
        outpath = UPDATES_DIR / fname
        if outpath.exists() and is_valid_gz_file(outpath):
            existing[url] = outpath
        else:
            if outpath.exists():
                logger.warning(f"Removing invalid existing file: {outpath}")
                outpath.unlink()
            todo_urls.append(url)

    logger.info(f"Found {len(existing)} existing files, {len(todo_urls)} to download")

    local_paths = list(existing.values())
    if todo_urls:
        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            future_to_url = {executor.submit(download_data, url): url for url in todo_urls}
            completed = 0
            for future in as_completed(future_to_url):
                completed += 1
                url = future_to_url[future]
                try:
                    fpath = future.result()
                    local_paths.append(fpath)
                    if completed % 10 == 0 or completed == len(todo_urls):
                        logger.info(f"Progress: {completed}/{len(todo_urls)} files downloaded")
                except Exception as e:
                    logger.error(f"Failed to download {url}: {e}")

    logger.info(f"Prepared {len(local_paths)} files for the event window")
    return local_paths


def ensure_updates_from_xlsx(
    xlsx_path: Path,
    start_col = "start_time",
    end_col = "end_time",
    pre_days = 7,
    post_days = 0,
    max_workers = 16,
):
    logger.info(f"Loading events table: {xlsx_path}")
    # Use polars for reading Excel files (faster than pandas)
    df = pl.read_excel(xlsx_path)
    all_paths = set()
    for idx, row in enumerate(df.iter_rows(named=True)):
        def parse_datetime(val):
            if isinstance(val, datetime):
                return val
            val_str = str(val).strip()
            if not val_str:
                raise ValueError("empty datetime string")
            pattern1 = r'^\s*(\d{1,2})/(\d{1,2})/(\d{2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*$'
            match = re.match(pattern1, val_str)
            if match:
                month, day, year, hour, minute, second = match.groups()
                year = int(year)
                year += 2000 if year < 100 else 0
                second = int(second) if second is not None else 0
                return datetime(
                    year=int(year),
                    month=int(month),
                    day=int(day),
                    hour=int(hour),
                    minute=int(minute),
                    second=second,
                )
            pattern2 = r'^\s*(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*$'
            match = re.match(pattern2, val_str)
            if match:
                year, month, day, hour, minute, second = match.groups()
                second = int(second) if second is not None else 0
                return datetime(
                    year=int(year),
                    month=int(month),
                    day=int(day),
                    hour=int(hour),
                    minute=int(minute),
                    second=second,
                )
            raise ValueError(f"Unsupported datetime format: {val_str}")
        
        try:
            s = parse_datetime(row[start_col])
            e = parse_datetime(row[end_col])
            paths = ensure_updates_available_for_event(
                s,
                e,
                pre_days=pre_days,
                post_days=post_days,
                max_workers=max_workers,
            )
            all_paths.update(paths)
        except Exception as err:
            logger.error(f"Failed for row {idx} (start={row[start_col]}, end={row[end_col]}): {err}")
            continue

    logger.info(f"Prepared total {len(all_paths)} files for {len(df)} events")
    return sorted(all_paths)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Prepare BGP update files from an events table")
    parser.add_argument("--xlsx", required=True, help="Path to Excel/CSV listing multiple events")
    parser.add_argument("--start-col", default="start_time", help="Column for event start time (default: start_time)")
    parser.add_argument("--end-col", default="end_time", help="Column for event end time (default: end_time)")
    parser.add_argument("--pre-days", type=int, default=7, help="Days before event-start to include (default: 7)")
    parser.add_argument("--post-days", type=int, default=1, help="Days after event-end to include (default: 0)")
    parser.add_argument("--max-workers", type=int, default=16, help="Number of parallel download workers (default: 16)")
    
    args = parser.parse_args()
    
    try:
        paths = ensure_updates_from_xlsx(
            Path(args.xlsx),
            args.start_col,
            args.end_col,
            pre_days=args.pre_days,
            post_days=args.post_days,
            max_workers=args.max_workers,
        )
    except Exception as e:
        logger.error(f"Failed to prepare updates from Excel: {e}")
        sys.exit(1)

    print("Prepared files:")
    for p in paths:
        print(str(p))
    print(f"Total: {len(paths)} files")
