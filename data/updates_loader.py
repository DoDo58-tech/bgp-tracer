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
import pandas as pd
import psutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import UPDATES_DIR

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
RIPE_RIS_URL = "https://data.ris.ripe.net/rrc00/"

def pull_list(ym):
    target_url = urljoin(RIPE_RIS_URL, f"{ym}/")
    res = subprocess.check_output(["curl", "-s", target_url]).decode()
    archive_list = re.findall(
        r'\<a href="(updates\.(\d{4})(\d{2})(\d{2})\.(\d{4})\.gz)"\>', res
        )
    return target_url, archive_list

def get_archive_list(start_time, end_time):
    start_ym = start_time.strftime("%Y.%m")
    end_ym = end_time.strftime("%Y.%m")
    target_url1, archive_list1 = pull_list(start_ym)
    target_url2, archive_list2 = pull_list(end_ym)
    
    if not archive_list1 or not archive_list2:
        logger.error(f"Unable to get data list: {start_time} {end_time}")
        return []
    
    time_list1 = ["".join(i[1:]) for i in archive_list1]
    time_list2 = ["".join(i[1:]) for i in archive_list2]
    t1 = start_time.strftime("%Y%m%d%H%M")
    t2 = end_time.strftime("%Y%m%d%H%M")
    idx1 = max(0, np.searchsorted(time_list1, t1, side="left") - 1)
    idx2 = np.searchsorted(time_list2, t2, side="right")
    
    data = []
    if start_ym == end_ym:
        data = [urljoin(target_url1, i[0]) for i in archive_list1[idx1:idx2]]
    else:
        data = [urljoin(target_url1, i[0]) for i in archive_list1[idx1:]]
        current_month = datetime(start_time.year, start_time.month, 1)
        current_month += relativedelta(months=1)
        upper_bound = datetime(end_time.year, end_time.month, 1)
        
        while current_month < upper_bound:
            cur_ym = current_month.strftime("%Y.%m")
            cur_target_url, cur_archive_list = pull_list(cur_ym)
            data += [urljoin(cur_target_url, i[0]) for i in cur_archive_list]
            current_month += relativedelta(months=1)
        
        data += [urljoin(target_url2, i[0]) for i in archive_list2[:idx2]]
    
    return data

def download_data(url):
    fname = url.split("/")[-1].strip()
    outpath = UPDATES_DIR / fname
    
    if outpath.exists():
        return outpath
    
    os.makedirs(outpath.parent, exist_ok=True)
    
    try:
        subprocess.check_call(["wget", "-q", "-c", url, "-O", str(outpath)], timeout=300)
    except subprocess.TimeoutExpired:
        logger.error(f"Download timeout: {url}")
        raise
    except Exception as e:
        logger.error(f"Failed to download {url}: {e}")
        raise
    
    return outpath


def _disk_busy(threshold: int = 80, sample_seconds: float = 0.2) -> bool:
    """Quick check of disk busy percentage via psutil (single sample)."""
    try:
        c1 = psutil.disk_io_counters()
        if not c1:
            return False
        import time
        time.sleep(sample_seconds)
        c2 = psutil.disk_io_counters()
        if not c2:
            return False
        busy_delta = c2.busy_time - c1.busy_time  # milliseconds
        pct = (busy_delta / (sample_seconds * 1000)) * 100
        return pct >= threshold
    except Exception:
        return False


def _read_updates_file(file_path, columns):
    """Read updates file - optimized for speed."""
    data = []
    
    try:
        if file_path.suffix == '.gz':
            f = gzip.open(file_path, 'rt', encoding='utf-8')
        else:
            f = open(file_path, 'r', encoding='utf-8')
        
        with f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if '|A|' not in line:
                    continue
                
                parts = line.split('|')
                if len(parts) >= 6:
                    # Pad parts to match column count
                    parts.extend([''] * (len(columns) - len(parts)))
                    data.append(parts[:len(columns)])
    
        if not data:
            return None
        
        # Single DataFrame creation - much faster than multiple concat
        df = pd.DataFrame(data, columns=columns)
        return df if not df.empty else None
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return None


def get_updates_streaming(start_time, end_time, workers: int = 1, io_busy_threshold: int = 85):
    columns = [
        'type', 'timestamp', 'A/W', 'peer_ip', 'peer_as', 'prefix', 
        'as-path', 'origin', 'next-hop', 'local-pref', 'med', 
        'communities', 'atomic-aggregate', 'aggregator', 'unknown'
    ]
    
    decoded_dir = UPDATES_DIR / "decoded"
    
    start_minute = (start_time.minute // 5) * 5
    current_time = start_time.replace(minute=start_minute, second=0, microsecond=0)
    
    files_to_process = []
    
    while current_time <= end_time:
        time_str = current_time.strftime("%Y%m%d.%H%M")
        decoded_file = decoded_dir / f"updates.{time_str}.txt"
        
        if decoded_file.exists():
            files_to_process.append(decoded_file)
        else:
            gz_file = UPDATES_DIR / f"updates.{time_str}.gz"
            if gz_file.exists():
                files_to_process.append(gz_file)
        
        current_time += timedelta(minutes=5)
    
    if not files_to_process:
        logger.warning(f"No update files found for time range {start_time} to {end_time}")
        return
    
    logger.info(f"Found {len(files_to_process)} files to process")
    
    # Force single-threaded for better performance (multithreading overhead not worth it)
    logger.info("Reading updates sequentially (single-threaded for optimal performance)")
    
    file_count = 0
    for file_path in sorted(files_to_process):
        try:
            df = _read_updates_file(file_path, columns)
            if df is None or df.empty:
                continue
            yield df
            file_count += 1
            # Only call gc every 10 files to reduce overhead
            if file_count % 10 == 0:
                del df
                gc.collect()
            else:
                del df
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            continue
    
    # Final gc after all files
    gc.collect()


def ensure_updates_available_for_event(event_start, event_end, pre_days: int = 7, post_days: int = 0, max_workers: int = 8):
    if event_end <= event_start:
        logger.error("event_end must be after event_start")
        return []
    window_start = event_start - timedelta(days=pre_days)
    window_end = event_end + timedelta(days=post_days)

    logger.info(
        f"Ensuring updates for window: {window_start.strftime('%Y-%m-%d %H:%M')} to {window_end.strftime('%Y-%m-%d %H:%M')} (pre_days={pre_days}, post_days={post_days}, workers={max_workers})"
    )

    urls = get_archive_list(window_start, window_end)
    if not urls:
        logger.warning("No archive URLs resolved for the requested window.")
        return []

    existing = {}
    todo_urls = []
    for url in urls:
        fname = url.split("/")[-1].strip()
        outpath = UPDATES_DIR / fname
        if outpath.exists():
            existing[url] = outpath
        else:
            todo_urls.append(url)

    logger.info(f"Found {len(existing)} existing files, {len(todo_urls)} to download")

    local_paths = list(existing.values())
    if todo_urls:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
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
    start_col: str = "start_time",
    end_col: str = "end_time",
    pre_days: int = 7,
    post_days: int = 0,
    max_workers: int = 8,
):
    logger.info(f"Loading events table: {xlsx_path}")
    df = pd.read_excel(xlsx_path)
    all_paths = set()
    for idx, row in df.iterrows():
        def parse_datetime(val):
            if isinstance(val, datetime):
                return val
            val_str = str(val).strip()
            if not val_str:
                raise ValueError("empty datetime string")
            pattern = r'^\s*(\d{1,2})/(\d{1,2})/(\d{2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*$'
            match = re.match(pattern, val_str)
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
    parser.add_argument("--max-workers", type=int, default=28, help="Number of parallel download workers (default: 8)")
    
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