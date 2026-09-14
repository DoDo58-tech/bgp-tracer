#!/usr/bin/env python3
"""
parquet_convert_and_purge.py
=============================

一次性工具：把 data/updates_rrc00/decoded/*.txt 全部转为 parquet，
然后删除对应的 decoded/*.txt，回收磁盘空间。

设计要点：
  1. 先全量生成 parquet（复用 `data.parquet_cache._ensure_parquet`，
     它已经处理了 gz→txt→parquet 的链路 + meta.json fingerprint），
     不修改现有缓存逻辑。
  2. 转换完成后，再用 `purge_decoded_txt(only_with_parquet=True, dry_run=False)`
     安全删除冗余 txt（只删有 parquet 镜像的 txt）。
  3. 用 ThreadPoolExecutor 并发转 parquet，避免单进程串行几个小时。
  4. 任何时候通过 Ctrl-C 中断：保留已生成的 parquet，已删除的 txt
     不会回退（gz 原始文件仍保留，重新解码即可）。

用法：
    python scripts/parquet_convert_and_purge.py [--workers N] [--keep-decoded]
                                                 [--batch-size 1000]
                                                 [--parquet-only]

退出码：
    0  成功
    1  部分失败但仍可继续
    2  致命错误
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Allow `python scripts/parquet_convert_and_purge.py` to import bgp_tracer
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from utils.logger import logger
from data.parquet_cache import (
    DECODED_DIR,
    PARQUET_DIR,
    _ensure_parquet,
    cache_stats,
    purge_decoded_txt,
    parquet_path_for,
)


def _convert_one(txt: Path) -> tuple[Path, bool, str]:
    try:
        parquet = _ensure_parquet(txt)
        if parquet is None:
            return txt, False, "_ensure_parquet returned None"
        return txt, True, ""
    except Exception as exc:  # noqa: BLE001 - log everything for visibility
        return txt, False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=8,
                        help="Number of parallel parquet converters (default 8)")
    parser.add_argument("--batch-size", type=int, default=2000,
                        help="Process in batches of N txt files (memory control)")
    parser.add_argument("--keep-decoded", action="store_true",
                        help="Only generate parquet; do NOT delete decoded txt")
    parser.add_argument("--parquet-only", action="store_true",
                        help="Only convert txt → parquet, skip purge entirely")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would happen without writing/deleting")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit to first N files (debug)")
    args = parser.parse_args()

    if not DECODED_DIR.exists():
        logger.error(f"DECODED_DIR missing: {DECODED_DIR}")
        return 2

    txts = sorted(DECODED_DIR.glob("updates.*.txt"))
    if args.limit > 0:
        txts = txts[: args.limit]

    pending = [t for t in txts if not parquet_path_for(t).exists()]
    logger.info(
        f"[convert] total={len(txts)} pending_parquet={len(pending)} "
        f"workers={args.workers} dry_run={args.dry_run}"
    )

    if args.dry_run:
        logger.info("[convert] DRY RUN — no parquet written, no txt deleted")
        dry = purge_decoded_txt(only_with_parquet=True, dry_run=True, progress_every=0)
        logger.info(
            f"[convert] dry-run purge: {dry['candidates']} candidates, "
            f"{dry['bytes_reclaimed'] // 1024 // 1024} MB reclaimable"
        )
        return 0

    if not pending and not args.parquet_only:
        logger.info("[convert] nothing to convert; running purge now")
    else:
        t0 = time.time()
        ok = err = 0
        errors: list[str] = []

        for batch_start in range(0, len(pending), args.batch_size):
            batch = pending[batch_start: batch_start + args.batch_size]
            batch_ok = batch_err = 0
            with ThreadPoolExecutor(max_workers=args.workers,
                                    thread_name_prefix="pq-conv") as ex:
                futures = {ex.submit(_convert_one, t): t for t in batch}
                for fut in as_completed(futures):
                    _txt, success, msg = fut.result()
                    if success:
                        ok += 1
                        batch_ok += 1
                    else:
                        err += 1
                        batch_err += 1
                        if len(errors) < 10:
                            errors.append(msg)
            elapsed = time.time() - t0
            logger.info(
                f"[convert] {ok + err}/{len(pending)} "
                f"(ok={ok}, err={err}) elapsed={elapsed:.0f}s"
            )
            if errors:
                for e in errors[:3]:
                    logger.warning(f"  err sample: {e}")

        elapsed = time.time() - t0
        rate = ok / elapsed if elapsed > 0 else 0
        logger.info(
            f"[convert] done: ok={ok}, err={err}, "
            f"elapsed={elapsed:.0f}s ({rate:.1f} files/s)"
        )
        if err and err == len(pending):
            logger.error("[convert] ALL conversions failed — investigate before purging")
            return 1

    if args.parquet_only:
        return 0

    # Step 2: purge redundant decoded txt (only those with valid parquet mirror).
    logger.info("[purge] starting decoded txt cleanup")
    res = purge_decoded_txt(only_with_parquet=True, dry_run=False, progress_every=500)
    logger.info(
        f"[purge] deleted={res.get('deleted', 0)} "
        f"bytes={res['bytes_reclaimed'] // 1024 // 1024} MB "
        f"errors={res['errors']}"
    )

    stats = cache_stats()
    logger.info(
        f"[purge] parquet cache now: {stats['count']} files, "
        f"{stats['total_size_mb']:.1f} MB"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
