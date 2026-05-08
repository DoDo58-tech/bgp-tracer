#!/usr/bin/env python3
"""
Count MRT records ("messages") in a RIPE RIS updates file.

RIPE RIS update dumps are MRT formatted. Each MRT record has a 12-byte header:
  - timestamp: 4 bytes (uint32, big-endian)
  - type:      2 bytes (uint16, big-endian)
  - subtype:   2 bytes (uint16, big-endian)
  - length:    4 bytes (uint32, big-endian)  payload length in bytes

We count records by iterating headers and skipping payload.
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Optional


MRT_HEADER_LEN = 12


@dataclass(frozen=True)
class Counts:
    total_records: int
    bgp4mp_records: int
    bytes_consumed: int


def _open_maybe_gzip(path: str) -> BinaryIO:
    # RIPE RIS files are often .gz; allow both compressed and plain MRT.
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def count_mrt_records(path: str, *, limit: Optional[int] = None) -> Counts:
    total = 0
    bgp4mp = 0
    consumed = 0

    with _open_maybe_gzip(path) as f:
        while True:
            hdr = f.read(MRT_HEADER_LEN)
            if not hdr:
                break
            if len(hdr) != MRT_HEADER_LEN:
                raise EOFError(
                    f"Truncated MRT header: expected {MRT_HEADER_LEN} bytes, got {len(hdr)}"
                )

            ts, mrt_type, mrt_subtype, length = struct.unpack("!IHHI", hdr)
            _ = ts  # timestamp not used for counting

            payload = f.read(length)
            if len(payload) != length:
                raise EOFError(
                    f"Truncated MRT payload: expected {length} bytes, got {len(payload)}"
                )

            total += 1
            # MRT type 16 is BGP4MP (common for RIS update dumps).
            if mrt_type == 16:
                bgp4mp += 1

            consumed += MRT_HEADER_LEN + length
            if limit is not None and total >= limit:
                break

    return Counts(total_records=total, bgp4mp_records=bgp4mp, bytes_consumed=consumed)


def main() -> None:
    ap = argparse.ArgumentParser(description="Count MRT records in a RIPE RIS updates file")
    ap.add_argument("path", help="Path to MRT file (.gz supported), e.g. updates.20250128.2115.gz")
    ap.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only read first N records (debug). Default: read all",
    )
    args = ap.parse_args()

    path = os.path.abspath(args.path)
    counts = count_mrt_records(path, limit=args.limit)

    print(f"path: {path}")
    print(f"total_mrt_records: {counts.total_records}")
    print(f"bgp4mp_records: {counts.bgp4mp_records}")
    print(f"bytes_consumed: {counts.bytes_consumed}")


if __name__ == "__main__":
    main()

