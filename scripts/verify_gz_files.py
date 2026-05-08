#!/usr/bin/env python3
"""
验证 BGP update gz 文件是否损坏
"""
import gzip
import sys
from pathlib import Path

def is_valid_gz(file_path: Path, min_size: int = 1000) -> bool:
    """检查 gzip 文件是否有效（非空、可解压）"""
    if not file_path.exists():
        return False
    if file_path.stat().st_size < min_size:
        return False
    try:
        with gzip.open(file_path, 'rb') as f:
            f.read(1)
        return True
    except Exception:
        return False

def check_directory(data_dir: str):
    data_path = Path(data_dir)
    if not data_path.exists():
        print(f"目录不存在: {data_dir}")
        return

    empty_files = []      # 0字节文件
    corrupt_files = []     # 损坏文件
    valid_files = []      # 有效文件
    total_size = 0

    for f in sorted(data_path.glob("*.gz")):
        size = f.stat().st_size
        total_size += size
        if size == 0:
            empty_files.append(f.name)
        elif not is_valid_gz(f):
            corrupt_files.append((f.name, size))
        else:
            valid_files.append(f.name)

    print(f"\n{'='*60}")
    print(f"检查目录: {data_dir}")
    print(f"{'='*60}")
    print(f"总文件数: {len(empty_files) + len(corrupt_files) + len(valid_files)}")
    print(f"有效文件: {len(valid_files)}")
    print(f"空文件(0字节): {len(empty_files)}")
    print(f"损坏文件(非gzip): {len(corrupt_files)}")
    print(f"总大小: {total_size / 1024 / 1024:.1f} MB")
    print(f"{'='*60}")

    if empty_files:
        print(f"\n空文件列表 ({len(empty_files)} 个):")
        for fname in empty_files[:20]:
            print(f"  - {fname}")
        if len(empty_files) > 20:
            print(f"  ... 还有 {len(empty_files) - 20} 个")

    if corrupt_files:
        print(f"\n损坏文件列表 ({len(corrupt_files)} 个):")
        for fname, size in corrupt_files[:20]:
            print(f"  - {fname} ({size} bytes)")
        if len(corrupt_files) > 20:
            print(f"  ... 还有 {len(corrupt_files) - 20} 个")

    if not empty_files and not corrupt_files:
        print("\n所有文件均正常！")

    # 删除损坏文件
    if empty_files or corrupt_files:
        print(f"\n删除空文件和损坏文件...")
        for fname in empty_files:
            (data_path / fname).unlink()
            print(f"  删除: {fname}")
        for fname, _ in corrupt_files:
            (data_path / fname).unlink()
            print(f"  删除: {fname}")
        print(f"共删除 {len(empty_files) + len(corrupt_files)} 个文件")

    return len(empty_files) + len(corrupt_files)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        data_dir = sys.argv[1]
    else:
        data_dir = "/data/bgp_tracer/data/updates_rrc00"
    
    check_directory(data_dir)
