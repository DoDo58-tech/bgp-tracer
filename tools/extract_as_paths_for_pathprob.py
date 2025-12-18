import os
import sys
from pathlib import Path
from collections import Counter
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.updates_loader import get_updates_streaming
from utils.logger import logger
from config import PROJECT_ROOT


def parse_as_path(as_path_str):
    if not as_path_str:
        return []
    
    if '|' in as_path_str:
        path = as_path_str.split('|')
    else:
        path = as_path_str.split()
    
    path = [asn.strip() for asn in path if asn.strip()]
    
    cleaned_path = []
    for asn in path:
        if asn.startswith('{') and asn.endswith('}'):
            as_set = asn[1:-1].split(',')
            if as_set:
                cleaned_path.append(as_set[0].strip())
        else:
            cleaned_path.append(asn)
    
    return cleaned_path


def extract_as_paths_from_bgp_data(start_time, end_time, output_dir, min_path_length=2):
    try:
        start_dt = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(str(end_time), "%Y-%m-%d %H:%M")
    except Exception as e:
        logger.error(f"Invalid time format: {e}")
        return None
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    path_counter = Counter()
    
    total_updates = 0
    chunk_count = 0
    
    logger.info(f"Extracting AS paths from {start_time} to {end_time}")
    
    for df_chunk in get_updates_streaming(start_dt, end_dt):
        chunk_count += 1
        
        if df_chunk is None or df_chunk.empty:
            continue
        
        announcements = df_chunk[df_chunk['A/W'] == 'A']
        if announcements.empty:
            continue
        
        total_updates += len(announcements)
        
        for idx, row in announcements.iterrows():
            as_path_str = str(row.get('as-path', ''))
            if not as_path_str:
                continue
            
            path = parse_as_path(as_path_str)
            
            if len(path) < min_path_length:
                continue
            
            path_str = '|'.join(path)
            path_counter[path_str] += 1
        
        if chunk_count % 10 == 0:
            logger.info(f"Processed {chunk_count} chunks, {total_updates} updates, {len(path_counter)} unique paths")
    
    logger.info(f"Extraction complete: {total_updates} updates, {len(path_counter)} unique paths")
    
    output_file = output_path / "as_paths.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        for path, count in path_counter.items():
            if count > 1:
                f.write(f"{path} {count}\n")
            else:
                f.write(f"{path}\n")
    
    logger.info(f"AS paths saved to: {output_file}")
    logger.info(f"Total paths: {len(path_counter)}")
    logger.info(f"Total path occurrences: {sum(path_counter.values())}")
    
    return str(output_file)


def main():
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start_time",
        type=str,
        required=True,
        help="Start time (format: YYYY-MM-DD HH:MM)"
    )
    parser.add_argument(
        "--end_time",
        type=str,
        required=True,
        help="End time (format: YYYY-MM-DD HH:MM)"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default=str(PROJECT_ROOT / "data" / "as_paths"),
        help="Output directory for extracted paths"
    )
    parser.add_argument(
        "--min_path_length",
        type=int,
        default=2,
        help="Minimum AS path length to include (default: 2)"
    )
    
    args = parser.parse_args()
    
    output_file = extract_as_paths_from_bgp_data(
        args.start_time,
        args.end_time,
        args.output_dir,
        args.min_path_length
    )
    
    if output_file:
        print(f"\n✓ Success! AS paths extracted to: {output_file}")
        print(f"\nNext steps:")
        print(f"  1. Use this file with PathProb_AE:")
        print(f"     cd /data/PathProb_AE")
        print(f"     python3 infer_prob/asrel_prob.py \\")
        print(f"       --path_dir {os.path.dirname(output_file)} \\")
        print(f"       --print_dir test_data/prob_inference/result/202506")
    else:
        print("\n✗ Failed to extract AS paths")
        sys.exit(1)


if __name__ == "__main__":
    main()

