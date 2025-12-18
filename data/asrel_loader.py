import os
import re
import sys
import json
import subprocess
from datetime import datetime
import numpy as np
from pathlib import Path
from typing import Dict, Set, List
from urllib.parse import urljoin

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import ASREL_DIR

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
CAIDA_ASREL_URL = "https://publicdata.caida.org/datasets/as-relationships/serial-1/"

def get_available_dates():
    try:
        res = subprocess.check_output(["curl", "-s", CAIDA_ASREL_URL]).decode()
        res = re.sub(r"\s\s+", " ", res.replace("\n", " "))
        
        file_pattern = r'href="(\d{8}\.as-rel\.txt\.bz2)"'
        files = re.findall(file_pattern, res)
        
        available_dates = [file.split('.')[0] for file in files]
        
        return available_dates
    except Exception as e:
        print(f"Failed to get available dates: {e}")
        return []


def get_asrel_url(target_time):
    target_date = target_time.strftime("%Y%m%d")
    available_dates = get_available_dates()
    available_dates = sorted([int(date) for date in available_dates])
    
    idx = np.searchsorted(available_dates, int(target_date), "right")
    if idx == 0:
        idx = 1  # Take the earliest available file if target is before all files
        
    closest_date = available_dates[idx-1]
    closest_date_str = str(closest_date)
    
    logger.info(f"Found closest available date: {closest_date_str}")
    
    file_name = f"{closest_date_str}.as-rel.txt.bz2"
    return urljoin(CAIDA_ASREL_URL, file_name)


def load_asrel(fpath):
    as_to_providers = {}
    as_to_peers = {}
    
    try:
        with open(fpath, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                    
                parts = line.strip().split('|')
                if len(parts) < 3:
                    continue
                    
                as1 = parts[0]
                as2 = parts[1]
                rel_type = int(parts[2])
                
                # rel_type: -1 means as1 is provider of as2 (as2 is customer of as1)
                # rel_type: 0 means as1 and as2 are peers
                
                # Record provider relationships
                if rel_type == -1:
                    # as1 is provider of as2
                    if as2 not in as_to_providers:
                        as_to_providers[as2] = []
                    as_to_providers[as2].append(as1)
                elif rel_type == 0:
                    # Peer relationships
                    if as1 not in as_to_peers:
                        as_to_peers[as1] = []
                    if as2 not in as_to_peers:
                        as_to_peers[as2] = []
                    as_to_peers[as1].append(as2)
                    as_to_peers[as2].append(as1)
    except Exception as e:
        logger.error(f"Error loading AS relationship data: {e}")
    
    return {
        'providers': as_to_providers,
        'peers': as_to_peers
    }


def download_asrel(url, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    compressed_filename = url.split('/')[-1]
    txt_filename = compressed_filename.replace('.bz2', '')
    txt_output_path = output_dir / txt_filename
    
    if txt_output_path.exists():
        return txt_output_path
    
    compressed_output_path = output_dir / compressed_filename
    
    logger.info(f"Downloading {url}")
    try:
        subprocess.check_call(["wget", "-q", url, "-O", str(compressed_output_path)])

        with open(txt_output_path, 'w') as f_out:
            subprocess.check_call(["bzcat", str(compressed_output_path)], stdout=f_out)
        
        os.remove(compressed_output_path)
        return txt_output_path
    except Exception as e:
        logger.error(f"Error downloading or extracting file: {e}")
        if compressed_output_path.exists():
            os.remove(compressed_output_path)
        return Path("")

def process_asrel(target_time):
    if target_time is None:
        target_time = datetime.now()
    
    url = get_asrel_url(target_time)
    if not url:
        logger.error("Failed to get AS relationship URL")
        return ""
    
    original_filename = url.split('/')[-1].replace('.bz2', '')  # e.g., "20230101.as-rel"
    parsed_filename = f"{original_filename}.parsed.json"
    parsed_filepath = Path(ASREL_DIR) / parsed_filename
    
    if parsed_filepath.exists():
        logger.info(f"Processed AS relationship file already exists: {parsed_filepath}")
        return str(parsed_filepath)
    
    filepath = download_asrel(url, Path(ASREL_DIR))
    if not filepath.exists():
        logger.error("Failed to download AS relationship file")
        return ""
    
    as_relationships = load_asrel(filepath)
    logger.info(f"Loaded AS relationships: {len(as_relationships['providers'])} provider relationships, {len(as_relationships['peers'])} peer relationships")
    
    try:
        with open(parsed_filepath, 'w', encoding='utf-8') as f:
            json.dump(as_relationships, f, indent=2, ensure_ascii=False)
        if filepath.exists():
            os.remove(filepath)
        return str(parsed_filepath)
    except Exception as e:
        logger.error(f"Failed to save processed AS relationship data: {e}")
        return ""

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Download and process AS relationship data")
    parser.add_argument("--date", help="Target date (YYYY-MM-DD)")
    
    args = parser.parse_args()
    
    if args.date:
        target_time = datetime.strptime(args.date, "%Y-%m-%d")
    else:
        target_time = datetime.now()
    
    json_filepath = process_asrel(target_time)
    if json_filepath:
        print(f"Processed AS relationship data saved to: {json_filepath}")
        
        with open(json_filepath, 'r') as f:
            as_relationships = json.load(f)
        print(f"Loaded AS relationships: {len(as_relationships['providers'])} provider relationships, {len(as_relationships['peers'])} peer relationships")
    else:
        print("Failed to process AS relationship data")