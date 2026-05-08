import os
import re
import sys
import json
import gzip
import subprocess
import numpy as np
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import PREFIX2AS_DIR

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
CAIDA_PREFIX2AS_URL = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/"

def get_available_dates():
    try:
        res = subprocess.check_output(["curl", "-s", "--max-time", "30", CAIDA_PREFIX2AS_URL]).decode()
        res = re.sub(r"\s\s+", " ", res.replace("\n", " "))

        year_pattern = r'href="(\d{4})/"'
        years = sorted(re.findall(year_pattern, res))

        available_dates = []
        for year in years:
            try:
                year_url = f"{CAIDA_PREFIX2AS_URL}/{year}/"
                res = subprocess.check_output(["curl", "-s", "--max-time", "10", year_url]).decode()
                res = re.sub(r"\s\s+", " ", res.replace("\n", " "))

                month_pattern = r'href="(\d{2})/"'
                months = sorted(re.findall(month_pattern, res))

                for month in months:
                    available_dates.append(f"{year}{month}")
            except subprocess.CalledProcessError:
                logger.warning(f"Failed to access year {year}, skipping")
                continue
            except Exception as e:
                logger.warning(f"Error processing year {year}: {e}")
                continue

        return available_dates
    except Exception as e:
        logger.error(f"Failed to get available dates: {e}")
        return []

def get_prefix2as_url(target_time):
    target_date = target_time.strftime("%Y%m")
    available_dates = get_available_dates()
    
    if not available_dates:
        logger.error("Failed to get available dates")
        return ""
    
    idx = np.searchsorted(available_dates, target_date, "right")
    if idx == 0:
        idx = 1
        
    closest_date = available_dates[idx-1]
    year = closest_date[:4]
    month = closest_date[4:]
    
    logger.info(f"Found closest available date: {year}-{month}")
    
    dir_url = f"{CAIDA_PREFIX2AS_URL}/{year}/{month}/"
    try:
        res = subprocess.check_output(["curl", "-s", dir_url]).decode()
        res = re.sub(r"\s\s+", " ", res.replace("\n", " "))
        
        file_pattern = r'href="(routeviews-(?:rv2|oix)-(\d{8})-\d{4}\.pfx2as\.gz)"'
        matches = re.findall(file_pattern, res)
        
        if not matches:
            logger.error(f"No data files found for {year}-{month}")
            return ""
            
        files = []
        dates = []
        for fname, date in matches:
            files.append(fname)
            dates.append(date)
            
        dates = sorted(dates)
        target_day = target_time.strftime("%Y%m%d")
        
        idx = np.searchsorted(dates, target_day, "right")
        if idx == 0:
            idx = 1  # Take the earliest available file if target is before all files
            
        closest_date = dates[idx-1]
        closest_file = next(f for f, d in matches if d == closest_date)
        logger.info(f"Found closest file: {closest_file} for date {closest_date}")
        
        return urljoin(dir_url, closest_file)
        
    except Exception as e:
        logger.error(f"Failed to get directory listing: {e}")
        return ""

def load_prefix2as(filepath):
    prefix_to_as = {}
    
    try:
        is_gzip = str(filepath).endswith('.gz')
        
        open_func = gzip.open if is_gzip else open
        mode = 'rt' if is_gzip else 'r'
        
        with open_func(filepath, mode) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    ip_addr = parts[0]
                    prefix_len = parts[1]
                    asns = parts[2].split('_')  # Get all ASes if there are multiple
                    asn = asns[0]  # Take first AS as primary
                    
                    prefix = f"{ip_addr}/{prefix_len}"
                    # Store as list to match hijack detector expectations
                    # If prefix already exists, append to list (rare case of multiple entries)
                    if prefix in prefix_to_as:
                        if isinstance(prefix_to_as[prefix], list):
                            prefix_to_as[prefix].append(asn)
                        else:
                            prefix_to_as[prefix] = [prefix_to_as[prefix], asn]
                    else:
                        prefix_to_as[prefix] = [asn]
    except Exception as e:
        logger.error(f"Error loading prefix2as data: {e}")
    
    return prefix_to_as

def download_prefix2as(url, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    compressed_filename = url.split('/')[-1]
    txt_filename = compressed_filename.replace('.gz', '.txt')
    txt_output_path = output_dir / txt_filename
    
    if txt_output_path.exists():
        logger.info(f"Extracted file already exists: {txt_output_path}")
        return txt_output_path
    
    compressed_output_path = output_dir / compressed_filename
    
    logger.info(f"Downloading {url}")
    try:
        subprocess.check_call(["wget", "-q", url, "-O", str(compressed_output_path)])

        with gzip.open(compressed_output_path, 'rt') as f_in:
            with open(txt_output_path, 'w') as f_out:
                f_out.write(f_in.read())
        
        os.remove(compressed_output_path)
        
        return txt_output_path
    except Exception as e:
        logger.error(f"Error downloading or extracting file: {e}")
        if compressed_output_path.exists():
            os.remove(compressed_output_path)
        return Path("")

def process_prefix2as(target_time):
    if target_time is None:
        target_time = datetime.now()
    
    logger.info(f"Processing prefix2as data for {target_time}")
    
    url = get_prefix2as_url(target_time)
    if not url:
        logger.error("Failed to get prefix2as URL")
        return ""
    
    original_filename = url.split('/')[-1].replace('.gz', '')  # e.g., "routeviews-rv2-20230101-1200.pfx2as"
    parsed_filename = f"{original_filename}.parsed.json"
    parsed_filepath = Path(PREFIX2AS_DIR) / parsed_filename
    
    if parsed_filepath.exists():
        logger.info(f"Processed prefix2as file already exists: {parsed_filepath}")
        return str(parsed_filepath)
    
    filepath = download_prefix2as(url, Path(PREFIX2AS_DIR))
    if not filepath.exists():
        logger.error("Failed to download prefix2as file")
        return ""
    
    prefix_to_as = load_prefix2as(filepath)
    logger.info(f"Loaded {len(prefix_to_as)} prefix-to-AS mappings")
    
    try:
        with open(parsed_filepath, 'w', encoding='utf-8') as f:
            json.dump(prefix_to_as, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved processed prefix2as mappings to: {parsed_filepath}")
        if filepath.exists():   
            os.remove(filepath)
        return str(parsed_filepath)
    except Exception as e:
        logger.error(f"Failed to save processed prefix2as mappings: {e}")
        return ""

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Download and process prefix2as data")
    parser.add_argument("--date", help="Target date (YYYY-MM-DD)")
    
    args = parser.parse_args()
    
    if args.date:
        target_time = datetime.strptime(args.date, "%Y-%m-%d")
    else:
        target_time = datetime.now()
    
    json_filepath = process_prefix2as(target_time)
    if json_filepath:
        print(f"Processed prefix2as mappings saved to: {json_filepath}")
        
        with open(json_filepath, 'r') as f:
            prefix_to_as = json.load(f)
        print(f"Loaded {len(prefix_to_as)} prefix-to-AS mappings")
    else:
        print("Failed to process prefix2as mappings")