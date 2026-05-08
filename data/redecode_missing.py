#!/usr/bin/env python3
"""
Re-download corrupted/missing gz files and decode them to txt files.
Usage: python redecode_missing.py
"""
import os
import subprocess
import sys
from pathlib import Path

# Add parent dir to path
sys.path.append(str(Path(__file__).parent.parent))
from utils.logger import logger

UPDATES_DIR = Path(__file__).parent / "updates_rrc00"
DECODED_DIR = UPDATES_DIR / "decoded"
RIPE_RIS_URL = "https://data.ris.ripe.net/rrc00/"

def get_missing_files():
    """Find gz files that don't have corresponding decoded txt files."""
    missing = []
    for f in UPDATES_DIR.glob("*.gz"):
        base = f.stem  # removes .gz
        txt_path = DECODED_DIR / f"{base}.txt"
        if not txt_path.exists():
            missing.append(f.name)
    return missing

def download_file(filename):
    """Download a single gz file from RIPE RIS."""
    # Extract year.month from filename like updates.20240815.0000.gz
    # Format: updates.YYYYMMDD.HHMM.gz
    parts = filename.replace(".gz", "").split(".")
    if len(parts) >= 3:
        year = parts[1][:4]
        month = parts[1][4:6]
        ym_dir = f"{year}.{month}"
        url = f"{RIPE_RIS_URL}{ym_dir}/{filename}"
        
        outpath = UPDATES_DIR / filename
        if outpath.exists():
            # Check if corrupted
            result = subprocess.run(["gzip", "-t", str(outpath)], 
                                   capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"File already exists and is valid: {filename}")
                return True
        
        logger.info(f"Downloading: {url}")
        try:
            subprocess.run(["wget", "-q", "-c", url, "-O", str(outpath)], 
                          timeout=120, check=True)
            logger.info(f"Downloaded: {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to download {filename}: {e}")
            return False
    return False

def convert_timestamp(line):
    """Convert MM/DD/YY HH:MM:SS to YYYY-MM-DD HH:MM:SS format."""
    import re
    # Match pattern: BGP4MP|MM/DD/YY HH:MM:SS|...
    pattern = r'^(BGP4MP\|)(\d{2}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})(\|.*)$'
    match = re.match(pattern, line)
    if match:
        prefix = match.group(1)
        date_part = match.group(2)  # MM/DD/YY
        time_part = match.group(3)   # HH:MM:SS
        suffix = match.group(4)
        
        # Convert MM/DD/YY to YYYY-MM-DD
        parts = date_part.split('/')
        month, day, year = parts[0], parts[1], parts[2]
        full_year = f"20{year}" if int(year) < 50 else f"19{year}"
        new_date = f"{full_year}-{month.zfill(2)}-{day.zfill(2)}"
        
        return f"{prefix}{new_date} {time_part}{suffix}"
    return line

def decode_file(filename):
    """Decode a gz file to txt using bgpdump."""
    gz_path = UPDATES_DIR / filename
    base = gz_path.stem
    txt_path = DECODED_DIR / f"{base}.txt"
    
    if txt_path.exists():
        logger.info(f"Decoded file already exists: {txt_path}")
        return True
    
    logger.info(f"Decoding: {filename}")
    try:
        # Use bgpdump -M -t change for human-readable timestamps
        # Then convert MM/DD/YY to YYYY-MM-DD format
        proc = subprocess.Popen(
            ["bgpdump", "-M", "-t", "change", str(gz_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        
        with open(txt_path, 'w') as out:
            for line in proc.stdout:
                decoded_line = line.decode('utf-8', errors='ignore').strip()
                if decoded_line:
                    converted_line = convert_timestamp(decoded_line)
                    out.write(converted_line + '\n')
        
        proc.wait()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, "bgpdump")
            
        logger.info(f"Decoded: {filename} -> {txt_path.name}")
        return True
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout decoding: {filename}")
        return False
    except Exception as e:
        logger.error(f"Failed to decode {filename}: {e}")
        # Remove partial output
        if txt_path.exists():
            txt_path.unlink()
        return False

def main():
    logger.info("Finding missing decoded files...")
    missing = get_missing_files()
    logger.info(f"Found {len(missing)} missing files")
    
    if not missing:
        logger.info("No missing files!")
        return
    
    # Process each missing file
    success = 0
    failed = []
    
    for i, filename in enumerate(missing):
        logger.info(f"[{i+1}/{len(missing)}] Processing: {filename}")
        
        # Step 1: Download (if needed)
        gz_path = UPDATES_DIR / filename
        if not gz_path.exists() or subprocess.run(["gzip", "-t", str(gz_path)], 
                                                   capture_output=True).returncode != 0:
            if not download_file(filename):
                failed.append(filename)
                continue
        
        # Step 2: Decode
        if decode_file(filename):
            success += 1
        else:
            failed.append(filename)
    
    logger.info(f"\n=== Summary ===")
    logger.info(f"Successfully processed: {success}")
    if failed:
        logger.error(f"Failed: {len(failed)}")
        for f in failed:
            logger.error(f"  - {f}")
    else:
        logger.info("All files processed successfully!")

if __name__ == "__main__":
    main()
