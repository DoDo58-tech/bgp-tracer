import os
import re
import sys
import json
import gzip
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from config import ASORG_DIR

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
CAIDA_ASORG_URL = "https://publicdata.caida.org/datasets/as-organizations/"

def get_available_dates():
    try:
        res = subprocess.check_output(["curl", "-s", CAIDA_ASORG_URL]).decode()
        res = re.sub(r"\s\s+", " ", res.replace("\n", " "))
        
        file_pattern = r'href="(\d{8}\.as-org2info\.txt\.gz)"'
        files = re.findall(file_pattern, res)
        
        available_dates = [file.split('.')[0] for file in files]
        return available_dates
    except Exception as e:
        logger.error(f"Failed to get ASORG available dates: {e}")
        return []


def get_asorg_url(target_time):
    target_date = int(target_time.strftime("%Y%m%d"))
    available_dates = get_available_dates()
    if not available_dates:
        logger.error("Failed to get ASORG available dates")
        return "", ""
    available_dates = sorted(int(date_key) for date_key in available_dates)
    idx = np.searchsorted(available_dates, target_date, "right")
    if idx == 0:
        idx = 1
    selected_date = available_dates[idx - 1]
    selected_key = f"{selected_date:08d}"
    file_name = f"{selected_key}.as-org2info.txt.gz"
    target_url = urljoin(CAIDA_ASORG_URL, file_name)
    logger.info(f"Selected ASORG archive date: {selected_key}")
    return target_url, selected_key

def parse_asorg_file(txt_path):
    asn_to_org_id: dict[str, str] = {}
    asn_to_name: dict[str, str] = {}
    org_id_to_info: dict[str, dict] = {}

    if not txt_path.exists():
        return {
            "asn_to_org_id": asn_to_org_id,
            "asn_to_name": asn_to_name,
            "org_id_to_info": org_id_to_info,
        }

    mode = None  # "aut" or "org"
    try:
        with open(txt_path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                if line.startswith("# format:"):
                    if line.startswith("# format:aut|"):
                        mode = "aut"
                    elif line.startswith("# format:org_id|"):
                        mode = "org"
                    else:
                        mode = None
                    continue
                if line.startswith("#"):
                    continue

                parts = line.split("|")
                if mode == "aut":
                    # aut|changed|aut_name|org_id|opaque_id|source
                    if len(parts) >= 6:
                        aut, changed, aut_name, org_id, opaque_id, source = parts[:6]
                        # Normalize ASN format: keep numeric string (strip 'AS' and spaces)
                        aut_norm = str(aut).strip().upper()
                        if aut_norm.startswith("AS"):
                            aut_norm = aut_norm[2:]
                        try:
                            aut_norm = str(int(aut_norm))
                        except Exception:
                            pass
                        asn_to_org_id[aut_norm] = org_id
                        asn_to_name[aut_norm] = aut_name
                elif mode == "org":
                    # org_id|changed|org_name|country|source
                    if len(parts) >= 5:
                        org_id, changed, org_name, country, source = parts[:5]
                        org_id_to_info[org_id] = {
                            "org_id": org_id,
                            "changed": changed,
                            "name": org_name,
                            "country": country,
                            "source": source,
                        }
        return {
            "asn_to_org_id": asn_to_org_id,
            "asn_to_name": asn_to_name,
            "org_id_to_info": org_id_to_info,
        }
    except Exception as e:
        logger.error(f"Failed to parse ASORG file {txt_path}: {e}")
        return {
            "asn_to_org_id": asn_to_org_id,
            "asn_to_name": asn_to_name,
            "org_id_to_info": org_id_to_info,
        }


def get_asn_org_info(target_time, asn):
    json_filepath = process_asorg(target_time)
    if not json_filepath:
        return {
            "success": False,
            "asn": asn,
            "error": "AS organization file not available",
        }
    parsed_path = Path(json_filepath)
    if not parsed_path.exists():
        return {
            "success": False,
            "asn": asn,
            "error": "Parsed AS organization file not available",
        }
    try:
        with open(parsed_path, "r", encoding="utf-8") as f:
            parsed = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load parsed ASORG data {parsed_path}: {e}")
        return {
            "success": False,
            "asn": asn,
            "error": "Unable to load parsed AS organization data",
        }
    asn_to_org_id = parsed.get("asn_to_org_id", {})
    asn_to_name = parsed.get("asn_to_name", {})
    org_id_to_info = parsed.get("org_id_to_info", {})

    asn_norm = str(asn).strip().upper()
    if asn_norm.startswith("AS"):
        asn_norm = asn_norm[2:]
    try:
        asn_norm = str(int(asn_norm))
    except Exception:
        pass

    org_id = asn_to_org_id.get(asn_norm)
    as_name = asn_to_name.get(asn_norm, "Unknown")
    if not org_id:
        return {
            "success": False,
            "asn": asn,
            "as_name": as_name,
            "error": "ASN not found in ASORG mappings",
        }
    org_info = org_id_to_info.get(org_id, {})
    return {
        "success": True,
        "asn": asn,
        "as_name": as_name,
        "org_id": org_id,
        "org_name": org_info.get("name", "Unknown"),
        "country": org_info.get("country", "Unknown"),
        "source": org_info.get("source", "Unknown"),
        "changed": org_info.get("changed", ""),
    }


def process_asorg(target_time):
    if target_time is None:
        target_time = datetime.now()
    
    url, selected_key = get_asorg_url(target_time)
    if not url:
        return ""
    
    as2org_dir = Path(ASORG_DIR)
    as2org_dir.mkdir(parents=True, exist_ok=True)
    
    original_filename = url.split('/')[-1].replace('.gz', '')
    parsed_filename = f"{original_filename}.parsed.json"
    parsed_filepath = as2org_dir / parsed_filename
    
    if parsed_filepath.exists():
        logger.info(f"Processed AS organization file already exists: {parsed_filepath}")
        return str(parsed_filepath)
    
    gz_path = as2org_dir / url.split('/')[-1]
    txt_path = gz_path.with_suffix("")
    
    if not txt_path.exists():
        logger.info(f"Downloading {url}")
        try:
            subprocess.run(["wget", "-q", url, "-O", str(gz_path)], check=True)
            # 用 Python 内置 gzip 解压，不依赖外部 gzip 命令，避免被信号打断
            with gzip.open(gz_path, 'rb') as f_in:
                with open(txt_path, 'wb') as f_out:
                    f_out.write(f_in.read())
            logger.info(f"ASORG file extracted to {txt_path}")
        except Exception as e:
            logger.error(f"Error downloading or extracting ASORG file ({selected_key}): {e}")
            if gz_path.exists():
                os.remove(gz_path)
            return ""
    
    parsed_data = parse_asorg_file(txt_path)
    
    try:
        with open(parsed_filepath, "w", encoding="utf-8") as f:
            json.dump(parsed_data, f, indent=2, ensure_ascii=False)
        if txt_path.exists():
            os.remove(txt_path)
        return str(parsed_filepath)
    except Exception as e:
        logger.error(f"Failed to save processed AS organization data: {e}")
        return ""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download and process AS organization data")
    parser.add_argument("--date", help="Target date (YYYY-MM-DD)", required=True)
    
    args = parser.parse_args()
    
    try:
        target_time = datetime.strptime(args.date, "%Y-%m-%d")
    except ValueError:
        logger.error("Invalid date format. Use YYYY-MM-DD")
        sys.exit(1)
        
    json_filepath = process_asorg(target_time)
    if json_filepath:
        print(f"Processed AS organization data saved to: {json_filepath}")
        
        with open(json_filepath, 'r') as f:
            asorg_data = json.load(f)
        print(f"Loaded {len(asorg_data['asn_to_org_id'])} ASN mappings and {len(asorg_data['org_id_to_info'])} organizations")
    else:
        print("Failed to process AS organization data")
