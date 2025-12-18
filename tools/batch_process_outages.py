#!/usr/bin/env python3
"""
Batch process traffic outage XLSX file and generate traffic comparison plots
"""

import json
import argparse
import sys
import os
from datetime import datetime
from typing import Dict, Any

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic_detect import CloudflareRadarAPI
from utils.logger import logger
from config import CLOUDFLARE_API_TOKEN, CLOUDFLARE_DEFAULT_THRESHOLD, CLOUDFLARE_DEFAULT_AGG_INTERVAL

try:
    import pandas as pd
    XLSX_SUPPORT = True
except ImportError:
    logger.error("pandas library is required for XLSX file support. Please install it: pip install pandas")
    XLSX_SUPPORT = False


def parse_time(time_str):
    """
    解析时间字符串，格式：M/D/YY HH:MM (如 6/20/25 14:30)
    """
    if isinstance(time_str, datetime):
        return time_str
    
    if XLSX_SUPPORT and pd.isna(time_str):
        return None
    
    if isinstance(time_str, str):
        # 只支持一种格式：M/D/YY HH:MM
        try:
            return datetime.strptime(time_str.strip(), '%m/%d/%y %H:%M')
        except ValueError:
            # 如果失败，尝试pandas的自动解析（作为后备）
            if XLSX_SUPPORT:
                try:
                    return pd.to_datetime(time_str)
                except:
                    pass
            return None
    
    if XLSX_SUPPORT and isinstance(time_str, pd.Timestamp):
        return time_str
        
    return None


def process_traffic_outage_xlsx(
    api: CloudflareRadarAPI,
    xlsx_path: str,
    threshold: float = CLOUDFLARE_DEFAULT_THRESHOLD,
    agg_interval: str = CLOUDFLARE_DEFAULT_AGG_INTERVAL,
    sheet_name: str = 0,  # 默认第一个sheet，也可以是具体的sheet名称
    asn_list: list = None  # 手动指定要分析的ASN列表
) -> Dict[str, Any]:
    """
    Process traffic-outage-info.xlsx and generate traffic comparison plots for each AS in each event

    Args:
        api: CloudflareRadarAPI instance
        xlsx_path: Path to the traffic-outage-info.xlsx file
        threshold: Anomaly detection threshold
        agg_interval: Data aggregation interval
        sheet_name: Excel sheet name or index (default: 0 for first sheet)
        asn_list: Manual list of AS numbers to analyze for all events

    Returns:
        Dictionary containing processing results and statistics
    """
    logger.info(f"Processing traffic outage XLSX file: {xlsx_path}")

    results = {
        "total_events": 0,
        "total_ases": 0,
        "successful_analyses": 0,
        "failed_analyses": 0,
        "events": []
    }

    if not XLSX_SUPPORT:
        logger.error("pandas library not available. Cannot process XLSX files.")
        return results

    try:
        # 使用pandas读取XLSX文件
        df = pd.read_excel(xlsx_path, sheet_name=sheet_name)
        
        # 检查必要的列
        required_columns = ['event_type', 'event_name', 'start_time', 'end_time']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            logger.error(f"Missing required columns in XLSX file: {missing_columns}")
            logger.info(f"Available columns: {list(df.columns)}")
            return results

        # 检查是否有outage_as列
        has_outage_as_column = 'outage_as' in df.columns

        # 处理每一行数据
        for row_idx, (_, row) in enumerate(df.iterrows(), start=2):  # Start from 2 (1 is header)
            event_type = row.get('event_type', '')
            event_name = row.get('event_name', f'event_{row_idx}')
            start_time_raw = row.get('start_time', '')
            end_time_raw = row.get('end_time', '')

            # 处理NaN值
            if pd.isna(event_type) or pd.isna(event_name):
                logger.info(f"Skipping row {row_idx}: missing event_type or event_name")
                continue
            if pd.isna(start_time_raw) or pd.isna(end_time_raw):
                logger.info(f"Skipping row {row_idx}: missing time data")
                continue

            # 跳过空值
            if not event_type or not event_name or not start_time_raw or not end_time_raw:
                logger.info(f"Skipping row {row_idx}: empty required fields")
                continue

            # Parse start and end times
            try:
                start_time_dt = parse_time(start_time_raw)
                end_time_dt = parse_time(end_time_raw)
                
                if start_time_dt is None or end_time_dt is None:
                    logger.error(f"Error parsing time for event {event_name}")
                    logger.error(f"Start time: {start_time_raw}, End time: {end_time_raw}")
                    continue
                
                start_time = start_time_dt.strftime('%Y-%m-%d %H:%M')
                end_time = end_time_dt.strftime('%Y-%m-%d %H:%M')
                
            except Exception as e:
                logger.error(f"Error processing time for event {event_name}: {e}")
                logger.error(f"Start time: {start_time_raw}, End time: {end_time_raw}")
                continue

            # 从outage_as列读取AS号，如果没有则使用手动提供的ASN列表
            as_numbers = []
            
            if has_outage_as_column:
                outage_as_raw = row.get('outage_as', '')
                if not pd.isna(outage_as_raw) and outage_as_raw:
                    # 解析outage_as列：支持中文逗号（、）和英文逗号（,）分隔
                    outage_as_str = str(outage_as_raw).strip()
                    if outage_as_str:
                        # 先按中文逗号分割，再按英文逗号分割
                        as_parts = outage_as_str.replace('，', ',').replace('、', ',').split(',')
                        for as_part in as_parts:
                            as_part = as_part.strip()
                            if as_part:
                                # 移除AS前缀（如果有）
                                as_num = as_part.replace('AS', '').replace('as', '').strip()
                                if as_num and as_num.isdigit():
                                    as_numbers.append(as_num)
            
            # 如果outage_as列没有数据，使用手动提供的ASN列表
            if not as_numbers and asn_list:
                as_numbers = [str(asn).replace('AS', '').replace('as', '') for asn in asn_list if str(asn).strip()]

            if not as_numbers:
                logger.info(f"Skipping event {event_name}: no valid AS numbers found in outage_as column or --asn-list")
                continue

            results["total_events"] += 1
            event_result = {
                "event_type": event_type,
                "event_name": event_name,
                "start_time": start_time,
                "end_time": end_time,
                "as_numbers": as_numbers,
                "analyses": []
            }

            logger.info(f"\n{'='*80}")
            logger.info(f"Processing event: {event_name} ({event_type})")
            logger.info(f"Time range: {start_time} to {end_time}")
            as_list_str = ', '.join([f'AS{asn}' for asn in as_numbers])
            logger.info(f"AS numbers to analyze: {as_list_str}")
            logger.info(f"{'='*80}\n")

            # Analyze each AS
            for asn in as_numbers:
                results["total_ases"] += 1
                logger.info(f"Analyzing AS{asn} for event {event_name}...")

                try:
                    analysis_result = api.detect_anomalies(
                        asn=asn,
                        start_time=start_time,
                        end_time=end_time,
                        threshold=threshold,
                        agg_interval=agg_interval,
                        plot_result=True,
                        event_name=event_name
                    )

                    if analysis_result and analysis_result.get('success'):
                        results["successful_analyses"] += 1
                        event_result["analyses"].append({
                            "asn": asn,
                            "success": True,
                            "plot_path": analysis_result.get('plot_path'),
                            "anomaly_count": analysis_result.get('anomaly_count', 0),
                            "percent_change": analysis_result.get('percent_change', 0)
                        })
                        logger.info(f"✓ Successfully analyzed AS{asn}: {analysis_result.get('anomaly_count', 0)} anomalies detected, "
                                  f"{analysis_result.get('percent_change', 0):.2f}% traffic change")
                    else:
                        results["failed_analyses"] += 1
                        event_result["analyses"].append({
                            "asn": asn,
                            "success": False,
                            "error": analysis_result.get('error', 'Unknown error')
                        })
                        logger.warning(f"✗ Failed to analyze AS{asn}: {analysis_result.get('error', 'Unknown error')}")

                except Exception as e:
                    results["failed_analyses"] += 1
                    event_result["analyses"].append({
                        "asn": asn,
                        "success": False,
                        "error": str(e)
                    })
                    logger.error(f"✗ Exception analyzing AS{asn}: {e}")

            results["events"].append(event_result)

        # Generate summary
        logger.info(f"\n{'='*80}")
        logger.info("Processing Summary:")
        logger.info(f"  Total events processed: {results['total_events']}")
        logger.info(f"  Total AS numbers analyzed: {results['total_ases']}")
        logger.info(f"  Successful analyses: {results['successful_analyses']}")
        logger.info(f"  Failed analyses: {results['failed_analyses']}")
        logger.info(f"{'='*80}\n")

        return results

    except FileNotFoundError:
        logger.error(f"XLSX file not found: {xlsx_path}")
        return results
    except Exception as e:
        logger.error(f"Error processing XLSX file: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return results


def main():
    parser = argparse.ArgumentParser(description='Batch process traffic outage XLSX file')
    parser.add_argument('--xlsx-file', default='/data/bgp_tracer/data/traffic-outage-info.xlsx',
                       help='Path to traffic-outage-info.xlsx file')
    parser.add_argument('--sheet-name', default=0,
                       help='Excel sheet name or index (default: 0 for first sheet)')
    parser.add_argument('--api-token', default=CLOUDFLARE_API_TOKEN,
                       help='Cloudflare API token')
    parser.add_argument('--threshold', type=float, default=CLOUDFLARE_DEFAULT_THRESHOLD,
                       help='Anomaly detection threshold (standard deviation multiplier)')
    parser.add_argument('--agg-interval', default=CLOUDFLARE_DEFAULT_AGG_INTERVAL,
                       help='Aggregation interval (15m, 1h, 1d, etc.)')
    parser.add_argument('--asn-list', nargs='+', default=[],
                       help='List of AS numbers to analyze (e.g., 13335 15169). If not provided, will read from outage_as column in XLSX file.')
    parser.add_argument('--output-json', help='Save results to JSON file')

    args = parser.parse_args()

    # Check if pandas is available
    if not XLSX_SUPPORT:
        logger.error("Cannot process XLSX files without pandas. Please install: pip install pandas openpyxl")
        return

    # Initialize API
    api = CloudflareRadarAPI(args.api_token)

    print(f"\n{'='*80}")
    print(f"🚀 Batch Processing Mode: Traffic Outage Analysis")
    print(f"{'='*80}")
    print(f"📄 XLSX File: {args.xlsx_file}")
    print(f"📊 Sheet: {args.sheet_name}")
    print(f"🔢 AS Numbers: {args.asn_list if args.asn_list else 'Will read from outage_as column in XLSX file'}")
    print(f"⚙️  Threshold: {args.threshold}")
    print(f"⏱️  Aggregation Interval: {args.agg_interval}")
    print(f"{'='*80}\n")

    # Process XLSX
    result = process_traffic_outage_xlsx(
        api=api,
        xlsx_path=args.xlsx_file,
        threshold=args.threshold,
        agg_interval=args.agg_interval,
        sheet_name=args.sheet_name,
        asn_list=args.asn_list
    )

    # Print summary
    print(f"\n{'='*80}")
    print(f"📊 Batch Processing Complete")
    print(f"{'='*80}")
    print(f"Total events processed: {result['total_events']}")
    print(f"Total AS numbers analyzed: {result['total_ases']}")
    print(f"Successful analyses: {result['successful_analyses']}")
    print(f"Failed analyses: {result['failed_analyses']}")

    # Display results by event
    for event in result['events']:
        print(f"\n📌 Event: {event['event_name']} ({event['event_type']})")
        print(f"   Time: {event['start_time']} to {event['end_time']}")
        as_list = ', '.join([f'AS{asn}' for asn in event['as_numbers']])
        print(f"   AS numbers: {as_list}")

        successful = [a for a in event['analyses'] if a.get('success')]
        failed = [a for a in event['analyses'] if not a.get('success')]

        if successful:
            print(f"   ✓ Successfully analyzed: {len(successful)}")
            for analysis in successful:
                print(f"      - AS{analysis['asn']}: {analysis['anomaly_count']} anomalies, "
                      f"{analysis['percent_change']:.2f}% change")
                if analysis.get('plot_path'):
                    print(f"        Plot: {analysis['plot_path']}")

        if failed:
            print(f"   ✗ Failed: {len(failed)}")
            for analysis in failed:
                print(f"      - AS{analysis['asn']}: {analysis.get('error', 'Unknown error')}")

    print(f"\n{'='*80}\n")

    # Save results to JSON if requested
    if args.output_json:
        with open(args.output_json, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, default=str, ensure_ascii=False)
        print(f"💾 Results saved to: {args.output_json}\n")


if __name__ == "__main__":
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    main()