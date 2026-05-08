#!/usr/bin/env python3
"""
Generate pathprob.txt from BGP AS path data.

This script uses the PathProb inference module to generate AS relationship
probability files from BGP AS path data.

Usage:
    python3 generate_pathprob.py --path_dir <path_to_as_paths> --print_dir <output_dir>

Example:
    python3 generate_pathprob.py \
        --path_dir data/as_paths \
        --print_dir data/pathprob
"""

import os
import sys
import argparse
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.logger import logger


def main():
    parser = argparse.ArgumentParser(
        description="Generate PathProb AS relationship inference from BGP paths"
    )
    parser.add_argument(
        "--path_dir",
        type=str,
        required=True,
        help="Directory containing AS path files",
    )
    parser.add_argument(
        "--print_dir",
        type=str,
        required=True,
        help="Directory to save output files",
    )
    parser.add_argument(
        "--label",
        type=str,
        default="pathprob",
        help="Label for output files (default: pathprob)",
    )
    parser.add_argument(
        "--solver",
        type=str,
        default="scip",
        choices=["scip", "gurobi"],
        help="Solver to use (default: scip)",
    )

    args = parser.parse_args()

    # Import here to avoid circular imports
    from detectors.leak.pathprob import ASRelProb

    start_time = time.time()

    # Validate input directory
    if not os.path.exists(args.path_dir):
        logger.error(f"Path directory does not exist: {args.path_dir}")
        return 1

    # Create output directories
    os.makedirs(args.print_dir, exist_ok=True)

    label = args.label
    probability_file = os.path.join(args.print_dir, f"{label}.txt")
    output_dir = os.path.join(args.print_dir, label)

    log_dir = os.path.join(output_dir, "log")
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    sub_print_dir = os.path.join(output_dir, "temp_dir")
    os.makedirs(sub_print_dir, exist_ok=True)

    logger.info(f"Generating PathProb file from: {args.path_dir}")
    logger.info(f"Output directory: {args.print_dir}")

    # Get list of path files
    pathnum = [
        os.path.join(args.path_dir, file)
        for file in os.listdir(args.path_dir)
        if os.path.isfile(os.path.join(args.path_dir, file))
    ]

    if not pathnum:
        logger.error(f"No files found in {args.path_dir}")
        return 1

    logger.info(f"Found {len(pathnum)} path files")

    th = 0.8  # P2C threshold

    core_link_file = os.path.join(output_dir, f"{label}_core_link.txt")
    edge_link_file = os.path.join(output_dir, f"{label}_edge_link.txt")

    # Run inference
    asrel_prob = ASRelProb(
        pathnum, core_link_file, edge_link_file, log_dir, solver_type=args.solver
    )

    logger.info("Step 1/3: Extracting core paths...")
    asrel_prob.get_core_path(os.path.join(output_dir, "corepath.txt"))

    logger.info("Step 2/3: Inferring core links...")
    asrel_prob.infer_core_links()

    logger.info("Step 3/3: Inferring edge links...")
    asrel_prob.infer_edge_link(
        os.path.join(sub_print_dir, f"{label}_p2c_set.txt"),
        os.path.join(sub_print_dir, f"{label}_reserved_paths.txt"),
        th,
    )

    # Combine core and edge links into final probability file
    with open(probability_file, "w", encoding="utf-8") as outfile:
        with open(core_link_file, "r", encoding="utf-8") as coref:
            for line in coref:
                outfile.write(line)
        with open(edge_link_file, "r", encoding="utf-8") as edgef:
            for line in edgef:
                outfile.write(line)

    end_time = time.time()
    elapsed = end_time - start_time

    logger.info(f"PathProb file generated successfully!")
    logger.info(f"Output file: {probability_file}")
    logger.info(f"Total time: {elapsed:.2f} seconds")

    # Print statistics
    try:
        with open(probability_file, "r") as f:
            line_count = sum(1 for _ in f)
        logger.info(f"Generated {line_count} AS relationship entries")
    except Exception:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
