#!/usr/bin/env python3
"""
PathProb Integration Checker

This script helps verify that PathProb_AE is properly integrated with bgp_tracer.
It checks for pathprob.txt file and provides guidance on how to generate it if missing.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import PATHPROB_SEARCH_PATHS, PATHPROB_AE_ROOT, PROJECT_ROOT
from tools.leak_detector import find_pathprob_file


def check_pathprob_integration():
    """Check PathProb integration status and provide guidance."""
    print("=" * 70)
    print("PathProb Integration Checker")
    print("=" * 70)
    print()
    
    # Check PathProb_AE directory
    print("1. Checking PathProb_AE installation...")
    pathprob_ae_path = Path(PATHPROB_AE_ROOT)
    if pathprob_ae_path.exists():
        print(f"   ✓ PathProb_AE found at: {pathprob_ae_path}")
        
        # Check for key files
        infer_script = pathprob_ae_path / "infer_prob" / "asrel_prob.py"
        if infer_script.exists():
            print(f"   ✓ Inference script found: {infer_script}")
        else:
            print(f"   ✗ Inference script missing: {infer_script}")
    else:
        print(f"   ✗ PathProb_AE not found at: {pathprob_ae_path}")
        print(f"     Expected location: /data/PathProb_AE")
    
    print()
    
    # Check for pathprob.txt
    print("2. Searching for pathprob.txt file...")
    pathprob_file = find_pathprob_file()
    
    if pathprob_file:
        print(f"   ✓ Found pathprob.txt at: {pathprob_file}")
        
        # Check file size
        file_size = os.path.getsize(pathprob_file)
        print(f"   ✓ File size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")
        
        # Check if file is readable
        try:
            with open(pathprob_file, 'r') as f:
                line_count = sum(1 for _ in f)
            print(f"   ✓ File is readable, contains {line_count:,} lines")
        except Exception as e:
            print(f"   ✗ Error reading file: {e}")
    else:
        print("   ✗ pathprob.txt not found in any search location")
        print()
        print("   Searched locations:")
        for i, search_path in enumerate(PATHPROB_SEARCH_PATHS, 1):
            exists = "✓" if search_path.exists() else "✗"
            print(f"     {i}. {exists} {search_path}")
    
    print()
    
    # Provide guidance
    if not pathprob_file:
        print("3. How to generate pathprob.txt:")
        print()
        print("   Option 1: Use PathProb_AE to generate the file")
        print(f"   {''.join([' '] * 3)}cd {PATHPROB_AE_ROOT}")
        print(f"   {''.join([' '] * 3)}python3 infer_prob/asrel_prob.py \\")
        print(f"   {''.join([' '] * 5)}--path_dir <path_to_as_paths> \\")
        print(f"   {''.join([' '] * 5)}--print_dir <output_directory>")
        print()
        print("   Option 2: Set environment variable")
        print(f"   {''.join([' '] * 3)}export PATHPROB_FILE=/path/to/pathprob.txt")
        print()
        print("   Option 3: Place file in default location")
        default_location = PROJECT_ROOT / "data" / "pathprob" / "pathprob.txt"
        print(f"   {''.join([' '] * 3)}mkdir -p {default_location.parent}")
        print(f"   {''.join([' '] * 3)}cp /path/to/pathprob.txt {default_location}")
        print()
    else:
        print("3. Integration Status: ✓ READY")
        print()
        print("   PathProb is properly integrated. Route leak detection should work.")
    
    print()
    print("=" * 70)
    
    return pathprob_file is not None


if __name__ == "__main__":
    success = check_pathprob_integration()
    sys.exit(0 if success else 1)

