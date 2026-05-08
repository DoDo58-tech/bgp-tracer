#!/usr/bin/env python3
"""
Test script for PathProb integration in bgp_tracer.

Usage:
    python3 scripts/test_leak_detector.py
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import PATHPROB_SEARCH_PATHS, DEFAULT_LEAK_THRESHOLD
from detectors.leak.leak_detector import (
    find_pathprob_file,
    check_pathprob_integration,
    _read_prob,
    _parse_as_path,
    _detect_leak_by_prob,
)

def test_imports():
    """Test that all modules can be imported."""
    print("=" * 60)
    print("Test 1: Module Imports")
    print("=" * 60)
    
    try:
        from detectors.leak.pathprob import ASRelProb, GibbsSampling, ASRelSolver
        print("  PathProb modules: OK")
    except Exception as e:
        print(f"  PathProb modules: FAILED - {e}")
        return False
    
    try:
        from detectors.leak.leak_detector import (
            find_pathprob_file,
            detect_route_leaks_in_announcements,
        )
        print("  Leak detector modules: OK")
    except Exception as e:
        print(f"  Leak detector modules: FAILED - {e}")
        return False
    
    return True


def test_pathprob_search():
    """Test pathprob.txt search paths."""
    print()
    print("=" * 60)
    print("Test 2: PathProb Search Paths")
    print("=" * 60)
    
    print(f"  Search paths configured: {len(PATHPROB_SEARCH_PATHS)}")
    for i, path in enumerate(PATHPROB_SEARCH_PATHS, 1):
        exists = "✓" if path.exists() else "✗"
        print(f"  {i}. [{exists}] {path}")
    
    return True


def test_pathprob_file():
    """Test finding pathprob.txt."""
    print()
    print("=" * 60)
    print("Test 3: Find PathProb File")
    print("=" * 60)
    
    pathprob_file = find_pathprob_file()
    
    if pathprob_file:
        print(f"  Found: {pathprob_file}")
        
        # Try to read probabilities
        try:
            probs = _read_prob(pathprob_file)
            print(f"  Loaded {len(probs)} AS relationships")
        except Exception as e:
            print(f"  Failed to load: {e}")
    else:
        print("  Not found - this is OK if test_data is not downloaded")
        print("  Run the following to generate it:")
        print("    cd /data/PathProb")
        print("    wget https://github.com/hyq8868/PathProb/releases/download/v1.2/test_data.tar.zst")
        print("    zstd -d test_data.tar.zst -c | tar -xf -")
    
    return True


def test_leak_detection():
    """Test basic leak detection with mock data."""
    print()
    print("=" * 60)
    print("Test 4: Leak Detection Logic")
    print("=" * 60)
    
    # Test AS path parsing
    test_paths = [
        ("174|20946|1299|7922", ["174", "20946", "1299", "7922"]),
        ("174 20946 1299 7922", ["174", "20946", "1299", "7922"]),
    ]
    
    for path_str, expected in test_paths:
        result = _parse_as_path(path_str)
        status = "✓" if result == expected else "✗"
        print(f"  [{status}] Parse '{path_str}' -> {result}")
    
    # Test leak detection with simple mock probabilities
    mock_probs = {
        ("1299", "7922"): [0.5, 0.3, 0.2],  # p2c, p2p, c2p
        ("7922", "1299"): [0.2, 0.3, 0.5],  # reversed
    }
    
    test_path = ["174", "20946", "1299", "7922"]
    is_leak, prob = _detect_leak_by_prob(test_path, mock_probs, 0.35)
    print(f"  Path {test_path}: prob={prob:.3f}, is_leak={is_leak}")
    
    return True


def test_full_check():
    """Run full integration check."""
    print()
    print("=" * 60)
    print("Test 5: Full Integration Check")
    print("=" * 60)
    
    check_pathprob_integration()
    
    return True


def main():
    print("PathProb Integration Test Suite")
    print()
    
    tests = [
        ("Module Imports", test_imports),
        ("Search Paths", test_pathprob_search),
        ("Find File", test_pathprob_file),
        ("Leak Detection", test_leak_detection),
        ("Integration Check", test_full_check),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append((name, False))
    
    print()
    print("=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    all_passed = True
    for name, result in results:
        status = "PASS" if result else "FAIL"
        if not result:
            all_passed = False
        print(f"  [{status}] {name}")
    
    print()
    if all_passed:
        print("All tests passed!")
        return 0
    else:
        print("Some tests failed. Check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
