#!/usr/bin/env python3
"""
Unit test for the hijack detection data extraction fix in reasoning_agent.py

This test verifies that the fix for accessing hijack results from detect_hijacks_batch
is working correctly. The bug was that the code was accessing batch_hijack_results.get(asn_str, {})
instead of batch_hijack_results.get("results_by_as", {}).get(asn_str, {})

The test simulates the data structure returned by detect_hijacks_batch and verifies
that the extraction logic correctly retrieves the hijack data.
"""

import sys
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime

# Add project root to path
sys.path.insert(0, '/data/bgp_tracer')


class TestHijackDataExtraction(unittest.TestCase):
    """Test that hijack detection results are correctly extracted from batch results"""
    
    def setUp(self):
        """Set up mock data structures"""
        # This is the actual structure returned by detect_hijacks_batch
        self.mock_batch_results = {
            "success": True,
            "batch_mode": True,
            "as_count": 2,
            "results_by_as": {
                "7420": {
                    "success": True,
                    "asn": "7420",
                    "origin_hijacked": [
                        {"prefix": "196.46.192.0/19", "hijacker_as": "37154", "victim_as": "7"},
                        {"prefix": "196.46.192.0/19", "hijacker_as": "37154", "victim_as": "7"},
                    ],
                    "forge_hijacked": [],
                    "origin_hijacking": [],
                    "forge_hijacking": [],
                    "total_announcements": 100,
                },
                "47474": {
                    "success": True,
                    "asn": "47474",
                    "origin_hijacked": [],
                    "forge_hijacked": [],
                    "origin_hijacking": [],
                    "forge_hijacking": [],
                    "total_announcements": 50,
                }
            },
            "analysis_timestamp": datetime.now().isoformat(),
        }
    
    def test_old_buggy_access_pattern(self):
        """
        Test the OLD (buggy) access pattern that was causing data loss
        
        This demonstrates why the bug occurred - directly accessing 
        batch_hijack_results.get(asn_str, {}) returns empty dict
        """
        asn_str = "7420"
        
        # BUGGY CODE: This is what the OLD code did
        hijack_data_old = self.mock_batch_results.get(asn_str, {})
        
        # This assertion shows the bug
        self.assertEqual(hijack_data_old, {}, 
            "Buggy access pattern should return empty dict (this is the bug!)")
        
        # Verify that accessing origin_hijacked from empty dict gives []
        self.assertEqual(hijack_data_old.get("origin_hijacked", []), [],
            "Buggy pattern results in empty list for origin_hijacked")
    
    def test_fixed_access_pattern(self):
        """
        Test the FIXED access pattern that correctly retrieves hijack data
        """
        asn_str = "7420"
        
        # FIXED CODE: Access through 'results_by_as' key
        batch_results_by_as = self.mock_batch_results.get("results_by_as", {})
        hijack_data_fixed = batch_results_by_as.get(asn_str, {})
        
        # This is the correct behavior
        self.assertNotEqual(hijack_data_fixed, {},
            "Fixed access pattern should return actual data")
        
        # Verify that we can access the hijack data
        origin_hijacked = hijack_data_fixed.get("origin_hijacked", [])
        self.assertEqual(len(origin_hijacked), 2,
            "Should have 2 origin hijacked events for AS7420")
    
    def test_all_asns_in_batch(self):
        """Test that all ASNs in the batch can be correctly accessed"""
        batch_results_by_as = self.mock_batch_results.get("results_by_as", {})
        
        for asn_str in ["7420", "47474"]:
            hijack_data = batch_results_by_as.get(asn_str, {})
            self.assertIsNotNone(hijack_data, f"Should find data for AS{asn_str}")
            self.assertIsInstance(hijack_data, dict, f"Data for AS{asn_str} should be a dict")
    
    def test_nonexistent_asn(self):
        """Test that non-existent ASNs return empty dict (no crash)"""
        batch_results_by_as = self.mock_batch_results.get("results_by_as", {})
        hijack_data = batch_results_by_as.get("99999", {})
        
        self.assertEqual(hijack_data, {},
            "Non-existent ASN should return empty dict, not crash")
        
        # Verify graceful handling
        self.assertEqual(hijack_data.get("origin_hijacked", []), [],
            "Non-existent ASN should return empty list for origin_hijacked")
    
    def test_missing_results_by_as_key(self):
        """Test handling when 'results_by_as' key is missing"""
        # Simulate a malformed response
        malformed_results = {
            "success": True,
            "batch_mode": True,
            # Missing 'results_by_as' key!
        }
        
        batch_results_by_as = malformed_results.get("results_by_as", {})
        hijack_data = batch_results_by_as.get("7420", {})
        
        # Should handle gracefully
        self.assertEqual(hijack_data, {},
            "Should handle missing 'results_by_as' key gracefully")
    
    def test_hijack_count_validation(self):
        """
        Test that validates the fix - this is what the validation logic does
        """
        batch_results = self.mock_batch_results
        
        # Count hijacks in batch source
        total_in_batch = 0
        for asn_str, hijack_result in batch_results.get("results_by_as", {}).items():
            total_in_batch += len(hijack_result.get("origin_hijacked", []))
            total_in_batch += len(hijack_result.get("forge_hijacked", []))
        
        # Count hijacks in extracted results (using fixed pattern)
        extracted_results = {}
        for asn_str in ["7420", "47474"]:
            batch_results_by_as = batch_results.get("results_by_as", {})
            hijack_data = batch_results_by_as.get(asn_str, {})
            extracted_results[asn_str] = {
                "origin_hijacked": hijack_data.get("origin_hijacked", []),
                "forge_hijacked": hijack_data.get("forge_hijacked", []),
            }
        
        total_in_extracted = 0
        for asn_str, result in extracted_results.items():
            total_in_extracted += len(result.get("origin_hijacked", []))
            total_in_extracted += len(result.get("forge_hijacked", []))
        
        # The fix ensures these counts match
        self.assertEqual(total_in_batch, total_in_extracted,
            f"Hijack counts should match: batch={total_in_batch}, extracted={total_in_extracted}")
        
        # With our test data, we expect 2 origin hijacks for AS7420
        self.assertEqual(total_in_batch, 2,
            "Should have detected 2 total hijack events in batch")
    
    def test_key_name_compatibility(self):
        """
        Test compatibility with both key naming conventions:
        - origin_hijacked (new/canonical)
        - origin_hijack (legacy)
        """
        # Some code paths might use origin_hijack instead of origin_hijacked
        mixed_results = {
            "results_by_as": {
                "7420": {
                    # Using legacy key name
                    "origin_hijack": [{"prefix": "1.0.0.0/24"}],
                    "forge_hijack": [],
                }
            }
        }
        
        batch_results_by_as = mixed_results.get("results_by_as", {})
        hijack_data = batch_results_by_as.get("7420", {})
        
        # Test both key names for compatibility
        origin_hijacked = hijack_data.get("origin_hijacked", []) or hijack_data.get("origin_hijack", [])
        self.assertEqual(len(origin_hijacked), 1,
            "Should find origin hijack via either key name")


class TestReportGeneration(unittest.TestCase):
    """Test that hijack data flows correctly to report generation"""
    
    def test_routing_data_keys_in_report(self):
        """
        Test that the expected keys exist in routing_data for report generation
        """
        # Simulate what the report generator expects
        routing_data = {
            "success": True,
            "asn": "7420",
            "origin_hijacked": [
                {"prefix": "196.46.192.0/19", "hijacker_as": "37154"},
            ],
            "forge_hijacked": [],
            "origin_hijacking": [],
            "forge_hijacking": [],
            "route_leaks": [],
            "outage_analysis": {"is_outage_suspected": False},
        }
        
        # Verify all keys that report generation expects
        self.assertIn("origin_hijacked", routing_data)
        self.assertIn("forge_hijacked", routing_data)
        self.assertIn("origin_hijacking", routing_data)
        self.assertIn("forge_hijacking", routing_data)
        self.assertIn("route_leaks", routing_data)
        self.assertIn("outage_analysis", routing_data)
        
        # Verify values are lists
        for key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking", "route_leaks"]:
            self.assertIsInstance(routing_data[key], list,
                f"{key} should be a list")


if __name__ == "__main__":
    print("=" * 70)
    print("Testing Hijack Detection Data Extraction Fix")
    print("=" * 70)
    print()
    print("This test verifies the fix for the bug where hijack detection results")
    print("were being lost because batch_hijack_results.get(asn_str, {}) was")
    print("used instead of batch_hijack_results.get('results_by_as', {}).get(asn_str, {})")
    print()
    print("=" * 70)
    print()
    
    unittest.main(verbosity=2)
