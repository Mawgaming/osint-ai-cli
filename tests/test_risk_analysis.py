import unittest
import os
from src.core.ai_processing import analyze_text_with_ai

class TestOSINTPipeline(unittest.TestCase):
    
    def test_full_pipeline(self):
        """Test full OSINT AI pipeline and ensure data is saved."""
        sample_text = "Target: google.com (IP: 8.8.8.8) might be vulnerable to CVE-2023-1234."
        results = analyze_text_with_ai(sample_text)

        # Verify JSON output exists
        scan_dir = "data/scan_results"
        json_files = [f for f in os.listdir(scan_dir) if f.endswith(".json")]

        self.assertGreater(len(json_files), 0, "No JSON scan results found!")
        print("[TEST PASSED] Scan result successfully saved!")

if __name__ == "__main__":
    unittest.main()
