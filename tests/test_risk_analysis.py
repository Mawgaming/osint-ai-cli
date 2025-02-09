import unittest
import json
from src.core.ai_processing import analyze_text_with_ai

class TestOSINTPipeline(unittest.TestCase):

    def test_full_pipeline(self):
        """Test full OSINT AI pipeline."""
        sample_text = "Target: example.com (IP: 192.168.1.1) might be vulnerable to CVE-2023-1234."
        results = analyze_text_with_ai(sample_text)

        self.assertIn("extracted_data", results)
        self.assertIn("osint_results", results)
        self.assertIn("risk_report", results)

        print(json.dumps(results, indent=4))

if __name__ == "__main__":
    unittest.main()
