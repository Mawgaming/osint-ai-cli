import unittest
from src.core.osint_scraper import shodan_search, virustotal_scan

class TestOSINTScraper(unittest.TestCase):
    
    def test_shodan_search(self):
        """Test Shodan search function with a dummy IP."""
        dummy_ip = "8.8.8.8"  # Google's Public DNS
        result = shodan_search("FAKE_SHODAN_API_KEY", dummy_ip)
        self.assertIsInstance(result, dict)
        self.assertIn("ip_str", result)
    
    def test_virustotal_scan(self):
        """Test VirusTotal scan function with a dummy URL."""
        dummy_url = "http://example.com"
        result = virustotal_scan("FAKE_VIRUSTOTAL_API_KEY", dummy_url)
        self.assertIsInstance(result, dict)
        self.assertIn("data", result)

if __name__ == "__main__":
    unittest.main()
