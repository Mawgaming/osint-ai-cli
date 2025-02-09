import unittest
import subprocess
import json

class TestCLI(unittest.TestCase):
    
    def test_help_command(self):
        """Test CLI help command."""
        result = subprocess.run(["python", "main.py", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout + result.stderr  # ✅ Capture both stdout & stderr
        self.assertIn("usage:", output.lower())  # ✅ Check both outputs

    
    def test_shodan_scan(self):
        """Test CLI Shodan scan with a dummy IP."""
        dummy_ip = "8.8.8.8"
        result = subprocess.run(["python", "main.py", "--target", dummy_ip, "--scan-type", "shodan"], capture_output=True, text=True)  # ✅ Calls main.py instead
        self.assertIn("[INFO] Running Shodan scan", result.stdout)
    
    def test_output_format(self):
        """Test CLI JSON output format."""
        dummy_ip = "8.8.8.8"
        result = subprocess.run(["python", "main.py", "--target", dummy_ip, "--scan-type", "shodan", "--output", "json"], capture_output=True, text=True)
        
        try:
            json.loads(result.stdout)
            valid_json = True
        except json.JSONDecodeError:
            valid_json = False
        
        self.assertTrue(valid_json, "CLI output is not valid JSON")
    
if __name__ == "__main__":
    unittest.main()
