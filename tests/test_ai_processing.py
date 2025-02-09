import unittest
from src.core.ai_processing import extract_entities, analyze_text_with_ai

class TestAIProcessing(unittest.TestCase):
    
    def test_extract_entities(self):
        """Test entity extraction from text."""
        sample_text = "John Doe's email is john.doe@example.com and his office is in New York. " \
                      "His company website is www.example.com and their server IP is 192.168.1.1."
        entities = extract_entities(sample_text)
        
        self.assertIn("EMAIL", entities)
        self.assertIn("IP", entities)
        self.assertIn("ORG", entities)
        
    def test_analyze_text_with_ai(self):
        """Test AI-powered text analysis."""
        sample_text = "Jane Smith's email is jane.smith@example.com and she works in San Francisco."
        analyzed_data = analyze_text_with_ai(sample_text)
        
        self.assertIsInstance(analyzed_data, str)
        self.assertIn("EMAIL", analyzed_data)
        
if __name__ == "__main__":
    unittest.main()
