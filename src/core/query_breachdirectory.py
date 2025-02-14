import requests
import logging
from src.core.api_manager import get_api_key

# Load API key
BREACHDIRECTORY_API_KEY = get_api_key("breachdirectory")

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

def query_breachdirectory(email):
    """Check if an email appears in known breaches using BreachDirectory API."""
    
    base_url = f"https://breachdirectory.org/api?email={email}"
    headers = {"Authorization": f"Bearer {BREACHDIRECTORY_API_KEY}"}

    try:
        response = requests.get(base_url, headers=headers, timeout=5)
        if response.status_code == 403:
            logging.warning("[WARNING] BreachDirectory API returned 403 Forbidden. Check API key or rate limits.")
            return {"error": "BreachDirectory API request failed", "message": "API key invalid or rate limit exceeded"}

        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] BreachDirectory request failed: {e}")
        return {"error": "BreachDirectory scan failed", "message": str(e)}

if __name__ == "__main__":
    sample_email = "test@example.com"
    print(query_breachdirectory(sample_email))
