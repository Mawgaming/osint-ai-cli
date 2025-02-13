import requests
import logging
from src.core.api_manager import get_api_key

# Load BreachDirectory API Key
BREACHDIRECTORY_API_KEY = get_api_key("breachdirectory")

BREACHDIRECTORY_API_URL = "https://breachdirectory.org/api"

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

def query_breachdirectory(email):
    """Search for breached credentials using BreachDirectory.org API."""
    headers = {"X-RapidAPI-Key": BREACHDIRECTORY_API_KEY}

    try:
        response = requests.get(f"{BREACHDIRECTORY_API_URL}?email={email}", headers=headers)
        response.raise_for_status()
        result = response.json()

        if not result:
            logging.warning(f"[WARNING] No breach records found for: {email}")
            return {"status": "not found", "email": email}

        return result

    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] BreachDirectory API request failed: {e}")
        return {"error": "BreachDirectory API request failed", "message": str(e)}

if __name__ == "__main__":
    sample_email = "test@example.com"
    print(query_breachdirectory(sample_email))
