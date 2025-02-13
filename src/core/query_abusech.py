import requests
import logging
from src.core.api_manager import get_api_key

# Load ThreatFox API Key
THREATFOX_API_KEY = get_api_key("threatfox")

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

def query_threatfox(ioc):
    """Query ThreatFox for intelligence on an IP, domain, or file hash."""
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {
        "query": "search_ioc",
        "search_term": ioc,
        "api_key": THREATFOX_API_KEY
    }

    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        result = response.json()

        if "query_status" in result and result["query_status"] == "no_result":
            logging.warning(f"[WARNING] No ThreatFox records found for: {ioc}")
            return {"status": "not found", "ioc": ioc}

        return result

    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] ThreatFox request failed: {e}")
        return {"error": "ThreatFox request failed", "message": str(e)}

if __name__ == "__main__":
    sample_ioc = "8.8.8.8"  # Example IP (Google Public DNS)
    print(query_threatfox(sample_ioc))
