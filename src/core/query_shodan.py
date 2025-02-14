import requests
import logging
from src.core.api_manager import get_api_key

# Load API key
SHODAN_API_KEY = get_api_key("shodan")

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

def query_shodan(target):
    """Search for an IP or domain on Shodan."""
    
    if target.replace(".", "").isdigit():
        return {"error": "Shodan Free API does not support IP lookups"}

    # Use domain lookup for free API
    base_url = f"https://api.shodan.io/dns/domain/{target}?key={SHODAN_API_KEY}"

    try:
        response = requests.get(base_url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] Shodan request failed: {e}")
        return {"error": "Shodan scan failed", "message": str(e)}

if __name__ == "__main__":
    sample_target = "bbc.com"
    print(query_shodan(sample_target))
