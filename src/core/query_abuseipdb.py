import requests
import logging
from src.core.api_manager import get_api_key

# Load API key
ABUSEIPDB_API_KEY = get_api_key("abuseipdb")

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

def query_abuseipdb(ip_address):
    """Query AbuseIPDB for threat intelligence on an IP address."""
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] AbuseIPDB request failed: {e}")
        return {"error": "AbuseIPDB request failed", "message": str(e)}

if __name__ == "__main__":
    sample_ip = "8.8.8.8"  # Example Google IP
    result = query_abuseipdb(sample_ip)
    print(result)
