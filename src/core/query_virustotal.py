import requests
import logging
from src.core.api_manager import get_api_key

# Load API key
VIRUSTOTAL_API_KEY = get_api_key("virustotal")

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

def query_virustotal(target):
    """Scan a target with VirusTotal."""
    
    # Check if target is an IP or domain
    if target.replace(".", "").isdigit():
        base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    else:
        base_url = f"https://www.virustotal.com/api/v3/domains/{target}"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(base_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] VirusTotal request failed: {e}")
        return {"error": "VirusTotal scan failed", "message": str(e)}

if __name__ == "__main__":
    sample_target = "8.8.8.8"
    print(query_virustotal(sample_target))
