import requests
import logging
from src.core.api_manager import get_api_key

# Load API keys dynamically
SHODAN_API_KEY = get_api_key("shodan")
VIRUSTOTAL_API_KEY = get_api_key("virustotal")

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

def shodan_search(target):
    """Search for a target on Shodan."""
    base_url = f"https://api.shodan.io/shodan/host/{target}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(base_url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Shodan request failed: {e}")
        return {"error": "Shodan scan failed", "message": str(e)}

def virustotal_scan(target):
    """Scan a target with VirusTotal."""
    # Ensure the target is a valid domain or IP
    target = target.replace("http://", "").replace("https://", "").strip("/")
    
    base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(base_url, headers=headers)
        response.raise_for_status()
        json_response = response.json()
        
        if "data" not in json_response:
            return {"error": "Unexpected response format from VirusTotal", "data": {}}
        
        return json_response

    except requests.exceptions.RequestException as e:
        logging.error(f"VirusTotal request failed: {e}")
        return {"error": "VirusTotal scan failed", "message": str(e)}

def run_osint_scan(target):
    """Runs OSINT scans on a given target and returns structured results."""
    return {
        "shodan": shodan_search(target),
        "virustotal": virustotal_scan(target)
    }
