import argparse
import requests
import logging
from src.core.api_manager import get_api_key
from src.core.query_abuseipdb import query_abuseipdb
from src.core.query_malwarebazaar import query_malware_bazaar
from src.core.query_breachdirectory import query_breachdirectory

# Load API keys dynamically
SHODAN_API_KEY = get_api_key("shodan")
VIRUSTOTAL_API_KEY = get_api_key("virustotal")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def shodan_search(target):
    """Search for a target on Shodan."""
    base_url = f"https://api.shodan.io/shodan/host/{target}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(base_url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] Shodan request failed: {e}")
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
        logging.error(f"[ERROR] VirusTotal request failed: {e}")
        return {"error": "VirusTotal scan failed", "message": str(e)}

def run_osint_scan(target):
    """Runs OSINT scans including Shodan, VirusTotal, AbuseIPDB, and MalwareBazaar."""
    logging.info(f"[INFO] Running OSINT scan for: {target}")

    # Extracted data (Assumes target is either an IP or domain)
    extracted_data = {
        "ips": [target] if target.replace(".", "").isdigit() else [],
        "hashes": []  # Future: Handle malware hash input
    }

    results = {
        "shodan": {}, 
        "virustotal": {}, 
        "abuseipdb": {}, 
        "malware_bazaar": {}, 
        "breachdirectory": {}
    }
    # Check and run queries for IPs
    for ip in extracted_data.get("ips", []):
        results["shodan"][ip] = shodan_search(ip)
        results["virustotal"][ip] = virustotal_scan(ip)
        results["abuseipdb"][ip] = query_abuseipdb(ip)

    # Future expansion: Check and run queries for malware hashes
    for file_hash in extracted_data.get("hashes", []):
        results["malware_bazaar"][file_hash] = query_malware_bazaar(file_hash)
   
    for email in extracted_data.get("emails", []):
        results["breachdirectory"][email] = query_breachdirectory(email)
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT Scraper - Scan domains and IPs.")
    parser.add_argument("--target", required=True, help="Target domain or IP for OSINT analysis")
    
    args = parser.parse_args()

    # Run the OSINT scan
    scan_results = run_osint_scan(args.target)

    # Display the results
    print("\n[INFO] OSINT Scan Results:")
    print(scan_results)
