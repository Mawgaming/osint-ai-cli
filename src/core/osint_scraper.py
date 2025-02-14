import argparse
import logging
import concurrent.futures
from src.core.api_manager import get_api_key
from src.core.query_abuseipdb import query_abuseipdb
from src.core.query_breachdirectory import query_breachdirectory
from src.core.query_passivedns import query_passivedns
from src.core.query_whois import query_whois
from src.core.query_shodan import query_shodan
from src.core.query_virustotal import query_virustotal
from src.core.query_username import query_username
from src.core.ai_processing import ai_expand_scan, ai_correlate_data

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def run_osint_scan(target):
    """Runs OSINT scans including Shodan, VirusTotal, AbuseIPDB, and more."""
    logging.info(f"[INFO] Running OSINT scan for: {target}")

    # Extracted data
    extracted_data = {
        "ips": [target] if target.replace(".", "").isdigit() else [],
        "domains": [target] if "." in target and "@" not in target else [],
        "emails": [target] if "@" in target else []
    }

    print(f"[DEBUG] Extracted Data: {extracted_data}")

    results = {
        "shodan": {}, 
        "virustotal": {}, 
        "abuseipdb": {}, 
        "breachdirectory": {},
        "passive_dns": {},
        "whois": {},
        "social_media": {}
    }

    # Use threading for initial scans
    threads = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:

        # Run domain-based queries (only if it's a domain, not an email)
        for domain in extracted_data.get("domains", []):
            logging.info(f"[DEBUG] Running Passive DNS lookup for {domain}")
            threads.append(executor.submit(lambda d: results["passive_dns"].update({d: query_passivedns(d)}), domain))
            logging.info(f"[DEBUG] Running WHOIS lookup for {domain}")
            threads.append(executor.submit(lambda d: results["whois"].update({d: query_whois(d)}), domain))

        # Run IP-based queries
        for ip in extracted_data.get("ips", []):
            logging.info(f"[DEBUG] Running Shodan scan for {ip}")
            threads.append(executor.submit(lambda i: results["shodan"].update({i: query_shodan(i)}), ip))
            logging.info(f"[DEBUG] Running VirusTotal scan for {ip}")
            threads.append(executor.submit(lambda i: results["virustotal"].update({i: query_virustotal(i)}), ip))
            logging.info(f"[DEBUG] Running AbuseIPDB scan for {ip}")
            threads.append(executor.submit(lambda i: results["abuseipdb"].update({i: query_abuseipdb(i)}), ip))

        # Run email-based queries
        for email in extracted_data.get("emails", []):
            logging.info(f"[DEBUG] Running BreachDirectory scan for {email}")
            threads.append(executor.submit(lambda e: results["breachdirectory"].update({e: query_breachdirectory(e)}), email))

        concurrent.futures.wait(threads)

    # AI-Driven Data Correlation - Multi-Threaded Processing
    results = ai_expand_scan(results)  # Expands scan if high-risk indicators found
    results = ai_correlate_data(results)  # Links OSINT findings dynamically

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
