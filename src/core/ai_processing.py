import re 
import json
import requests
import spacy
import logging
import concurrent.futures
from src.core.query_shodan import query_shodan
from src.core.query_virustotal import query_virustotal
from src.core.query_abuseipdb import query_abuseipdb
from src.core.query_breachdirectory import query_breachdirectory
from src.core.query_username import query_username
from src.core.query_passivedns import query_passivedns
from src.core.query_whois import query_whois

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

HIGH_RISK_PORTS = [22, 3389, 5900]  # SSH, RDP, VNC

# Load NLP model
nlp = spacy.load("en_core_web_sm")

def extract_osint_entities(text):
    """Extract OSINT entities (IPs, domains, emails, CVEs, hashes) from input text using NLP and Regex."""
    extracted = {"ips": [], "domains": [], "emails": [], "hashes": [], "cves": []}

    # Regex patterns
    patterns = {
        "ips": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "domains": r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "cves": r"\bCVE-\d{4}-\d{4,7}\b",
        "hashes": r"\b[a-fA-F0-9]{32,64}\b"
    }

    # Apply regex
    for key, pattern in patterns.items():
        matches = re.findall(pattern, text)
        extracted[key].extend(matches)

    # Apply NLP for additional entity recognition
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ == "ORG" and "." in ent.text:  # Likely a domain
            extracted["domains"].append(ent.text)
        elif ent.label_ == "PERSON" and "@" in ent.text:  # Likely an email
            extracted["emails"].append(ent.text)

    # Remove duplicates
    for key in extracted:
        extracted[key] = list(set(extracted[key]))

    return extracted

def ai_prioritize_findings(results):
    """Prioritize OSINT findings based on risk level."""
    
    prioritized_findings = {"high": [], "medium": [], "low": []}

    # Prioritize open ports on Shodan
    if "shodan" in results:
        for ip, shodan_data in results["shodan"].items():
            if "ports" in shodan_data:
                for port in shodan_data["ports"]:
                    if port in HIGH_RISK_PORTS:
                        logging.warning(f"[HIGH RISK] RDP/SSH/VNC open on {ip}")
                        prioritized_findings["high"].append({"type": "open_port", "ip": ip, "port": port})
                    else:
                        prioritized_findings["medium"].append({"type": "open_port", "ip": ip, "port": port})
    
    # Prioritize breached credentials
    if "breachdirectory" in results:
        for email, breach_data in results["breachdirectory"].items():
            if "breach" in breach_data:
                logging.warning(f"[HIGH RISK] Breached email found: {email}")
                prioritized_findings["high"].append({"type": "breach", "email": email, "breach": breach_data})

    return prioritized_findings

def ai_expand_scan(results):
    """Expand OSINT scan automatically if high-risk indicators are found."""
    
    logging.info("[INFO] Expanding OSINT Scan Based on Findings...")
    threads = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        prioritized_findings = ai_prioritize_findings(results)

        for high_risk in prioritized_findings["high"]:
            if high_risk["type"] == "open_port":
                ip = high_risk["ip"]
                logging.info(f"[EXPANDING] Running additional scans for {ip}")
                threads.append(executor.submit(query_virustotal, ip))
                threads.append(executor.submit(query_abuseipdb, ip))
            
            elif high_risk["type"] == "breach":
                email = high_risk["email"]
                username = email.split("@")[0]
                logging.info(f"[EXPANDING] Checking social media presence for {username}")
                threads.append(executor.submit(query_username, username))

        # Wait for all additional scans to finish
        concurrent.futures.wait(threads)

    return results

def ai_correlate_data(results):
    """Link OSINT findings to expand intelligence."""
    
    logging.info("[INFO] Correlating OSINT Data...")
    threads = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        
        # If Passive DNS finds an IP, scan the IP
        if "passive_dns" in results:
            for domain, dns_data in results["passive_dns"].items():
                if "Addresses" in dns_data:
                    for ip in dns_data["Addresses"]:
                        logging.info(f"[CORRELATION] Found IP {ip} from domain {domain} - Auto-Scanning...")
                        threads.append(executor.submit(query_shodan, ip))
                        threads.append(executor.submit(query_virustotal, ip))
                        threads.append(executor.submit(query_abuseipdb, ip))

        # If an email breach is found, check linked usernames
        if "breachdirectory" in results:
            for email, breach_data in results["breachdirectory"].items():
                if "breach" in breach_data:
                    logging.info(f"[CORRELATION] Found Breach for {email} - Searching for Social Media...")
                    threads.append(executor.submit(query_username, email.split("@")[0]))  # Extract username
        
        concurrent.futures.wait(threads)

    return results

def analyze_text_with_ai(text):
    """Full AI-driven OSINT processing pipeline."""
    extracted = extract_osint_entities(text)

    results = {
        "shodan": {}, 
        "virustotal": {}, 
        "abuseipdb": {}, 
        "breachdirectory": {},
        "passive_dns": {},
        "whois": {},
        "social_media": {}
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        threads = []

        for domain in extracted["domains"]:
            threads.append(executor.submit(lambda d: results["passive_dns"].update({d: query_passivedns(d)}), domain))
            threads.append(executor.submit(lambda d: results["whois"].update({d: query_whois(d)}), domain))

        for ip in extracted["ips"]:
            threads.append(executor.submit(lambda i: results["shodan"].update({i: query_shodan(i)}), ip))
            threads.append(executor.submit(lambda i: results["virustotal"].update({i: query_virustotal(i)}), ip))
            threads.append(executor.submit(lambda i: results["abuseipdb"].update({i: query_abuseipdb(i)}), ip))

        for email in extracted["emails"]:
            threads.append(executor.submit(lambda e: results["breachdirectory"].update({e: query_breachdirectory(e)}), email))

        concurrent.futures.wait(threads)

    results = ai_expand_scan(results)
    results = ai_correlate_data(results)

    return results

if __name__ == "__main__":
    sample_text = input("Enter domain or IP: ")
    print(json.dumps(analyze_text_with_ai(sample_text), indent=4))
