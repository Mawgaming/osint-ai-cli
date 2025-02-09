import re
import json
import requests
import spacy
from collections import defaultdict
from src.core.osint_scraper import run_osint_scan
from src.core.risk_analysis import assess_risk

# Load English NLP model
nlp = spacy.load("en_core_web_sm")

# Regex patterns for OSINT entity extraction
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
CVE_REGEX = r"CVE-\d{4}-\d{4,7}"
HASH_REGEX = r"\b[a-fA-F0-9]{32,64}\b"  # Matches MD5, SHA-1, SHA-256

def extract_entities(text):
    """Extract emails, IPs, domains, CVEs, and hashes from text."""
    extracted_data = {
        "emails": re.findall(EMAIL_REGEX, text),
        "ips": re.findall(IP_REGEX, text),
        "domains": re.findall(DOMAIN_REGEX, text),
        "cves": re.findall(CVE_REGEX, text),
        "hashes": re.findall(HASH_REGEX, text),
        "named_entities": defaultdict(list)
    }

    # Use NLP for additional entity recognition
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ in ["ORG", "PERSON", "GPE"]:
            extracted_data["named_entities"][ent.label_].append(ent.text)

    return extracted_data

def analyze_text_with_ai(text):
    """Extracts entities, runs OSINT scans, and assesses risk."""
    extracted_data = extract_entities(text)  # Step 1: Extract Entities
    osint_results = run_osint_scan(extracted_data)  # Step 2: Run Scans
    risk_report = assess_risk(osint_results)  # Step 3: Risk Assessment

    return {
        "extracted_data": extracted_data,
        "osint_results": osint_results,
        "risk_report": risk_report,
}

if __name__ == "__main__":
    sample_text = """
    John Doe's email is john.doe@example.com and his office is in New York.
    His company website is www.example.com and their server IP is 192.168.1.1.
    They are vulnerable to CVE-2023-1234. The system hash is 5d41402abc4b2a76b9719d911017c592.
    """
    print(analyze_text_with_ai(sample_text))
