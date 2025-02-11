import re
import json
import requests
import spacy
from collections import defaultdict
from datetime import datetime
from src.core.data_manager import save_json
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
    """Extracts entities, runs OSINT scans only if valid targets exist, assesses risk, and generates reports."""
    extracted_data = extract_entities(text)

    # Check if there are valid domains or IPs before running the scan
    if extracted_data.get("domains") or extracted_data.get("ips"):
        osint_results = run_osint_scan(extracted_data)
        risk_report = assess_risk(osint_results)
    else:
        osint_results = {"shodan": {}, "virustotal": {}}
        risk_report = {"risk_level": "Unknown", "details": ["No valid target found."]}

    final_result = {
        "extracted_data": extracted_data,
        "osint_results": osint_results,
        "risk_report": risk_report,
    }

    # Generate reports in all formats
    #generate_json_report(final_result)
    #generate_markdown_report(final_result)
    #generate_pdf_report(final_result)

    return final_result

if __name__ == "__main__":
    sample_text = input("Enter domain or IP: ")  # Ask for user input
    print(json.dumps(analyze_text_with_ai(sample_text), indent=4))
