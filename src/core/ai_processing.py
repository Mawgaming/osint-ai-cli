import re
import json
import requests
import spacy
from collections import defaultdict

# Load English NLP model
nlp = spacy.load("en_core_web_sm")

def extract_entities(text):
    """Extract named entities (emails, domains, IPs) from text."""
    doc = nlp(text)
    entities = defaultdict(list)
    
    for ent in doc.ents:
        if ent.label_ in ["ORG", "PERSON", "GPE"]:
            entities[ent.label_].append(ent.text)
    
    # Extract emails and IPs manually using regex
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
    ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    
    if emails:
        entities["EMAIL"].extend(emails)
    if ips:
        entities["IP"].extend(ips)
    
    return entities

def analyze_text_with_ai(text):
    """Analyze text input using AI-powered NLP."""
    extracted_data = extract_entities(text)
    return json.dumps(extracted_data, indent=4)

if __name__ == "__main__":
    sample_text = "John Doe's email is john.doe@example.com and his office is in New York. " \
                  "His company website is www.example.com and their server IP is 192.168.1.1."
    print(analyze_text_with_ai(sample_text))
