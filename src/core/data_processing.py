import json
import pandas as pd

def clean_data(raw_data):
    """Cleans and structures extracted OSINT data."""
    if not raw_data:
        return {}
    
    cleaned_data = {
        "domains": list(set(raw_data.get("domains", []))),
        "emails": list(set(raw_data.get("emails", []))),
        "ips": list(set(raw_data.get("ips", []))),
        "usernames": list(set(raw_data.get("usernames", []))),
        "vulnerabilities": raw_data.get("vulnerabilities", []),
        "risk_level": raw_data.get("risk_level", "Unknown"),
        "darkweb": raw_data.get("darkweb", {}),
        "social_media": raw_data.get("social_media", {}),
        "passive_dns": raw_data.get("passive_dns", {}),
        "whois": raw_data.get("whois", {}),
        "reverse_image_search": raw_data.get("reverse_image_search", {})
    }
    return cleaned_data

def save_to_json(data, filename="processed_data.json"):
    """Saves structured data to a JSON file."""
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)
    print(f"Data saved to {filename}")

def save_to_csv(data, filename="processed_data.csv"):
    """Saves structured data to a CSV file."""
    df = pd.DataFrame([data])
    df.to_csv(filename, index=False)
    print(f"Data saved to {filename}")

if __name__ == "__main__":
    sample_data = {
        "domains": ["example.com", "test.com"],
        "emails": ["admin@example.com", "contact@test.com"],
        "ip_addresses": ["192.168.1.1", "10.0.0.1"],
        "vulnerabilities": ["CVE-2022-1234", "CVE-2023-5678"],
        "risk_level": "High"
    }
    
    cleaned = clean_data(sample_data)
    save_to_json(cleaned)
    save_to_csv(cleaned)
