import whois
import logging
import json

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def query_whois(domain):
    """Perform a WHOIS lookup using Python's `whois` package."""
    try:
        w = whois.whois(domain)
        result = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "status": w.status,
            "name_servers": w.name_servers
        }
        return result
    except Exception as e:
        logging.error(f"[ERROR] WHOIS lookup failed: {e}")
        return {"error": "WHOIS lookup failed", "message": str(e)}

if __name__ == "__main__":
    sample_domain = "bbc.com"
    print(json.dumps(query_whois(sample_domain), indent=4))

