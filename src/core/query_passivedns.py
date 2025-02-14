import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def query_passivedns(domain):
    """Perform a passive DNS lookup using the `host` or `nslookup` command."""
    try:
        result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        logging.error(f"[ERROR] Passive DNS lookup failed: {e}")
        return {"error": "Passive DNS lookup failed", "message": str(e)}

if __name__ == "__main__":
    sample_domain = "example.com"
    print(query_passivedns(sample_domain))
