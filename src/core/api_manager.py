import os
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load API keys from .env file
load_dotenv()

# API keys dictionary (retrieved from environment variables)
API_KEYS = {
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
    "threatfox": os.getenv("THREATFOX_API_KEY"),
    "shodan": os.getenv("SHODAN_API_KEY"),
    "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
    "breachdirectory": os.getenv("BREACHDIRECTORY_API_KEY"),  # X-RapidAPI BreachDirectory Key
}

def get_api_key(service_name):
    """Retrieve an API key dynamically based on the service name."""
    key = API_KEYS.get(service_name.lower(), None)
    if not key:
        logging.warning(f"[WARNING] API key for {service_name} is missing!")
    return key

if __name__ == "__main__":
    print("API Keys Loaded Securely:")
    for key in API_KEYS:
        status = "Loaded" if API_KEYS[key] else "Missing"
        print(f"{key.capitalize()} Key: {status}")
