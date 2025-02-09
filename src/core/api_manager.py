import json
import os
import logging

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

def get_settings_path():
    """Get the absolute path to settings.json, ensuring it works in both CLI & Flask."""
    base_dir = os.path.dirname(os.path.abspath(__file__))  # Current directory of api_manager.py
    return os.path.join(base_dir, "..", "..", "config", "settings.json")  # Adjusted path

def load_api_keys():
    """Loads API keys from the settings.json file safely."""
    config_path = get_settings_path()

    try:
        with open(config_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        logging.error("[ERROR] Missing config/settings.json file! Please set up API keys.")
        return {}
    except json.JSONDecodeError:
        logging.error("[ERROR] Invalid JSON format in settings.json!")
        return {}

# Load API keys once when module is imported
API_KEYS = load_api_keys()

def get_api_key(service_name):
    """Retrieve an API key dynamically based on the service name."""
    return API_KEYS.get(f"{service_name}_api_key", None)

# If run directly, print API key status
if __name__ == "__main__":
    print("Shodan API Key:", get_api_key("shodan"))
    print("VirusTotal API Key:", get_api_key("virustotal"))
