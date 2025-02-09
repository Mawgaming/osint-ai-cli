import json
import os
from datetime import datetime

def generate_json_report(data, folder="data/reports/"):
    """Generates a JSON report and saves it in the reports directory."""
    os.makedirs(folder, exist_ok=True)  # Ensure the folder exists
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(folder, f"osint_report_{timestamp}.json")

    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        print(f"[INFO] JSON report saved to {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to save JSON report: {e}")
