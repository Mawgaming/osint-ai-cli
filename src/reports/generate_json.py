import json
import os
from datetime import datetime

def generate_json_report(data, folder="data/reports/"):
    """Generates a JSON report and saves it in the reports directory."""
    os.makedirs(folder, exist_ok=True)  # Ensure the folder exists
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(folder, f"osint_report_{timestamp}.json")

    try:

        # Structure the data more cleanly
        domains = data.get("extracted_data", {}).get("domains", [])

        # Structure the data more cleanly
        formatted_data = {
            "Target": domains[0] if domains else "N/A",
            "Risk Level": data.get("risk_report", {}).get("risk_level", "Unknown"),
            "Findings": {
                "Identified IPs": data.get("extracted_data", {}).get("ips", []),
                "Identified Domains": data.get("extracted_data", {}).get("domains", []),
                "Detected CVEs": data.get("extracted_data", {}).get("cves", []),
                "Open Ports (Shodan)": data.get("osint_results", {}).get("shodan", {}),
                "VirusTotal Findings": data.get("osint_results", {}).get("virustotal", {}),
            },
            "Scan Summary": data.get("risk_report", {}).get("details", [])
        }

        # Write the structured data to JSON file
        with open(filename, "w") as file:
            json.dump(formatted_data, file, indent=4)

        print(f"[INFO] JSON report saved to {filename}")

    except Exception as e:
        print(f"[ERROR] Failed to save JSON report: {e}")

if __name__ == "__main__":
    sample_data = {
        "extracted_data": {
            "domains": ["example.com"],
            "ips": ["192.168.1.1"],
            "cves": ["CVE-2023-1234"]
        },
        "osint_results": {
            "shodan": {"192.168.1.1": "Open Ports: 80, 443"},
            "virustotal": {"example.com": "No malicious activity detected"}
        },
        "risk_report": {
            "risk_level": "Low",
            "details": ["No immediate threats detected."]
        }
    }
    
    # Call the correct function for JSON report
    generate_json_report(sample_data)
