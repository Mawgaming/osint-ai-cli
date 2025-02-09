import json

def generate_json_report(data, filename="osint_report.json"):
    """Generates a JSON report from OSINT analysis data."""
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        print(f"[INFO] JSON report saved to {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to save JSON report: {e}")

if __name__ == "__main__":
    sample_data = {
        "target": "example.com",
        "shodan": {"open_ports": [80, 443]},
        "virustotal": {"malicious": False},
        "risk_analysis": {"risk_level": "Low"}
    }
    generate_json_report(sample_data)
