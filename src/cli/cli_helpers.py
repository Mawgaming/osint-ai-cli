import json

def format_output(data):
    """Formats data into a readable JSON string."""
    return json.dumps(data, indent=4)

def print_results(results):
    """Prints formatted results to the console."""
    print("\n[INFO] OSINT Analysis Results:")
    print(format_output(results))

def save_results_to_file(results, filename):
    """Saves results to a specified file based on format."""
    try:
        if filename.endswith(".json"):
            with open(filename, "w") as file:
                json.dump(results, file, indent=4)
        elif filename.endswith(".md"):
            with open(filename, "w") as file:
                file.write("# OSINT Analysis Report\n\n")
                file.write(f"## Target: {results.get('extracted_data', {}).get('domains', ['N/A'])[0]}\n\n")
                file.write(f"### Risk Level: **{results.get('risk_report', {}).get('risk_level', 'Unknown')}**\n\n")
                file.write("## Findings\n")
                file.write(f"- **Identified IPs:** {', '.join(results.get('extracted_data', {}).get('ips', []) )}\n")
                file.write(f"- **Identified Domains:** {', '.join(results.get('extracted_data', {}).get('domains', []))}\n")
                file.write(f"- **Detected CVEs:** {', '.join(results.get('extracted_data', {}).get('cves', []))}\n\n")
        elif filename.endswith(".pdf"):
            from src.reports.generate_pdf import generate_pdf_report
            generate_pdf_report(results, folder="data/reports/")
        else:
            print(f"[ERROR] Unsupported file format: {filename}")
            return
        
        print(f"[INFO] Results saved to {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to save results: {e}")

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
    print_results(sample_data)
    save_results_to_file(sample_data, "data/reports/osint_results.json")
