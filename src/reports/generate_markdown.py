import os
from datetime import datetime

def generate_markdown_report(data, folder="data/reports/"):
    """Generates a Markdown report and saves it in the reports directory."""
    os.makedirs(folder, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(folder, f"osint_report_{timestamp}.md")

    try:
        with open(filename, "w") as file:
            file.write("# OSINT Analysis Report\n\n")
            file.write(f"## Target: {data.get('extracted_data', {}).get('domains', ['N/A'])[0]}\n\n")
            file.write(f"### Risk Level: **{data.get('risk_report', {}).get('risk_level', 'Unknown')}**\n\n")

            file.write("## Findings\n")
            file.write(f"- **Identified IPs:** {', '.join(data.get('extracted_data', {}).get('ips', []))}\n")
            file.write(f"- **Identified Domains:** {', '.join(data.get('extracted_data', {}).get('domains', []))}\n")
            file.write(f"- **Detected CVEs:** {', '.join(data.get('extracted_data', {}).get('cves', []))}\n\n")

            file.write("## Shodan Results\n")
            file.write("| IP Address | Details |\n")
            file.write("|------------|---------|\n")
            for ip, result in data.get("osint_results", {}).get("shodan", {}).items():
                file.write(f"| {ip} | {result} |\n")
            file.write("\n")

            file.write("## VirusTotal Results\n")
            file.write("| Target | Details |\n")
            file.write("|--------|---------|\n")
            for target, result in data.get("osint_results", {}).get("virustotal", {}).items():
                file.write(f"| {target} | {result} |\n")
            file.write("\n")

            file.write("\n## Scan Summary\n")
            for detail in data.get("risk_report", {}).get("details", []):
                file.write(f"- {detail}\n")

        print(f"[INFO] Markdown report saved to {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to save Markdown report: {e}")

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
    generate_markdown_report(sample_data)
