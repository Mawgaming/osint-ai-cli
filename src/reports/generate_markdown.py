import json

def generate_markdown_report(data, filename="osint_report.md"):
    """Generates a Markdown report from OSINT analysis data."""
    try:
        with open(filename, "w") as file:
            file.write("# OSINT Analysis Report\n\n")
            file.write(f"## Target: {data.get('target', 'N/A')}\n\n")
            
            if "shodan" in data:
                file.write("## Shodan Results\n")
                file.write(f"Open Ports: {', '.join(map(str, data['shodan'].get('open_ports', [])))}\n\n")
            
            if "virustotal" in data:
                file.write("## VirusTotal Results\n")
                file.write(f"Malicious: {data['virustotal'].get('malicious', 'N/A')}\n\n")
            
            if "risk_analysis" in data:
                file.write("## Risk Analysis\n")
                file.write(f"Risk Level: {data['risk_analysis'].get('risk_level', 'N/A')}\n\n")
            
        print(f"[INFO] Markdown report saved to {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to save Markdown report: {e}")

if __name__ == "__main__":
    sample_data = {
        "target": "example.com",
        "shodan": {"open_ports": [80, 443]},
        "virustotal": {"malicious": False},
        "risk_analysis": {"risk_level": "Low"}
    }
    generate_markdown_report(sample_data)
