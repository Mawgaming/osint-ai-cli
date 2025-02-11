from fpdf import FPDF 
import os
from datetime import datetime

def generate_pdf_report(data, folder="data/reports/"):
    """Generates a PDF report and saves it in the reports directory."""
    os.makedirs(folder, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(folder, f"osint_report_{timestamp}.pdf")

    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # Use Times font for better encoding support
        pdf.set_font("Times", style='B', size=16)
        pdf.cell(200, 10, "OSINT Analysis Report", ln=True, align='C')
        pdf.ln(10)

        # Target
        pdf.set_font("Times", style='B', size=14)
        pdf.cell(200, 10, "Target", ln=True)
        pdf.set_font("Times", size=12)
        domains = data.get('extracted_data', {}).get('domains', [])
        target = domains[0] if domains else "N/A"
        pdf.cell(200, 10, target, ln=True)
        pdf.ln(5)

        # Risk Level
        pdf.set_font("Times", style='B', size=14)
        pdf.cell(200, 10, "Risk Level", ln=True)
        pdf.set_font("Times", size=12)
        risk_level = data.get("risk_report", {}).get("risk_level", "Unknown")
        pdf.cell(200, 10, risk_level, ln=True)
        pdf.ln(10)

        # Findings
        pdf.set_font("Times", style='B', size=14)
        pdf.cell(200, 10, "Findings", ln=True)
        pdf.set_font("Times", size=12)
        pdf.cell(200, 10, f"Identified IPs: {', '.join(data.get('extracted_data', {}).get('ips', []))}", ln=True)
        pdf.cell(200, 10, f"Identified Domains: {', '.join(domains)}", ln=True)
        pdf.cell(200, 10, f"Detected CVEs: {', '.join(data.get('extracted_data', {}).get('cves', []))}", ln=True)
        pdf.ln(5)

        # Shodan Results
        pdf.set_font("Times", style='B', size=14)
        pdf.cell(200, 10, "Shodan Results", ln=True)
        pdf.set_font("Times", size=12)
        pdf.cell(100, 10, "IP Address", border=1, ln=False, align="C")
        pdf.cell(100, 10, "Details", border=1, ln=True, align="C")
        for ip, result in data.get("osint_results", {}).get("shodan", {}).items():
            pdf.cell(100, 10, ip, border=1, ln=False, align="C")
            pdf.cell(100, 10, str(result), border=1, ln=True, align="C")
        pdf.ln(5)

        # VirusTotal Results
        pdf.set_font("Times", style='B', size=14)
        pdf.cell(200, 10, "VirusTotal Results", ln=True)
        pdf.set_font("Times", size=12)
        pdf.cell(100, 10, "Target", border=1, ln=False, align="C")
        pdf.cell(100, 10, "Details", border=1, ln=True, align="C")
        for target, result in data.get("osint_results", {}).get("virustotal", {}).items():
            pdf.cell(100, 10, target, border=1, ln=False, align="C")
            pdf.cell(100, 10, str(result), border=1, ln=True, align="C")
        pdf.ln(5)

        # Scan Summary
        pdf.set_font("Times", style='B', size=14)
        pdf.cell(200, 10, "Scan Summary", ln=True)
        pdf.set_font("Times", size=12)
        for detail in data.get("risk_report", {}).get("details", []):
            pdf.cell(200, 10, f"- {detail}", ln=True)

        pdf.output(filename)
        print(f"[INFO] PDF report saved to {filename}")
        return filename

    except Exception as e:
        print(f"[ERROR] Failed to save PDF report: {e}")

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
    generate_pdf_report(sample_data)