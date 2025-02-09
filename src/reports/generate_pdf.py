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
        pdf.set_font("Arial", style='B', size=16)
        pdf.cell(200, 10, "OSINT Analysis Report", ln=True, align='C')
        pdf.ln(10)

        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, f"Target: {data.get('target', 'N/A')}", ln=True)
        pdf.ln(5)

        if "shodan" in data:
            pdf.set_font("Arial", style='B', size=14)
            pdf.cell(200, 10, "Shodan Results", ln=True)
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, f"Open Ports: {', '.join(map(str, data['shodan'].get('open_ports', [])))}", ln=True)
            pdf.ln(5)

        if "virustotal" in data:
            pdf.set_font("Arial", style='B', size=14)
            pdf.cell(200, 10, "VirusTotal Results", ln=True)
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, f"Malicious: {data['virustotal'].get('malicious', 'N/A')}", ln=True)
            pdf.ln(5)

        if "risk_analysis" in data:
            pdf.set_font("Arial", style='B', size=14)
            pdf.cell(200, 10, "Risk Analysis", ln=True)
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, f"Risk Level: {data['risk_analysis'].get('risk_level', 'N/A')}", ln=True)
            pdf.ln(5)

        pdf.output(filename)
        print(f"[INFO] PDF report saved to {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to save PDF report: {e}")

if __name__ == "__main__":
    sample_data = {
        "target": "example.com",
        "shodan": {"open_ports": [80, 443]},
        "virustotal": {"malicious": False},
        "risk_analysis": {"risk_level": "Low"}
    }
    generate_pdf_report(sample_data)
