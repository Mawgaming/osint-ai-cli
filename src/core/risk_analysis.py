import json

def assess_risk(osint_results):
    """Assess risk based on Shodan and VirusTotal scan results."""
    risk_score = 0
    risk_factors = {
        "open_ports": 2,
        "vulnerabilities": 3,
        "malicious_activity": 5,
        "positive_detections": 4,  # VirusTotal malware detection
    }

    report = {"risk_level": "Low", "details": []}

    # Process Shodan Results
    for ip, shodan_data in osint_results.get("shodan", {}).items():
        if "error" not in shodan_data:
            open_ports = len(shodan_data.get("ports", []))
            report["details"].append(f"Shodan: {ip} has {open_ports} open ports.")
            risk_score += open_ports * risk_factors["open_ports"]

    # Process VirusTotal Results
    for target, vt_data in osint_results.get("virustotal", {}).items():
        if "error" not in vt_data:
            detections = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if detections > 0:
                report["details"].append(f"VirusTotal: {target} flagged as malicious ({detections} detections).")
                risk_score += detections * risk_factors["positive_detections"]

    # Assign Risk Level
    if risk_score > 10:
        report["risk_level"] = "High"
    elif risk_score > 5:
        report["risk_level"] = "Medium"

    return report

if __name__ == "__main__":
    sample_data = {
        "open_ports": [22, 80, 443],
        "vulnerabilities": ["CVE-2022-1234", "CVE-2023-5678"],
        "malicious_activity": True,
        "exposed_credentials": False
    }
    
    risk_report = assess_risk(sample_data)
    print(json.dumps(risk_report, indent=4))
