import json

def assess_risk(data):
    """Assess the risk level based on OSINT findings."""
    risk_score = 0
    risk_factors = {
        "open_ports": 2,
        "vulnerabilities": 3,
        "malicious_activity": 5,
        "exposed_credentials": 4,
    }
    
    report = {
        "risk_level": "Low",
        "details": []
    }
    
    if "open_ports" in data:
        report["details"].append(f"Open ports detected: {len(data['open_ports'])}")
        risk_score += len(data["open_ports"]) * risk_factors["open_ports"]
    
    if "vulnerabilities" in data:
        report["details"].append(f"Known vulnerabilities found: {len(data['vulnerabilities'])}")
        risk_score += len(data["vulnerabilities"]) * risk_factors["vulnerabilities"]
    
    if "malicious_activity" in data and data["malicious_activity"]:
        report["details"].append("Malicious activity detected!")
        risk_score += risk_factors["malicious_activity"]
    
    if "exposed_credentials" in data and data["exposed_credentials"]:
        report["details"].append("Exposed credentials found!")
        risk_score += risk_factors["exposed_credentials"]
    
    # Determine risk level
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
