# OSINT-AI-CLI

## 🔍 AI-Powered OSINT CLI Tool

An advanced **AI-powered OSINT (Open Source Intelligence) tool** that automates reconnaissance, collects intelligence, and generates actionable security reports. Built for cybersecurity professionals, penetration testers, and researchers, this tool leverages **AI-driven data extraction, OSINT APIs, and automated risk assessment** to deliver valuable insights.

## 🚀 Features

✅ **Automated OSINT Data Collection** – Scrapes and queries OSINT sources for intelligence (domains, IPs, emails, breaches, etc.).  
✅ **AI-Powered Data Analysis** – Uses NLP to extract and classify relevant entities.  
✅ **Risk Assessment & Scoring** – Prioritizes threats based on AI-driven correlation.  
✅ **Multi-Format Reports** – Outputs findings as JSON, Markdown, and PDF reports.  
✅ **Modular & Extensible** – Easily integrates with additional OSINT sources.

---

## 🛠 Installation

### **Prerequisites**
- Python 3.8+
- Virtual environment (recommended)
- API keys for OSINT services (e.g., Shodan, Censys, Have I Been Pwned)

### **Setup Instructions**
```bash
# Clone the repository
git clone https://github.com/Mawgaming/osint-ai-cli.git
cd osint-ai-cli

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # (Linux/macOS)
venv\Scripts\activate    # (Windows)

# Install dependencies
pip install -r requirements.txt
```

---

## 🔎 Usage

### **Basic OSINT Scan**
```bash
python osint_ai.py --target example.com --scan-type full
```

### **Available Arguments**
| Argument | Description |
|----------|-------------|
| `--target` | Specifies the target (domain, IP, email) |
| `--scan-type` | Type of scan: `basic`, `full`, `breach` |
| `--output` | Format of report (`json`, `markdown`, `pdf`) |

### **Example Output**
```
[✓] Found exposed emails linked to data breaches.
[!] ALERT: example.com uses outdated Apache server (CVE-2022-1234)
```

---

## 🌍 Supported OSINT APIs
- **Shodan** – Network & vulnerability intelligence
- **Censys** – Internet-wide scanning
- **Have I Been Pwned** – Breach data lookup
- **VirusTotal** – Malware and reputation analysis
- **AbuseIPDB** – Malicious IP detection

---

## 🗺 Roadmap
- 📊 **Enhance Report Formatting** (Markdown & PDF improvements)
- 🌐 **Web UI for Interactive Analysis**
- 🔄 **Automated OSINT Monitoring & Scheduled Scans**
- 📡 **Integration with More OSINT APIs** (GreyNoise, SecurityTrails, URLScan)

---

## 🤝 Contributing
Contributions are welcome! If you'd like to help improve this tool, follow these steps:
1. Fork the repo & clone it locally.
2. Create a new branch: `git checkout -b feature-branch`
3. Make your changes and commit them.
4. Push your branch: `git push origin feature-branch`
5. Submit a pull request!

---

## 📝 License
This project is licensed under the **MIT License** – free to use, modify, and distribute.

---

## 🎯 Author
👨‍💻 **Mawgaming** – Open-source developer & cybersecurity enthusiast. Feel free to connect and contribute!

📌 **GitHub:** [Mawgaming/osint-ai-cli](https://github.com/Mawgaming/osint-ai-cli)

