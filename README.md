# OSINT-AI CLI Tool

## 📌 Overview
The **OSINT-AI CLI Tool** is a powerful, AI-powered reconnaissance and intelligence-gathering tool designed for cybersecurity professionals, ethical hackers, and researchers. It automates OSINT (Open Source Intelligence) tasks by leveraging APIs such as **Shodan** and **VirusTotal**, AI-driven text analysis, and risk assessment capabilities.

## 🚀 Features
- **Automated OSINT Scanning** (Domain, IP, URL analysis)
- **API Integrations:** Shodan & VirusTotal
- **AI-Powered Risk Assessment**
- **Data Processing & Reporting** (JSON, CSV, Markdown, PDF)
- **Command-Line Interface (CLI) for Easy Usage**

## 🛠️ Installation
### **Prerequisites**
Ensure you have the following installed:
- **Python 3.8+**
- **pip (Python package manager)**

### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/yourusername/osint-ai-cli.git
cd osint-ai-cli
```

### **2️⃣ Set Up Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### **3️⃣ Install Dependencies**
```bash
pip install -r requirements.txt
```

## 🔑 API Configuration
Before running scans, set up your API keys in `config/settings.json`:
```json
{
    "shodan_api_key": "YOUR_SHODAN_API_KEY",
    "virustotal_api_key": "YOUR_VIRUSTOTAL_API_KEY"
}
```

## 🖥️ Usage
Run a basic OSINT scan using Shodan:
```bash
python src/cli/cli_main.py --target example.com --scan-type shodan
```

Generate reports:
```bash
python src/reports/generate_json.py
python src/reports/generate_markdown.py
python src/reports/generate_pdf.py
```

## 🧪 Running Tests
Run unit tests to validate functionality:
```bash
python -m unittest discover tests
```

## 📜 License
This project is licensed under the **MIT License**.

## 👤 Author
Developed by **Your Name** - [GitHub Profile](https://github.com/yourusername)

---
For any issues or feature requests, please open an **issue** in the repository. 🚀
