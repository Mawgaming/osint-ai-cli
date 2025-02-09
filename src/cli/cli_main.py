import argparse
import json
from src.core.osint_scraper import shodan_search, virustotal_scan
from src.core.risk_analysis import assess_risk
from src.core.data_processing import clean_data, save_to_json, save_to_csv

def main():
    """AI-Powered OSINT CLI Tool"""
    parser = argparse.ArgumentParser(description="AI-Powered OSINT CLI Tool")
    parser.add_argument("--target", required=True, help="Target domain or IP for OSINT analysis")
    parser.add_argument("--scan-type", choices=["shodan", "virustotal", "full"], default="full", help="Specify the scan type")
    parser.add_argument("--output", choices=["json", "csv"], default="json", help="Output format")
    args = parser.parse_args()
    
    results = {}

    print(f"[INFO] Starting OSINT scan for target: {args.target}")  # ✅ General logging

    # ✅ Fix `test_shodan_scan`
    if args.scan_type in ["shodan", "full"]:
        print("[INFO] Running Shodan scan")  # ✅ Ensure log message appears
        results["shodan"] = shodan_search(args.target)

    # ✅ Fix `test_virustotal_scan`
    if args.scan_type in ["virustotal", "full"]:
        print("[INFO] Running VirusTotal scan...")
        results["virustotal"] = virustotal_scan(args.target) or {"error": "VirusTotal scan failed"}  # Ensure `dict` output

    # ✅ Fix risk analysis logging
    print("[INFO] Assessing risk...")
    results["risk_analysis"] = assess_risk(results)

    # ✅ Fix data cleaning logging
    print("[INFO] Cleaning data...")
    cleaned_results = clean_data(results)

    # ✅ Ensure valid JSON output for `test_output_format`
    if args.output == "json":
        save_to_json(cleaned_results)
        output_json = json.dumps(cleaned_results, indent=4)
        print(output_json)  # ✅ This ensures JSON output is printed properly

    elif args.output == "csv":
        save_to_csv(cleaned_results)

    print("[INFO] OSINT analysis complete.")

if __name__ == "__main__":
    main()
