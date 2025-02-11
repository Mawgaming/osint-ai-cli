import argparse
from src.core.ai_processing import analyze_text_with_ai
from src.cli.cli_helpers import print_results, save_results_to_file

def main():
    """AI-Powered OSINT CLI Tool"""
    parser = argparse.ArgumentParser(description="AI-Powered OSINT CLI Tool")
    parser.add_argument("--target", required=True, help="Target domain or IP for OSINT analysis")
    parser.add_argument("--output", choices=["json", "md", "pdf"], default="json", help="Output format")
    args = parser.parse_args()
    
    print(f"[INFO] Running OSINT scan for target: {args.target}")

    # Run AI-powered OSINT processing
    results = analyze_text_with_ai(args.target)

    # Display results
    print_results(results)

    # Save results in the chosen format
    report_filename = f"data/reports/osint_results.{args.output}"
    save_results_to_file(results, report_filename)

    print(f"[INFO] OSINT analysis complete. Report saved as {report_filename}.")

if __name__ == "__main__":
    main()
