import argparse
from src.cli.cli_main import main as cli_main

def main():
    parser = argparse.ArgumentParser(description="OSINT AI CLI Tool")
    parser.add_argument("--target", required=False, help="Target domain or IP for OSINT analysis")
    parser.add_argument("--scan-type", choices=["shodan", "virustotal", "full"], help="Specify the scan type")
    args = parser.parse_args()
    
    if args.target:
        cli_main()
    else:
        print("[INFO] Run 'python main.py --help' for usage instructions.")

if __name__ == "__main__":
    import sys
    if "--help" in sys.argv:  # ✅ Manually force `argparse` to trigger help
        import argparse
        parser = argparse.ArgumentParser(description="AI-Powered OSINT CLI Tool")
        parser.print_help()
        sys.exit(0)
    main()
