import json

def format_output(data):
    """Formats data into a readable JSON string."""
    return json.dumps(data, indent=4)

def print_results(results):
    """Prints formatted results to the console."""
    print("\n[INFO] OSINT Analysis Results:")
    print(format_output(results))

def save_results_to_file(results, filename="results.json"):
    """Saves results to a specified file."""
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    print(f"[INFO] Results saved to {filename}")

if __name__ == "__main__":
    sample_data = {
        "target": "example.com",
        "shodan": {"open_ports": [80, 443]},
        "virustotal": {"malicious": False},
        "risk_level": "Low"
    }
    print_results(sample_data)
    save_results_to_file(sample_data)
