import os
import json
import shutil
import pandas as pd

data_dirs = ["data/scan_results", "data/processed_data", "data/cache"]

# Ensure directories exist
def setup_directories():
    for directory in data_dirs:
        os.makedirs(directory, exist_ok=True)

# Save JSON data to a file
def save_json(data, filename, folder="data/scan_results"):
    filepath = os.path.join(folder, filename)
    try:
        with open(filepath, "w") as file:
            json.dump(data, file, indent=4)
        print(f"[INFO] Data saved to {filepath}")
    except Exception as e:
        print(f"[ERROR] Could not save JSON file: {e}")

# Load JSON data from a file
def load_json(filename, folder="data/scan_results"):
    filepath = os.path.join(folder, filename)
    try:
        with open(filepath, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return None
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON format in {filepath}")
        return None

# Save CSV data to a file
def save_csv(data, filename, folder="data/scan_results"):
    filepath = os.path.join(folder, filename)
    try:
        df = pd.DataFrame([data])
        df.to_csv(filepath, index=False)
        print(f"[INFO] CSV data saved to {filepath}")
    except Exception as e:
        print(f"[ERROR] Could not save CSV file: {e}")

# Load CSV data from a file
def load_csv(filename, folder="data/scan_results"):
    filepath = os.path.join(folder, filename)
    try:
        return pd.read_csv(filepath).to_dict(orient="records")
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return None
    except Exception as e:
        print(f"[ERROR] Could not load CSV file: {e}")
        return None

# Clear cache directory
def clear_cache():
    cache_folder = "data/cache"
    try:
        shutil.rmtree(cache_folder)
        os.makedirs(cache_folder, exist_ok=True)
        print("[INFO] Cache cleared successfully.")
    except Exception as e:
        print(f"[ERROR] Could not clear cache: {e}")

if __name__ == "__main__":
    setup_directories()
    sample_data = {"target": "example.com", "result": "Sample scan data"}
    save_json(sample_data, "example_scan.json")
    save_csv(sample_data, "example_scan.csv")
    loaded_data_json = load_json("example_scan.json")
    loaded_data_csv = load_csv("example_scan.csv")
    print("Loaded JSON Data:", loaded_data_json)
    print("Loaded CSV Data:", loaded_data_csv)
    clear_cache()
