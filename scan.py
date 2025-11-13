# scan.py (run this from your project root)
import os
from pathlib import Path
import csv

from utils.feature_Extractor import extract_pe_features_vector, is_pe_file, FEATURE_NAMES
from utils.predict import load_model_and_scaler, predict_from_vector

def walk_all_files(root_folder: str):
    """Recursively yield all file paths in the folder."""
    for r, _, files in os.walk(root_folder):
        for fname in files:
            yield os.path.join(r, fname)

def main():
    folder = input("Enter folder path to scan: ").strip().strip('"')
    if not os.path.isdir(folder):
        print("❌ Path does not exist or is not a directory.")
        return

    estimator, scaler = load_model_and_scaler()
    print("✅ Model loaded.\n")

    results = []
    total = 0
    malicious = 0
    legit = 0

    for path in walk_all_files(folder):
        total += 1
        try:
            if not is_pe_file(path):
                # Treat non-PE files as legitimate
                label = "Safe"
                legit += 1
                print(f"{path} → Not a PE file → Marked as Legitimate")
            else:
                vec = extract_pe_features_vector(path)
                _, label = predict_from_vector(vec, estimator, scaler)
                if label == "Malicious":
                    malicious += 1
                else:
                    legit += 1
                print(f"{path} → {label}")
            results.append({"file": path, "label": label})
        except Exception as e:
            print(f"⚠️  Error on {path}: {e}")
            results.append({"file": path, "label": "Error"})

    # Save results to CSV
    out_csv = Path("scan_results.csv")
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "label"])
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    # Print summary
    print("\n=== Scan Summary ===")
    print(f"Total files       : {total}")
    print(f"Predicted Legit   : {legit}")
    print(f"Predicted Malicious: {malicious}")
    print(f"Saved CSV         : {out_csv.resolve()}")

if __name__ == "__main__":
    main()
