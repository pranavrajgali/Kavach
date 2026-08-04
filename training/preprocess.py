import os
import json
import zipfile
import re
from pathlib import Path

def extract_smali_strings_from_apk(apk_path: Path):
    """Simple lightweight extractor that searches APK DEX files for Smali API calls."""
    slices = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            for name in zip_ref.namelist():
                if name.endswith('.dex'):
                    dex_bytes = zip_ref.read(name)
                    # Extract printable strings representing suspicious API calls
                    found_strings = re.findall(rb'(L[a-zA-Z0-9_\/$]+;->[a-zA-Z0-9_]+)', dex_bytes)
                    matched_calls = [s.decode('utf-8', errors='ignore') for s in found_strings if len(s) > 10]
                    if matched_calls:
                        # Group calls into slices
                        for i in range(0, len(matched_calls), 15):
                            chunk = matched_calls[i:i+15]
                            slice_text = "\n".join(chunk)
                            slices.append(slice_text)
    except Exception as e:
        print(f"[WARN] Error reading {apk_path.name}: {e}")

    if not slices:
        # Fallback slice if no DEX strings parsed
        slices.append(f"invoke-virtual {{v0}}, Landroid/content/Context;->getPackageName; //{apk_path.name}")
    
    return slices

def preprocess_dataset(data_dir: str = "data", output_path: str = "data/processed_slices.jsonl"):
    """
    Ingests raw APK datasets (data/Benign and data/Malicious).
    Extracts control flow/API call slices and serializes them into .jsonl format.
    """
    print("[DATA] Starting APK Dataset Preprocessing...")
    root = Path(data_dir)
    benign_dir = root / "Benign"
    malicious_dir = root / "Malicious"

    samples = []

    # 1. Process Benign APKs
    if benign_dir.exists():
        benign_apks = list(benign_dir.glob("*.apk"))
        print(f"[DATA] Found {len(benign_apks)} Benign APKs.")
        for apk in benign_apks[:250]:  # Limit to 250 for balanced pretraining
            slices = extract_smali_strings_from_apk(apk)
            for s in slices:
                samples.append({"slice_text": s, "label": 0, "apk": apk.name})

    # 2. Process Malicious APKs
    if malicious_dir.exists():
        malicious_apks = list(malicious_dir.glob("*.apk"))
        print(f"[DATA] Found {len(malicious_apks)} Malicious APKs.")
        for apk in malicious_apks[:250]:  # Limit to 250 for balanced pretraining
            slices = extract_smali_strings_from_apk(apk)
            for s in slices:
                samples.append({"slice_text": s, "label": 1, "apk": apk.name})

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"[SAVE] Writing {len(samples)} preprocessed slices to: '{out_file.resolve()}'")
    with open(out_file, "w", encoding="utf-8") as f:
        for item in samples:
            f.write(json.dumps(item) + "\n")

    print("[OK] Preprocessing Complete!\n")

if __name__ == "__main__":
    preprocess_dataset()
