#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

def process_advisories(file_paths):
    """
    Reads a list of paths to JSON advisory files, extracts CVEs, 
    and saves them into organized folders.
    """
    cve_year_pattern = re.compile(r"CVE-(\d{4})-\d+", re.IGNORECASE)
    files_processed = 0

    for path_str in file_paths:
        file_path = Path(path_str)
        
        if not file_path.exists():
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                advisory = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error reading {file_path}: {e}")
            continue

        # Ensure it's a valid GitHub Advisory
        if "id" not in advisory or not advisory.get("id", "").startswith("GHSA"):
            continue

        # Extract all valid CVE markers from the 'aliases' list
        cve_aliases = [
            alias.upper() for alias in advisory.get("aliases", [])
            if isinstance(alias, str) and alias.upper().startswith("CVE-")
        ]

        # Skip if no CVEs exist
        if not cve_aliases:
            continue

        # Process each CVE found in the advisory
        for cve_id in cve_aliases:
            match = cve_year_pattern.search(cve_id)
            year = match.group(1) if match else "Unknown_Year"

            # Create directory for the year
            target_folder = Path(year)
            target_folder.mkdir(parents=True, exist_ok=True)

            # Write the JSON to the specific CVE file
            target_file = target_folder / f"{cve_id}.json"
            
            with open(target_file, "w", encoding="utf-8") as out_f:
                json.dump(advisory, out_f, indent=2, ensure_ascii=False)
            
            files_processed += 1

    print(f"Successfully processed {files_processed} CVE entries.")

if __name__ == "__main__":
    # Get file paths from command line arguments
    # (The workflow will pass these via 'temp_data/*.json')
    if len(sys.argv) < 2:
        print("Usage: python3 sync_advisories.py <file1.json> <file2.json> ...")
        sys.exit(1)
        
    process_advisories(sys.argv[1:])
