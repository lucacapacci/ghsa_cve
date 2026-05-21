#!/usr/bin/env python3
import json
import re
import urllib.request
from pathlib import Path

def fetch_and_sync_advisories():
    url = "https://api.github.com/advisories?per_page=100"
    req = urllib.request.Request(
        url, headers={"User-Agent": "Python-urllib-CVE-Sync"}
    )

    print(f"Requesting recent updates from: {url}")

    try:
        with urllib.request.urlopen(req) as response:
            advisories = json.loads(response.read().decode("utf-8"))
    except Exception as e:
        print(f"Failed to fetch data from GitHub API: {e}")
        return

    cve_year_pattern = re.compile(r"CVE-(\d{4})-\d+", re.IGNORECASE)
    files_written = 0

    for advisory in advisories:
        if "id" not in advisory or not advisory["id"].startswith("GHSA"):
            continue

        # Extract all valid CVE markers
        cve_aliases = []
        if "aliases" in advisory and isinstance(advisory["aliases"], list):
            for alias in advisory["aliases"]:
                if alias.upper().startswith("CVE-"):
                    cve_aliases.append(alias.upper())

        # Rule 1: If there are no CVE identifiers, completely skip it
        if not cve_aliases:
            continue

        # Rule 2: Iterate across items featuring multi-CVE combinations individually
        for cve_id in cve_aliases:
            match = cve_year_pattern.search(cve_id)
            year = match.group(1) if match else "Unknown_Year"

            target_folder = year
            target_folder.mkdir(parents=True, exist_ok=True)

            target_file_path = target_folder / f"{cve_id.upper()}.json"

            with open(target_file_path, "w", encoding="utf-8") as out_f:
                json.dump(advisory, out_f, indent=2, ensure_ascii=False)

            files_written += 1

    print(f"Done! Created/Updated {files_written} CVE definition files.")


if __name__ == "__main__":
    fetch_and_sync_advisories()
