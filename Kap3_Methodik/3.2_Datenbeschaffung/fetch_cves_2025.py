# Lädt alle CVEs eines Jahres über die NVD API 2.0 (paginiert, mit Rate-Limiting)
# und speichert CVE-ID, Beschreibung, CVSS v3.1/v4.0-Vektoren/-Scores und CWE-IDs als CSV.
#
# Nutzung:
#     python fetch_cves_2025.py [--out cves_2025.csv]

import argparse
import csv
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
WINDOW_DAYS = 120
YEAR = 2025

CSV_FIELDS = [
    "cve_id",
    "published",
    "last_modified",
    "description",
    "cwe_ids",
    "cvss_v31_vector",
    "cvss_v31_base_score",
    "cvss_v31_base_severity",
    "cvss_v40_vector",
    "cvss_v40_base_score",
    "cvss_v40_base_severity",
]


def load_api_key() -> str | None:
    key = os.environ.get("NVD_API_KEY")
    if key:
        return key

    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip() == "NVD_API_KEY":
                return v.strip()
    return None


def date_windows(year: int, window_days: int):
    start = datetime(year, 1, 1)
    year_end = datetime(year + 1, 1, 1)
    while start < year_end:
        end = min(start + timedelta(days=window_days), year_end)
        yield start, end - timedelta(microseconds=1)
        start = end


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def extract_cvss(metrics: dict, key: str):
    entries = metrics.get(key, [])
    if not entries:
        return None, None, None
    data = entries[0].get("cvssData", {})
    return data.get("vectorString"), data.get("baseScore"), data.get("baseSeverity")


def extract_cwe_ids(weaknesses: list) -> str:
    ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            value = desc.get("value")
            if value and value not in ids:
                ids.append(value)
    return ";".join(ids)


def flatten_text(text: str) -> str:
    return " ".join(text.split())


def extract_description(descriptions: list) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return flatten_text(d.get("value", ""))
    return flatten_text(descriptions[0].get("value", "")) if descriptions else ""


def is_rejected(cve: dict) -> bool:
    return cve.get("vulnStatus") == "Rejected"


def cve_to_row(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    v31_vector, v31_score, v31_sev = extract_cvss(metrics, "cvssMetricV31")
    v40_vector, v40_score, v40_sev = extract_cvss(metrics, "cvssMetricV40")

    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": extract_description(cve.get("descriptions", [])),
        "cwe_ids": extract_cwe_ids(cve.get("weaknesses", [])),
        "cvss_v31_vector": v31_vector,
        "cvss_v31_base_score": v31_score,
        "cvss_v31_base_severity": v31_sev,
        "cvss_v40_vector": v40_vector,
        "cvss_v40_base_score": v40_score,
        "cvss_v40_base_severity": v40_sev,
    }


def fetch_window(session: requests.Session, headers: dict, start: datetime, end: datetime, sleep_s: float):
    start_index = 0
    total_results = None

    while total_results is None or start_index < total_results:
        params = {
            "pubStartDate": iso(start),
            "pubEndDate": iso(end),
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }

        for attempt in range(5):
            resp = session.get(NVD_API_URL, params=params, headers=headers, timeout=30)
            if resp.status_code == 200:
                break
            if resp.status_code in (403, 429):
                wait = sleep_s * (attempt + 2)
                print(f"  Rate limited (HTTP {resp.status_code}), warte {wait:.1f}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            resp.raise_for_status()
        else:
            resp.raise_for_status()

        data = resp.json()
        total_results = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            yield item.get("cve", {})

        start_index += RESULTS_PER_PAGE
        time.sleep(sleep_s)


def main():
    parser = argparse.ArgumentParser(description="CVEs 2025 über NVD-API abrufen und als CSV speichern")
    parser.add_argument("--out", default="cves_2025.csv", help="Pfad der Ausgabe-CSV")
    parser.add_argument("--year", type=int, default=YEAR, help="Jahr der zu ladenden CVEs")
    parser.add_argument(
        "--delay",
        type=float,
        default=None,
        help="Wartezeit in Sekunden zwischen Requests (Default: 2.0s mit Key, 6.5s ohne Key)",
    )
    args = parser.parse_args()

    api_key = load_api_key()
    headers = {"apiKey": api_key} if api_key else {}
    if args.delay is not None:
        sleep_s = args.delay
    else:
        sleep_s = 2.0 if api_key else 6.5

    if not api_key:
        print("Warnung: kein NVD_API_KEY gefunden, nutze ungekeyed Rate Limit (langsam).", file=sys.stderr)

    out_path = Path(args.out)
    session = requests.Session()

    total_written = 0
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for win_start, win_end in date_windows(args.year, WINDOW_DAYS):
            print(f"Lade Zeitraum {win_start.date()} bis {win_end.date()}...")
            for cve in fetch_window(session, headers, win_start, win_end, sleep_s):
                if is_rejected(cve):
                    continue
                writer.writerow(cve_to_row(cve))
                total_written += 1
            print(f"  bisher {total_written} CVEs geschrieben")

    print(f"Fertig. {total_written} CVEs gespeichert in {out_path}")


if __name__ == "__main__":
    main()
