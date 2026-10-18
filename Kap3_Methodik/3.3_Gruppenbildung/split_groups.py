# Teilt cves_2025.csv in Gruppe A (v3.1 + v4.0 vorhanden) und Gruppe B (nur v3.1).
# CVEs ohne v3.1-Score werden übersprungen.
#
# Nutzung:
#     python split_groups.py [--in cves_2025.csv] [--out-a cves_2025_group_A.csv] [--out-b cves_2025_group_B.csv]

import argparse
import csv
from pathlib import Path

DEFAULT_IN = "cves_2025.csv"
DEFAULT_OUT_A = "cves_2025_group_A.csv"
DEFAULT_OUT_B = "cves_2025_group_B.csv"


def main():
    parser = argparse.ArgumentParser(description="CVEs 2025 in Gruppe A (v3.1+v4.0) und Gruppe B (nur v3.1) aufteilen")
    parser.add_argument("--in", dest="in_path", default=DEFAULT_IN, help="Eingabe-CSV")
    parser.add_argument("--out-a", default=DEFAULT_OUT_A, help="Ausgabe-CSV für Gruppe A")
    parser.add_argument("--out-b", default=DEFAULT_OUT_B, help="Ausgabe-CSV für Gruppe B")
    args = parser.parse_args()

    in_path = Path(args.in_path)

    with in_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

        with open(args.out_a, "w", newline="", encoding="utf-8") as fa, \
             open(args.out_b, "w", newline="", encoding="utf-8") as fb:
            writer_a = csv.DictWriter(fa, fieldnames=fieldnames)
            writer_b = csv.DictWriter(fb, fieldnames=fieldnames)
            writer_a.writeheader()
            writer_b.writeheader()

            count_a = 0
            count_b = 0
            count_skipped = 0

            for row in reader:
                has_v31 = bool(row.get("cvss_v31_base_score"))
                has_v40 = bool(row.get("cvss_v40_base_score"))

                if has_v31 and has_v40:
                    writer_a.writerow(row)
                    count_a += 1
                elif has_v31 and not has_v40:
                    writer_b.writerow(row)
                    count_b += 1
                else:
                    count_skipped += 1

    print(f"Gruppe A (v3.1 + v4.0): {count_a} CVEs -> {args.out_a}")
    print(f"Gruppe B (nur v3.1): {count_b} CVEs -> {args.out_b}")
    print(f"Übersprungen (ohne v3.1): {count_skipped} CVEs")


if __name__ == "__main__":
    main()
