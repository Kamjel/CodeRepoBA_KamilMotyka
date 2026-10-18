# Teilt eine CSV-Datei zufällig in 70% (Kalibrierung) und 30% (Validierung) auf.
# Reproduzierbar durch festen Zufalls-Seed.
#
# Nutzung:
#     python split_random_70_30.py [--in cves_2025_group_A.csv] [--out-70 cves_group_A70.csv] [--out-30 cves_group_A30.csv] [--seed 42]

import argparse
import csv
import random
from pathlib import Path

DEFAULT_IN = "cves_2025_group_A.csv"
DEFAULT_OUT_70 = "cves_group_A70.csv"
DEFAULT_OUT_30 = "cves_group_A30.csv"
DEFAULT_SEED = 40 


def main():
    parser = argparse.ArgumentParser(description="CSV zufällig in 70%/30% aufteilen")
    parser.add_argument("--in", dest="in_path", default=DEFAULT_IN, help="Eingabe-CSV")
    parser.add_argument("--out-70", default=DEFAULT_OUT_70, help="Ausgabe-CSV für den 70%-Anteil")
    parser.add_argument("--out-30", default=DEFAULT_OUT_30, help="Ausgabe-CSV für den 30%-Anteil")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Zufalls-Seed für Reproduzierbarkeit")
    args = parser.parse_args()

    in_path = Path(args.in_path)

    with in_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    rng = random.Random(args.seed)
    shuffled = rows.copy()
    rng.shuffle(shuffled)

    split_index = round(len(shuffled) * 0.7)
    rows_70 = shuffled[:split_index]
    rows_30 = shuffled[split_index:]

    with open(args.out_70, "w", newline="", encoding="utf-8") as f70:
        writer_70 = csv.DictWriter(f70, fieldnames=fieldnames)
        writer_70.writeheader()
        writer_70.writerows(rows_70)

    with open(args.out_30, "w", newline="", encoding="utf-8") as f30:
        writer_30 = csv.DictWriter(f30, fieldnames=fieldnames)
        writer_30.writeheader()
        writer_30.writerows(rows_30)

    print(f"Gesamt: {len(rows)} CVEs aus {in_path}")
    print(f"70%-Anteil: {len(rows_70)} CVEs -> {args.out_70}")
    print(f"30%-Anteil: {len(rows_30)} CVEs -> {args.out_30}")
    print(f"Seed: {args.seed}")


if __name__ == "__main__":
    main()
