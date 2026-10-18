# Kontingenztabellen (AC:H -> AC/AT, UI:R -> UI, S:C -> Impact) als CSV.
# Nutzung: python build_contingency_tables_csv.py [--in cves_group_A70.csv]

import argparse, csv, sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Mapping"))
from common import lade_gruppe_a, parse_vector

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / "cves_group_A70.csv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    zeilen = lade_gruppe_a(Path(args.inp))

    # Tabelle 1: AC:H -> (AC, AT)
    out1 = SCRIPT_DIR / "kontingenz_ac_at.csv"
    with out1.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["v40_kombination", "n", "anteil_%"])
        treffer = Counter()
        for z in zeilen:
            if parse_vector(z["cvss_v31_vector"]).get("AC") != "H":
                continue
            v40 = parse_vector(z["cvss_v40_vector"])
            treffer[f"AC:{v40.get('AC','?')}/AT:{v40.get('AT','?')}"] += 1
        n = sum(treffer.values())
        for kombi, anzahl in treffer.most_common():
            wr.writerow([kombi, anzahl, round(anzahl / n * 100, 2) if n else 0])
    print(f"Gespeichert: {out1}")

    # Tabelle 2: UI:R -> UI
    out2 = SCRIPT_DIR / "kontingenz_ui.csv"
    with out2.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["v40_UI", "n", "anteil_%"])
        treffer = Counter()
        for z in zeilen:
            if parse_vector(z["cvss_v31_vector"]).get("UI") != "R":
                continue
            treffer[parse_vector(z["cvss_v40_vector"]).get("UI", "?")] += 1
        n = sum(treffer.values())
        for wert, anzahl in treffer.most_common():
            wr.writerow([wert, anzahl, round(anzahl / n * 100, 2) if n else 0])
    print(f"Gespeichert: {out2}")


if __name__ == "__main__":
    main()
