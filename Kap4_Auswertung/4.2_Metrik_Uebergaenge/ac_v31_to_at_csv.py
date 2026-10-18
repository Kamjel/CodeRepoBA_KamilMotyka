# Kreuztabelle AC (v3.1) vs. AT (v4.0) als CSV.
# Nutzung: python ac_v31_to_at_csv.py [--in cves_group_A70.csv]

import argparse, csv, sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import lade_gruppe_a, parse_vector

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / ".." / "Verteilung_GroupA" / "cves_group_A70.csv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    zeilen = lade_gruppe_a(Path(args.inp))

    tabelle: dict[str, Counter] = {}
    for z in zeilen:
        ac = parse_vector(z["cvss_v31_vector"]).get("AC", "?")
        at = parse_vector(z["cvss_v40_vector"]).get("AT", "?")
        tabelle.setdefault(ac, Counter())[at] += 1

    out = SCRIPT_DIR / "ac_v31_to_at.csv"
    with out.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["AC_v31", "n", "AT_N", "at_n_anteil_%", "AT_P", "at_p_anteil_%"])
        for ac in sorted(tabelle):
            c = tabelle[ac]
            n = sum(c.values())
            at_n = c.get("N", 0)
            at_p = c.get("P", 0)
            wr.writerow([ac, n, at_n, round(at_n / n * 100, 2) if n else 0,
                         at_p, round(at_p / n * 100, 2) if n else 0])

    print(f"Gespeichert: {out}")


if __name__ == "__main__":
    main()
