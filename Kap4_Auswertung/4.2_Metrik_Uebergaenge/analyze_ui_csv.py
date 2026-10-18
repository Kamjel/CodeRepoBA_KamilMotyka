# UI-Mapping v3.1 -> v4.0: Übergangsverteilung als CSV.
# Nutzung: python analyze_ui_csv.py [--in cves_group_A70.csv]

import argparse, csv, sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import lade_gruppe_a, parse_vector

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / ".." / "Verteilung_GroupA" / "cves_group_A70.csv"
V31, V40 = ["N", "R"], ["N", "P", "A"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    zeilen = lade_gruppe_a(Path(args.inp))
    gruppen: dict[str, list[dict]] = {w: [] for w in V31}
    for z in zeilen:
        w = parse_vector(z["cvss_v31_vector"]).get("UI", "?")
        if w in gruppen:
            gruppen[w].append(z)

    out = SCRIPT_DIR / "ui_uebergaenge.csv"
    with out.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["uebergang", "n_v31", "n_v40", "anteil_%"])
        for src in V31:
            n_src = len(gruppen[src])
            treffer = Counter(parse_vector(z["cvss_v40_vector"]).get("UI", "?") for z in gruppen[src])
            for dst in V40:
                n_dst = treffer.get(dst, 0)
                wr.writerow([f"{src}->{dst}", n_src, n_dst, round(n_dst / n_src * 100, 2) if n_src else 0])

    print(f"Gespeichert: {out}")


if __name__ == "__main__":
    main()
