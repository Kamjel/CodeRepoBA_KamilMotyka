# AC-Mapping v3.1 -> v4.0: Übergangsverteilung als CSV.
# Nutzung: python analyze_ac_csv.py [--in cves_group_A70.csv]

import argparse, csv, sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import lade_gruppe_a, parse_vector

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / ".." / "Verteilung_GroupA" / "cves_group_A70.csv"
AC = ["L", "H"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    zeilen = lade_gruppe_a(Path(args.inp))
    gruppen: dict[str, list[dict]] = {w: [] for w in AC}
    for z in zeilen:
        w = parse_vector(z["cvss_v31_vector"]).get("AC", "?")
        if w in gruppen:
            gruppen[w].append(z)

    out = SCRIPT_DIR / "ac_uebergaenge.csv"
    with out.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["uebergang", "n_v31", "n_v40", "anteil_%"])
        for src in AC:
            n_src = len(gruppen[src])
            if not n_src:
                continue
            treffer = Counter(parse_vector(z["cvss_v40_vector"]).get("AC", "?") for z in gruppen[src])
            for dst in AC:
                n_dst = treffer.get(dst, 0)
                wr.writerow([f"{src}->{dst}", n_src, n_dst, round(n_dst / n_src * 100, 2)])

    print(f"Gespeichert: {out}")


if __name__ == "__main__":
    main()
