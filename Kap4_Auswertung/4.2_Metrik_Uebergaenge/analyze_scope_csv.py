# Scope-Mapping v3.1 -> v4.0: Impact-Übergangsmatrizen als CSV.
# v3.1: S:U/C mit C/I/A -> v4.0: VC/VI/VA (vulnerable) + SC/SI/SA (subsequent).
#
# Nutzung: python analyze_scope_csv.py [--in cves_group_A70.csv]

import argparse, csv, sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import lade_gruppe_a, parse_vector

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / ".." / "Verteilung_GroupA" / "cves_group_A70.csv"
IMPACT = ["N", "L", "H"]
PAARE = {"C": ("VC", "SC"), "I": ("VI", "SI"), "A": ("VA", "SA")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    zeilen = lade_gruppe_a(Path(args.inp))
    gruppen: dict[str, list[dict]] = {"U": [], "C": []}
    for z in zeilen:
        s = parse_vector(z["cvss_v31_vector"]).get("S", "?")
        if s in gruppen:
            gruppen[s].append(z)

    out = SCRIPT_DIR / "scope_uebergaenge.csv"
    with out.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["scope_v31", "v31_metrik", "v40_metrik", "uebergang", "n_v31", "n_v40", "anteil_%"])

        for scope, gruppe in gruppen.items():
            for v31_m, (v40_vs, v40_ss) in PAARE.items():
                for v40_m in (v40_vs, v40_ss):
                    je_src: dict[str, list[str]] = {w: [] for w in IMPACT}
                    for z in gruppe:
                        src = parse_vector(z["cvss_v31_vector"]).get(v31_m, "?")
                        dst = parse_vector(z["cvss_v40_vector"]).get(v40_m, "?")
                        if src in je_src:
                            je_src[src].append(dst)

                    for src in IMPACT:
                        n_src = len(je_src[src])
                        if not n_src:
                            continue
                        treffer = Counter(je_src[src])
                        for dst in IMPACT:
                            n_dst = treffer.get(dst, 0)
                            wr.writerow([scope, v31_m, v40_m, f"{src}->{dst}",
                                         n_src, n_dst, round(n_dst / n_src * 100, 2)])

    print(f"Gespeichert: {out}")


if __name__ == "__main__":
    main()
