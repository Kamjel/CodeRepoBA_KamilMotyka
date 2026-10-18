# AT-Analyse (v4.0): Severity- und Metrik-Verteilung je AT-Gruppe als CSV.
# AT ist neu in v4.0 (N/P), daher kein 1:1-Übergang aus v3.1.
# Erzeugt at_uebergaenge.csv mit Severity- und Vektor-Verteilung je AT-Wert.
#
# Nutzung: python analyze_at_csv.py [--in cves_group_A70.csv]

import argparse, csv, sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import lade_gruppe_a, parse_vector

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / ".." / "Verteilung_GroupA" / "cves_group_A70.csv"
V31_METRIKEN = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
V40_METRIKEN = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    zeilen = lade_gruppe_a(Path(args.inp))
    gruppen: dict[str, list[dict]] = {"N": [], "P": []}
    for z in zeilen:
        w = parse_vector(z["cvss_v40_vector"]).get("AT", "?")
        if w in gruppen:
            gruppen[w].append(z)

    out = SCRIPT_DIR / "at_uebergaenge.csv"
    with out.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["at_wert", "version", "metrik", "wert", "n_at", "n_wert", "anteil_%"])

        for at_val, gruppe in gruppen.items():
            n_at = len(gruppe)
            for sev_feld, ver in [("cvss_v31_base_severity", "v31"), ("cvss_v40_base_severity", "v40")]:
                treffer = Counter(z.get(sev_feld, "?") for z in gruppe)
                for wert, anzahl in treffer.most_common():
                    wr.writerow([at_val, ver, "severity", wert, n_at, anzahl, round(anzahl / n_at * 100, 2)])

            for metrik in V31_METRIKEN:
                treffer = Counter(parse_vector(z["cvss_v31_vector"]).get(metrik, "?") for z in gruppe)
                for wert, anzahl in treffer.most_common():
                    wr.writerow([at_val, "v31", metrik, wert, n_at, anzahl, round(anzahl / n_at * 100, 2)])

            for metrik in V40_METRIKEN:
                treffer = Counter(parse_vector(z["cvss_v40_vector"]).get(metrik, "?") for z in gruppe)
                for wert, anzahl in treffer.most_common():
                    wr.writerow([at_val, "v40", metrik, wert, n_at, anzahl, round(anzahl / n_at * 100, 2)])

    print(f"Gespeichert: {out}")


if __name__ == "__main__":
    main()
