# Zählt CVEs mit befüllten Nicht-Base-Metriken als CSV.
# Nutzung: python analyze_extra_metrics_csv.py [--in cves_group_A70.csv]

import argparse, csv, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import lade_gruppe_a, parse_vector

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / ".." / "Verteilung_GroupA" / "cves_group_A70.csv"

V31_METRIKEN = ["E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]
V40_METRIKEN = ["E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
                "MVC", "MVI", "MVA", "MSC", "MSI", "MSA", "S", "AU", "R", "V", "RE", "U"]


def ist_befuellt(vektor: dict, metrik: str) -> bool:
    wert = vektor.get(metrik)
    return wert is not None and wert != "X"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    zeilen = lade_gruppe_a(Path(args.inp))
    n = len(zeilen)

    out = SCRIPT_DIR / "extra_metrics.csv"
    with out.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["version", "metrik", "n_gesamt", "n_befuellt", "anteil_%"])

        for metrik in V31_METRIKEN:
            cnt = sum(1 for z in zeilen if ist_befuellt(parse_vector(z["cvss_v31_vector"]), metrik))
            wr.writerow(["v31", metrik, n, cnt, round(cnt / n * 100, 2) if n else 0])

        for metrik in V40_METRIKEN:
            cnt = sum(1 for z in zeilen if ist_befuellt(parse_vector(z["cvss_v40_vector"]), metrik))
            wr.writerow(["v40", metrik, n, cnt, round(cnt / n * 100, 2) if n else 0])

    print(f"Gespeichert: {out}")


if __name__ == "__main__":
    main()
