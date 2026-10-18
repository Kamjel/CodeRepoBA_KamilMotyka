# Erzeugt zwei CSVs zur Auswertung des Mappings auf Gruppe B:
#   1) gruppe_b_lagemasse.csv  -- Deskriptive Lagemaße v3.1 vs. approx v4.0
#   2) gruppe_b_severity.csv   -- Severity-Kreuztabelle v3.1 vs. approx v4.0
#
# Nutzung: python gruppe_b_auswertung_csv.py [--in cves_mapped.csv]

import argparse, csv, math, sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / "cves_mapped.csv"
SEVERITY = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def median(werte):
    s = sorted(werte)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2


def stddev(werte, mittel):
    return math.sqrt(sum((x - mittel) ** 2 for x in werte) / len(werte))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    with Path(args.inp).open(encoding="utf-8", newline="") as f:
        zeilen = list(csv.DictReader(f))

    scores_v31, scores_v40, sev_v31, sev_v40 = [], [], [], []

    for z in zeilen:
        try:
            s31 = float(z["cvss_v31_base_score"])
            s40 = float(z["approx_v40_base_score"])
        except (ValueError, KeyError):
            continue
        scores_v31.append(s31)
        scores_v40.append(s40)
        sev_v31.append(z.get("cvss_v31_base_severity", "").upper())
        sev_v40.append(z.get("approx_v40_base_severity", "").upper())

    n = len(scores_v31)

    # --- CSV 1: Lagemaße ---
    mittel_31 = sum(scores_v31) / n
    mittel_40 = sum(scores_v40) / n
    lagemasse = [
        ("n", n, n),
        ("Mittelwert", round(mittel_31, 2), round(mittel_40, 2)),
        ("Median", round(median(scores_v31), 2), round(median(scores_v40), 2)),
        ("Standardabweichung", round(stddev(scores_v31, mittel_31), 2),
         round(stddev(scores_v40, mittel_40), 2)),
        ("Minimum", min(scores_v31), min(scores_v40)),
        ("Maximum", max(scores_v31), max(scores_v40)),
    ]

    out1 = SCRIPT_DIR / "gruppe_b_lagemasse.csv"
    with out1.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["Kennzahl", "v3.1", "approx_v4.0"])
        for row in lagemasse:
            wr.writerow(row)

    # --- CSV 2: Severity-Kreuztabelle ---
    kreuz = {e: {a: 0 for a in SEVERITY} for e in SEVERITY}
    for s31, s40 in zip(sev_v31, sev_v40):
        if s31 in kreuz and s40 in kreuz[s31]:
            kreuz[s31][s40] += 1

    out2 = SCRIPT_DIR / "gruppe_b_severity.csv"
    with out2.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["v3.1\\approx_v4.0"] + SEVERITY)
        for e in SEVERITY:
            wr.writerow([e] + [kreuz[e][a] for a in SEVERITY])

    print(f"Gespeichert: {out1}")
    print(f"Gespeichert: {out2}")


if __name__ == "__main__":
    main()
