# Validierung des Mapping-Verfahrens (A_30) als CSV.
# Erzeugt zwei CSVs:
#   1) validierung_metriken.csv  -- Übereinstimmung pro Metrik + Kennzahlen
#   2) validierung_konfusion.csv -- Konfusionsmatrix (Severity)
#
# Nutzung: python mapping_validierung_csv.py [--in cves_group_A30.csv]

import argparse, csv, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import parse_vector, lade_gruppe_a
from mapping import mappe_v31_auf_v40, baue_v40_vektor, berechne_score, severity_aus_score

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / "Verteilung_GroupA" / "cves_group_A30.csv"
SEVERITY = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
METRIKEN = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    zeilen = lade_gruppe_a(Path(args.inp))

    metrik_treffer = {m: {"korrekt": 0, "falsch": 0} for m in METRIKEN}
    konfusion = {e: {a: 0 for a in SEVERITY} for e in SEVERITY}
    deltas = []

    for z in zeilen:
        v31_str, v40_str = z.get("cvss_v31_vector", ""), z.get("cvss_v40_vector", "")
        if not v31_str or not v40_str:
            continue
        v31 = parse_vector(v31_str)
        v40_echt = parse_vector(v40_str)
        v40_approx = mappe_v31_auf_v40(v31)

        try:
            score_approx, _ = berechne_score(baue_v40_vektor(v40_approx))
            score_echt = float(z["cvss_v40_base_score"])
        except Exception:
            continue

        sev_echt = z.get("cvss_v40_base_severity", "").upper() or severity_aus_score(score_echt)
        sev_approx = severity_aus_score(score_approx)

        deltas.append(round(score_approx - score_echt, 2))
        if sev_echt in konfusion and sev_approx in konfusion[sev_echt]:
            konfusion[sev_echt][sev_approx] += 1

        for m in METRIKEN:
            if v40_echt.get(m, "?") == v40_approx.get(m, "?"):
                metrik_treffer[m]["korrekt"] += 1
            else:
                metrik_treffer[m]["falsch"] += 1

    n = len(deltas)
    mae = round(sum(abs(d) for d in deltas) / n, 4) if n else 0
    sev_korrekt = sum(konfusion[e][e] for e in SEVERITY)

    # CSV 1: Metrik-Übereinstimmung + Kennzahlen
    out1 = SCRIPT_DIR / "validierung_metriken.csv"
    with out1.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["metrik", "korrekt", "falsch", "uebereinstimmung_%"])
        for m in METRIKEN:
            k, fa = metrik_treffer[m]["korrekt"], metrik_treffer[m]["falsch"]
            g = k + fa
            wr.writerow([m, k, fa, round(k / g * 100, 2) if g else 0])
        wr.writerow([])
        wr.writerow(["kennzahl", "wert"])
        wr.writerow(["n", n])
        wr.writerow(["MAE", mae])
        wr.writerow(["severity_uebereinstimmung_%", round(sev_korrekt / n * 100, 2) if n else 0])

    # CSV 2: Konfusionsmatrix
    out2 = SCRIPT_DIR / "validierung_konfusion.csv"
    with out2.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["echt\\approx"] + SEVERITY)
        for e in SEVERITY:
            wr.writerow([e] + [konfusion[e][a] for a in SEVERITY])

    print(f"Gespeichert: {out1}")
    print(f"Gespeichert: {out2}")


if __name__ == "__main__":
    main()
