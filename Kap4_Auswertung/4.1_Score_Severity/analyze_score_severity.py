# Vergleichende Score- und Severity-Analyse (Kapitel 3.3 / 4).
#
# Nutzung:
#     python analyze_score_severity.py [--in cves_2025_group_A.csv]
#
# Ausgaben (CSV):
#     score_deskriptiv.csv        – Lage-/Streuungsmaße beider Versionen
#     score_differenzen.csv       – Δ-Score pro CVE (v4.0 − v3.1)
#     severity_uebergang.csv      – Kreuztabelle v3.1 × v4.0 Severity
#     score_statistik.csv         – Wilcoxon-Test + Cliff's Delta

import argparse
import csv
import math
import sys
from collections import Counter
from pathlib import Path

from scipy.stats import wilcoxon

sys.path.insert(0, str(Path(__file__).resolve().parent / "Mapping"))
from common import lade_gruppe_a

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / "cves_2025_group_A.csv"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ---------------------------------------------------------------------------
# Teil 1: Deskriptive Score-Analyse
# Berechnet Lagemaße (Min, Q1, Median, Mittelwert, Q3, Max) und
# Streuungsmaß (Standardabweichung) für eine Liste von Scores.
# ---------------------------------------------------------------------------
def deskriptiv(werte: list[float]) -> dict:
    n = len(werte)
    sortiert = sorted(werte)
    mittel = sum(sortiert) / n
    median = sortiert[n // 2] if n % 2 else (sortiert[n // 2 - 1] + sortiert[n // 2]) / 2
    varianz = sum((x - mittel) ** 2 for x in sortiert) / (n - 1)
    stddev = math.sqrt(varianz)
    q1 = sortiert[n // 4]
    q3 = sortiert[3 * n // 4]
    return {
        "n": n,
        "min": sortiert[0],
        "q1": round(q1, 1),
        "median": round(median, 1),
        "mittelwert": round(mittel, 2),
        "q3": round(q3, 1),
        "max": sortiert[-1],
        "stddev": round(stddev, 2),
    }


# ---------------------------------------------------------------------------
# Teil 4b: Cliff's Delta – nicht-parametrische Effektstärke
# Quantifiziert die Dominanz einer Verteilung über die andere.
# Schwellenwerte nach Romano et al. (2006).
# ---------------------------------------------------------------------------
def cliffs_delta(v31: list[float], v40: list[float]) -> dict:
    n1, n2 = len(v31), len(v40)
    mehr = 0
    weniger = 0
    for a in v31:
        for b in v40:
            if b > a:
                mehr += 1
            elif b < a:
                weniger += 1
    delta = (mehr - weniger) / (n1 * n2)

    if abs(delta) < 0.147:
        interpretation = "vernachlässigbar"
    elif abs(delta) < 0.33:
        interpretation = "klein"
    elif abs(delta) < 0.474:
        interpretation = "mittel"
    else:
        interpretation = "groß"

    return {
        "cliffs_delta": round(delta, 4),
        "interpretation": interpretation,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=DEFAULT_IN)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    zeilen = lade_gruppe_a(Path(args.inp))
    print(f"Geladene CVEs: {len(zeilen)}")

    scores_v31 = [float(z["cvss_v31_base_score"]) for z in zeilen]
    scores_v40 = [float(z["cvss_v40_base_score"]) for z in zeilen]
    differenzen = [v40 - v31 for v31, v40 in zip(scores_v31, scores_v40)]

    # -------------------------------------------------------------------
    # Teil 1: Deskriptive Score-Analyse
    # Lage- und Streuungsmaße für v3.1 und v4.0 getrennt berechnen.
    # -------------------------------------------------------------------
    desk_v31 = deskriptiv(scores_v31)
    desk_v40 = deskriptiv(scores_v40)
    out1 = SCRIPT_DIR / "score_deskriptiv.csv"
    with out1.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["version", "n", "min", "q1", "median", "mittelwert", "q3", "max", "stddev"])
        wr.writerow(["CVSS v3.1", desk_v31["n"], desk_v31["min"], desk_v31["q1"],
                      desk_v31["median"], desk_v31["mittelwert"], desk_v31["q3"],
                      desk_v31["max"], desk_v31["stddev"]])
        wr.writerow(["CVSS v4.0", desk_v40["n"], desk_v40["min"], desk_v40["q1"],
                      desk_v40["median"], desk_v40["mittelwert"], desk_v40["q3"],
                      desk_v40["max"], desk_v40["stddev"]])
    print(f"Gespeichert: {out1}")

    # -------------------------------------------------------------------
    # Teil 2: Paarweise Score-Differenz
    # Δ = v4.0 − v3.1 pro CVE. Positive Werte = v4.0 bewertet höher.
    # -------------------------------------------------------------------
    out2 = SCRIPT_DIR / "score_differenzen.csv"
    with out2.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["cve_id", "score_v31", "score_v40", "delta"])
        for z, d in zip(zeilen, differenzen):
            wr.writerow([z["cve_id"], z["cvss_v31_base_score"],
                         z["cvss_v40_base_score"], round(d, 1)])
    print(f"Gespeichert: {out2}")

    desk_diff = deskriptiv(differenzen)
    n_pos = sum(1 for d in differenzen if d > 0)
    n_neg = sum(1 for d in differenzen if d < 0)
    n_gleich = sum(1 for d in differenzen if d == 0)
    print(f"\nScore-Differenz (v4.0 − v3.1):")
    print(f"  Median: {desk_diff['median']}, Mittelwert: {desk_diff['mittelwert']}, Std: {desk_diff['stddev']}")
    print(f"  Höher in v4.0: {n_pos} ({n_pos/len(differenzen)*100:.1f}%)")
    print(f"  Niedriger in v4.0: {n_neg} ({n_neg/len(differenzen)*100:.1f}%)")
    print(f"  Gleich: {n_gleich} ({n_gleich/len(differenzen)*100:.1f}%)")

    # -------------------------------------------------------------------
    # Teil 3: Severity-Übergangsmatrix
    # Kreuztabelle v3.1-Severity × v4.0-Severity (4×4).
    # Diagonale = unverändert, oberhalb = Hochstufung, unterhalb = Herabstufung.
    # -------------------------------------------------------------------
    out3 = SCRIPT_DIR / "severity_uebergang.csv"
    uebergaenge = Counter()
    for z in zeilen:
        sev31 = z.get("cvss_v31_base_severity", "").strip().upper()
        sev40 = z.get("cvss_v40_base_severity", "").strip().upper()
        if sev31 in SEVERITY_ORDER and sev40 in SEVERITY_ORDER:
            uebergaenge[(sev31, sev40)] += 1

    with out3.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["v31_severity"] + SEVERITY_ORDER + ["summe"])
        for sev31 in SEVERITY_ORDER:
            werte = [uebergaenge.get((sev31, sev40), 0) for sev40 in SEVERITY_ORDER]
            wr.writerow([sev31] + werte + [sum(werte)])
    print(f"Gespeichert: {out3}")

    n_upgrade = sum(v for (s31, s40), v in uebergaenge.items()
                    if SEVERITY_ORDER.index(s40) < SEVERITY_ORDER.index(s31))
    n_downgrade = sum(v for (s31, s40), v in uebergaenge.items()
                      if SEVERITY_ORDER.index(s40) > SEVERITY_ORDER.index(s31))
    n_gleich_sev = sum(v for (s31, s40), v in uebergaenge.items() if s31 == s40)
    gesamt_sev = sum(uebergaenge.values())
    print(f"\nSeverity-Übergänge:")
    print(f"  Hochgestuft (v4.0 höher): {n_upgrade} ({n_upgrade/gesamt_sev*100:.1f}%)")
    print(f"  Herabgestuft (v4.0 niedriger): {n_downgrade} ({n_downgrade/gesamt_sev*100:.1f}%)")
    print(f"  Gleich geblieben: {n_gleich_sev} ({n_gleich_sev/gesamt_sev*100:.1f}%)")

    # -------------------------------------------------------------------
    # Teil 4a: Wilcoxon-Vorzeichen-Rang-Test (scipy.stats.wilcoxon)
    # Zweiseitiger Test bei α = 0,05. Nulldifferenzen werden von scipy
    # automatisch ausgeschlossen, Rangbindungen über mittlere Ränge behandelt.
    # -------------------------------------------------------------------
    stat, p_value = wilcoxon(scores_v31, scores_v40, alternative="two-sided")
    n_nulldiff = sum(1 for d in differenzen if d == 0)
    n_eff = len(differenzen) - n_nulldiff
    richtung = "v4.0 < v3.1" if sum(differenzen) < 0 else "v4.0 > v3.1"

    # -------------------------------------------------------------------
    # Teil 4b: Cliff's Delta – nicht-parametrische Effektstärke
    # Schwellenwerte: <0.147 vernachlässigbar, <0.33 klein,
    # <0.474 mittel, >=0.474 groß (Romano et al., 2006).
    # -------------------------------------------------------------------
    cliff = cliffs_delta(scores_v31, scores_v40)

    out4 = SCRIPT_DIR / "score_statistik.csv"
    with out4.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["test", "kennzahl", "wert"])
        wr.writerow(["Wilcoxon", "n_paare", len(differenzen)])
        wr.writerow(["Wilcoxon", "n_nulldifferenzen_ausgeschlossen", n_nulldiff])
        wr.writerow(["Wilcoxon", "n_effektiv", n_eff])
        wr.writerow(["Wilcoxon", "teststatistik_W", stat])
        wr.writerow(["Wilcoxon", "p_wert", p_value])
        wr.writerow(["Wilcoxon", "alpha", 0.05])
        wr.writerow(["Wilcoxon", "signifikant", "ja" if p_value < 0.05 else "nein"])
        wr.writerow(["Wilcoxon", "testrichtung", "zweiseitig"])
        wr.writerow(["Wilcoxon", "richtung_effekt", richtung])
        wr.writerow(["Cliff's Delta", "delta", cliff["cliffs_delta"]])
        wr.writerow(["Cliff's Delta", "interpretation", cliff["interpretation"]])
    print(f"Gespeichert: {out4}")

    print(f"\nWilcoxon-Vorzeichen-Rang-Test (scipy {__import__('scipy').__version__}):")
    print(f"  n Paare: {len(differenzen)}, davon {n_nulldiff} Nulldifferenzen ausgeschlossen")
    print(f"  W = {stat:.1f}, p = {p_value:.2e}, α = 0.05, zweiseitig")
    print(f"  Ergebnis: {'Signifikant' if p_value < 0.05 else 'Nicht signifikant'} ({richtung})")
    print(f"\nCliff's Delta: {cliff['cliffs_delta']} ({cliff['interpretation']})")


if __name__ == "__main__":
    main()
