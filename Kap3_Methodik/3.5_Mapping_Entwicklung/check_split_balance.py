# Vergleicht die Severity-Verteilung der 70%- und 30%-Teilmenge nach dem Split,
# um zu prüfen, ob die Klassenverteilung vergleichbar geblieben ist.
#
# Nutzung:
#     python check_split_balance.py [--a70 cves_group_A70.csv] [--a30 cves_group_A30.csv] [--col cvss_v31_severity]
 
import argparse
import csv
from collections import Counter
from pathlib import Path
 
DEFAULT_A70 = "cves_group_A70.csv"
DEFAULT_A30 = "cves_group_A30.csv"
DEFAULT_COL = "cvss_v31_severity"  # ggf. an den tatsächlichen Spaltennamen anpassen
 
 
def verteilung(pfad: Path, spalte: str):
    with pfad.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if spalte not in (reader.fieldnames or []):
            raise SystemExit(
                f"Spalte '{spalte}' nicht in {pfad} gefunden. "
                f"Vorhandene Spalten: {reader.fieldnames}"
            )
        werte = [row[spalte] for row in reader]
 
    n = len(werte)
    counts = Counter(werte)
    anteile = {klasse: anzahl / n for klasse, anzahl in counts.items()}
    return n, counts, anteile
 
 
def main():
    parser = argparse.ArgumentParser(
        description="Vergleicht die Klassenverteilung zweier CSV-Teilmengen"
    )
    parser.add_argument("--a70", default=DEFAULT_A70, help="Pfad zur 70%-Datei")
    parser.add_argument("--a30", default=DEFAULT_A30, help="Pfad zur 30%-Datei")
    parser.add_argument("--col", default=DEFAULT_COL, help="Name der Severity-Spalte")
    args = parser.parse_args()
 
    n70, counts70, v70 = verteilung(Path(args.a70), args.col)
    n30, counts30, v30 = verteilung(Path(args.a30), args.col)
 
    alle_klassen = sorted(set(v70) | set(v30))
 
    print(f"Vergleich der Severity-Verteilung ({args.col})\n")
    print(f"{'Klasse':<10}{'A_70 (n)':>10}{'A_70 (%)':>10}{'A_30 (n)':>10}{'A_30 (%)':>10}{'Diff (pp)':>11}")
    print("-" * 61)
 
    max_diff = 0.0
    for klasse in alle_klassen:
        n_70 = counts70.get(klasse, 0)
        n_30 = counts30.get(klasse, 0)
        a_70 = v70.get(klasse, 0.0)
        a_30 = v30.get(klasse, 0.0)
        diff_pp = (a_30 - a_70) * 100
        max_diff = max(max_diff, abs(diff_pp))
        print(f"{klasse:<10}{n_70:>10}{a_70:>9.1%}{n_30:>10}{a_30:>9.1%}{diff_pp:>+10.1f}")
 
    print("-" * 61)
    print(f"{'Summe':<10}{n70:>10}{'':>10}{n30:>10}")
    print(f"\nGrößte Abweichung zwischen den Verteilungen: {max_diff:.1f} Prozentpunkte")
 
    if max_diff < 2.0:
        print("→ Verteilung ist vergleichbar. Schichtung war nicht notwendig.")
    else:
        print("→ Deutliche Abweichung. Geschichteten Split in Erwägung ziehen.")
 
 
if __name__ == "__main__":
    main()
 