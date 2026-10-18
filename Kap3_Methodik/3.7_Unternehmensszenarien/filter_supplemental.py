# Filtert CVEs mit befüllten Supplemental Metrics (v4.0) heraus.
# Zeigt welche Supplemental-Metriken gesetzt sind, den v3.1- und v4.0-Score,
# und ob ein Dreiervergleich (v3.1 → v4.0-Base → v4.0+Supplemental) möglich ist.
#
# Durchsucht die gesamte Datenbasis (cves_2025.csv), nicht nur Gruppe A.
#
# Nutzung:
#     python filter_supplemental.py [--in cves_2025.csv] [--out supplemental_cves.json]

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import parse_vector, ergebnis_huelle  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / ".." / "cves_2025.csv"
DEFAULT_OUT = SCRIPT_DIR / "supplemental_cves.json"
DEFAULT_CSV_OUT = SCRIPT_DIR / "supplemental_cves.csv"

V40_SUPPLEMENTAL = {
    "S": "Safety",
    "AU": "Automatable",
    "R": "Recovery",
    "V": "Value Density",
    "RE": "Vulnerability Response Effort",
    "U": "Provider Urgency",
}


def ist_befuellt(vektor: dict, metrik: str) -> bool:
    wert = vektor.get(metrik)
    return wert is not None and wert != "X"


def main():
    parser = argparse.ArgumentParser(
        description="Filtert CVEs mit befüllten Supplemental Metrics und analysiert deren Verteilung"
    )
    parser.add_argument("--in", dest="in_path", default=DEFAULT_IN, help="Eingabe-CSV (gesamter Datensatz)")
    parser.add_argument("--out", default=DEFAULT_OUT, help="Ausgabe-JSON")
    parser.add_argument("--csv-out", default=DEFAULT_CSV_OUT, help="Ausgabe-CSV mit gefilterten CVEs")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8")

    pfad = Path(args.in_path)
    with pfad.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        alle_zeilen = list(reader)

    print(f"Eingelesen: {pfad} ({len(alle_zeilen)} Zeilen)")

    # Filtern: CVEs mit mindestens einer befüllten Supplemental Metric
    treffer = []
    metrik_zaehler = Counter()
    wert_zaehler = {m: Counter() for m in V40_SUPPLEMENTAL}

    for z in alle_zeilen:
        v40_vektor_str = z.get("cvss_v40_vector", "")
        if not v40_vektor_str:
            continue

        v40 = parse_vector(v40_vektor_str)
        befuellte = {}
        for kuerzel, name in V40_SUPPLEMENTAL.items():
            if ist_befuellt(v40, kuerzel):
                befuellte[kuerzel] = v40[kuerzel]
                metrik_zaehler[kuerzel] += 1
                wert_zaehler[kuerzel][v40[kuerzel]] += 1

        if befuellte:
            treffer.append({
                "cve_id": z.get("cve_id", ""),
                "hat_v31": bool(z.get("cvss_v31_vector", "")),
                "hat_v40": True,
                "v31_score": z.get("cvss_v31_base_score", ""),
                "v31_severity": z.get("cvss_v31_base_severity", ""),
                "v40_score": z.get("cvss_v40_base_score", ""),
                "v40_severity": z.get("cvss_v40_base_severity", ""),
                "supplemental_befuellt": befuellte,
                "anzahl_supplemental": len(befuellte),
            })

    # Statistiken
    n_treffer = len(treffer)
    n_mit_v31 = sum(1 for t in treffer if t["hat_v31"])
    n_ohne_v31 = n_treffer - n_mit_v31

    print(f"\n{'=' * 60}")
    print(f"CVEs mit mindestens einer Supplemental Metric: {n_treffer}")
    print(f"  davon mit v3.1-Score (Dreiervergleich möglich): {n_mit_v31}")
    print(f"  davon ohne v3.1-Score: {n_ohne_v31}")
    print(f"{'=' * 60}")

    print(f"\n--- Häufigkeit je Supplemental Metrik ---")
    for kuerzel, name in V40_SUPPLEMENTAL.items():
        n = metrik_zaehler.get(kuerzel, 0)
        print(f"  {kuerzel:<4} ({name:<30})  {n:>6} CVEs")
        if n > 0:
            for wert, anzahl in wert_zaehler[kuerzel].most_common():
                print(f"       {wert:<20} {anzahl:>6}  ({anzahl/n*100:5.1f}%)")

    print(f"\n--- Anzahl befüllter Supplemental Metrics pro CVE ---")
    anzahl_verteilung = Counter(t["anzahl_supplemental"] for t in treffer)
    for anz in sorted(anzahl_verteilung):
        print(f"  {anz} Metrik(en): {anzahl_verteilung[anz]} CVEs")

    # Severity-Verteilung der Treffer
    if n_mit_v31 > 0:
        print(f"\n--- Severity-Verteilung (nur CVEs mit v3.1 + v4.0 + Supplemental) ---")
        sev_v31 = Counter()
        sev_v40 = Counter()
        for t in treffer:
            if t["hat_v31"]:
                sev_v31[t["v31_severity"]] += 1
                sev_v40[t["v40_severity"]] += 1
        print(f"  v3.1: {dict(sev_v31.most_common())}")
        print(f"  v4.0: {dict(sev_v40.most_common())}")

    # JSON speichern
    ergebnis = {
        "n_gesamt": len(alle_zeilen),
        "n_mit_supplemental": n_treffer,
        "n_mit_v31_und_supplemental": n_mit_v31,
        "n_ohne_v31": n_ohne_v31,
        "metrik_haeufigkeit": {
            k: {"n": metrik_zaehler.get(k, 0), "werte": dict(wert_zaehler[k].most_common())}
            for k in V40_SUPPLEMENTAL
        },
        "anzahl_pro_cve": dict(sorted(anzahl_verteilung.items())),
        "cves": treffer,
    }

    ausgabe = ergebnis_huelle("filter_supplemental.py", pfad, len(alle_zeilen), ergebnis)

    out_pfad = Path(args.out)
    with out_pfad.open("w", encoding="utf-8") as f:
        json.dump(ausgabe, f, ensure_ascii=False, indent=2)
    print(f"\nJSON gespeichert: {out_pfad}")

    # CSV speichern (für leichtere Weiterverarbeitung)
    csv_pfad = Path(args.csv_out)
    csv_felder = [
        "cve_id", "hat_v31", "v31_score", "v31_severity",
        "v40_score", "v40_severity", "anzahl_supplemental",
        "S", "AU", "R", "V", "RE", "U",
    ]
    with csv_pfad.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_felder)
        writer.writeheader()
        for t in treffer:
            row = {
                "cve_id": t["cve_id"],
                "hat_v31": t["hat_v31"],
                "v31_score": t["v31_score"],
                "v31_severity": t["v31_severity"],
                "v40_score": t["v40_score"],
                "v40_severity": t["v40_severity"],
                "anzahl_supplemental": t["anzahl_supplemental"],
            }
            for k in V40_SUPPLEMENTAL:
                row[k] = t["supplemental_befuellt"].get(k, "")
            writer.writerow(row)
    print(f"CSV gespeichert: {csv_pfad}")


if __name__ == "__main__":
    main()
