# Findet CVE-Beispiele mit AC:L (v3.1) -> AC:H (v4.0).
# Dieser Wechsel ist unerwartet, da v4.0 die Umgebungsvoraussetzungen in die
# neue Metrik AT auslagert und AC nur die technische Komplexität abbildet.
#
# Nutzung:
#     python find_ac_l_to_h.py [--in cves_group_A70.csv] [--out ac_l_to_h_beispiele.csv] [--limit 10]

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import lade_gruppe_a, parse_vector  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / ".." / "Verteilung_GroupA" / "cves_group_A70.csv"
DEFAULT_OUT = SCRIPT_DIR / "ac_l_to_h_beispiele.csv"


def finde_ac_l_zu_h(zeilen: list[dict]) -> list[dict]:
    beispiele = []
    for z in zeilen:
        v31 = parse_vector(z["cvss_v31_vector"])
        v40 = parse_vector(z["cvss_v40_vector"])
        if v31.get("AC") != "L" or v40.get("AC") != "H":
            continue
        beispiele.append({
            "cve_id": z["cve_id"],
            "v31_vector": z["cvss_v31_vector"],
            "v31_base_score": z["cvss_v31_base_score"],
            "v31_base_severity": z["cvss_v31_base_severity"],
            "v40_vector": z["cvss_v40_vector"],
            "v40_base_score": z["cvss_v40_base_score"],
            "v40_base_severity": z["cvss_v40_base_severity"],
            "v40_at": v40.get("AT", "?"),
        })
    return beispiele


def drucke_beispiele(beispiele: list[dict], limit: int):
    print(f"\nGefundene CVEs mit AC:L (v3.1) -> AC:H (v4.0): {len(beispiele)}")
    print("-" * 90)
    for b in beispiele[:limit]:
        print(f"{b['cve_id']}")
        print(f"  v3.1: {b['v31_vector']}")
        print(f"        Score {b['v31_base_score']}  ({b['v31_base_severity']})")
        print(f"  v4.0: {b['v40_vector']}")
        print(f"        Score {b['v40_base_score']}  ({b['v40_base_severity']})  AT:{b['v40_at']}")
        print()
    if len(beispiele) > limit:
        print(f"... ({len(beispiele) - limit} weitere, siehe Ausgabedatei)")


def main():
    parser = argparse.ArgumentParser(
        description="Findet CVE-Beispiele mit AC:L (v3.1) -> AC:H (v4.0)"
    )
    parser.add_argument("--in", dest="in_path", default=DEFAULT_IN, help="Eingabe-CSV (A_70)")
    parser.add_argument("--out", default=DEFAULT_OUT, help="Ausgabe-CSV mit allen Beispielen")
    parser.add_argument("--limit", type=int, default=10, help="Wie viele Beispiele auf der Konsole gezeigt werden")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8")

    pfad = Path(args.in_path)
    zeilen = lade_gruppe_a(pfad)

    print(f"Eingelesen: {pfad}")
    print(f"Zeilen mit vollständigem v3.1- UND v4.0-Vektor: {len(zeilen)}")

    beispiele = finde_ac_l_zu_h(zeilen)
    drucke_beispiele(beispiele, args.limit)

    out_pfad = Path(args.out)
    if beispiele:
        with out_pfad.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(beispiele[0].keys()))
            writer.writeheader()
            writer.writerows(beispiele)
        print(f"\nAlle {len(beispiele)} Beispiele gespeichert in: {out_pfad}")
    else:
        print("\nKeine Beispiele gefunden, keine Ausgabedatei geschrieben.")


if __name__ == "__main__":
    main()
