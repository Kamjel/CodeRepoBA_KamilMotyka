# Mapping-Skript: Bildet CVSS v3.1 Base-Vektoren auf CVSS v4.0 Base-Vektoren ab.
# Basiert auf den dokumentierten Entscheidungen in Mapping_Entscheidung.md.
# Berechnet den v4.0-Score mit der cvss-Bibliothek (RedHat).
#
# Nutzung:
#     python mapping.py [--in cves_2025_group_B.csv] [--out cves_mapped.csv]

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import parse_vector  # noqa: E402

from cvss import CVSS4  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / "cves_2025_group_B.csv"
DEFAULT_OUT = SCRIPT_DIR / "cves_mapped.csv"

APPROX_DISCLAIMER = "[APPROX CVSS 4.0] "


def mappe_v31_auf_v40(v31: dict) -> dict:
    """Wendet die Mapping-Regeln aus Mapping_Entscheidung.md an."""

    # --- 1:1 Metriken ---
    av = v31.get("AV", "N")
    ac = v31.get("AC", "L")
    pr = v31.get("PR", "N")

    # --- UI: N->N, R->P ---
    ui_31 = v31.get("UI", "N")
    if ui_31 == "R":
        ui = "P"
    else:
        ui = "N"

    # --- AT: immer N (92,3% korrekt laut Analyse, AC:H ergibt nur 40% AT:P) ---
    at = "N"

    # --- Scope + C/I/A -> VC/VI/VA + SC/SI/SA ---
    scope = v31.get("S", "U")
    c = v31.get("C", "N")
    i = v31.get("I", "N")
    a = v31.get("A", "N")

    if scope == "U":
        vc, sc = c, "N"
        vi, si = i, "N"
        va, sa = a, "N"
    else:  # Scope:C
        if c == "N":
            vc, sc = "N", "N"
        elif c == "L":
            vc, sc = "N", "L"
        else:  # H
            vc, sc = "H", "H"

        if i == "N":
            vi, si = "N", "N"
        elif i == "L":
            vi, si = "N", "L"
        else:  # H
            vi, si = "H", "H"

        if a == "N":
            va, sa = "N", "N"
        elif a == "L":
            va, sa = "L", "L"
        else:  # H
            va, sa = "H", "H"

    return {
        "AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
        "VC": vc, "VI": vi, "VA": va, "SC": sc, "SI": si, "SA": sa,
    }


def baue_v40_vektor(metriken: dict) -> str:
    """Baut den vollständigen CVSS v4.0 Vektor-String (Base + alle anderen auf X)."""
    base = (
        f"CVSS:4.0/AV:{metriken['AV']}/AC:{metriken['AC']}/AT:{metriken['AT']}"
        f"/PR:{metriken['PR']}/UI:{metriken['UI']}"
        f"/VC:{metriken['VC']}/VI:{metriken['VI']}/VA:{metriken['VA']}"
        f"/SC:{metriken['SC']}/SI:{metriken['SI']}/SA:{metriken['SA']}"
    )
    nicht_base = (
        "/E:X/CR:X/IR:X/AR:X"
        "/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X"
        "/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X"
        "/S:X/AU:X/R:X/V:X/RE:X/U:X"
    )
    return base + nicht_base


def berechne_score(vektor: str) -> tuple[float, str]:
    """Berechnet Score und Severity mit der cvss-Bibliothek."""
    c = CVSS4(vektor)
    return c.base_score, c.severity


def severity_aus_score(score: float) -> str:
    if score == 0.0:
        return "NONE"
    elif score <= 3.9:
        return "LOW"
    elif score <= 6.9:
        return "MEDIUM"
    elif score <= 8.9:
        return "HIGH"
    else:
        return "CRITICAL"


def main():
    parser = argparse.ArgumentParser(
        description="Mappt CVSS v3.1 Base-Vektoren auf approximierte CVSS v4.0 Base-Vektoren "
                    "und berechnet den v4.0-Score."
    )
    parser.add_argument("--in", dest="in_path", default=DEFAULT_IN,
                        help="Eingabe-CSV mit v3.1-Vektoren (z.B. Gruppe B)")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="Ausgabe-CSV mit approximierten v4.0-Werten")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8")

    pfad = Path(args.in_path)
    out_pfad = Path(args.out)

    with pfad.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        eingabe_felder = reader.fieldnames
        zeilen = list(reader)

    print(f"Eingelesen: {pfad} ({len(zeilen)} Zeilen)")

    ausgabe_felder = list(eingabe_felder) + [
        "approx_v40_vector", "approx_v40_base_score", "approx_v40_base_severity"
    ]

    n_gemappt = 0
    n_uebersprungen = 0
    n_fehler = 0

    ergebnisse = []
    for z in zeilen:
        v31_vektor = z.get("cvss_v31_vector", "")
        if not v31_vektor:
            n_uebersprungen += 1
            z["approx_v40_vector"] = ""
            z["approx_v40_base_score"] = ""
            z["approx_v40_base_severity"] = ""
            ergebnisse.append(z)
            continue

        v31 = parse_vector(v31_vektor)
        v40_metriken = mappe_v31_auf_v40(v31)
        v40_vektor = baue_v40_vektor(v40_metriken)

        try:
            score, _ = berechne_score(v40_vektor)
            severity = severity_aus_score(score)
        except Exception as e:
            print(f"  Fehler bei {z.get('cve_id', '?')}: {e}")
            n_fehler += 1
            z["approx_v40_vector"] = v40_vektor
            z["approx_v40_base_score"] = "ERROR"
            z["approx_v40_base_severity"] = "ERROR"
            ergebnisse.append(z)
            continue

        z["approx_v40_vector"] = v40_vektor
        z["approx_v40_base_score"] = score
        z["approx_v40_base_severity"] = severity

        if z.get("description", ""):
            z["description"] = APPROX_DISCLAIMER + z["description"]

        n_gemappt += 1
        ergebnisse.append(z)

    with out_pfad.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ausgabe_felder)
        writer.writeheader()
        writer.writerows(ergebnisse)

    print(f"\nErgebnis:")
    print(f"  Gemappt:      {n_gemappt}")
    print(f"  Übersprungen:  {n_uebersprungen} (kein v3.1-Vektor)")
    print(f"  Fehler:        {n_fehler}")
    print(f"\nAusgabe: {out_pfad}")


if __name__ == "__main__":
    main()
