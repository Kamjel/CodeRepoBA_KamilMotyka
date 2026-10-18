# Validierung des Mapping-Verfahrens anhand der A_30 (Out-of-Sample).
# Wendet das Mapping auf die v3.1-Vektoren der A_30 an und vergleicht
# die approximierten v4.0-Werte mit den echten v4.0-Werten.
#
# Validierungsmetriken (siehe Mapping_Entscheidung.md):
#   - Severity-Übereinstimmungsrate
#   - MAE (Mean Absolute Error)
#   - Konfusionsmatrix (Severity approx vs. Severity echt)
#   - Vektor-Übereinstimmung pro Metrik
#
# Nutzung:
#     python mapping_validierung.py [--in cves_group_A30.csv] [--out validierung.json]

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import parse_vector, lade_gruppe_a, ergebnis_huelle  # noqa: E402
from mapping import mappe_v31_auf_v40, baue_v40_vektor, berechne_score, severity_aus_score  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / ".." / "Verteilung_GroupA" / "cves_group_A30.csv"
DEFAULT_OUT = SCRIPT_DIR / "validierung.json"

SEVERITY_KLASSEN = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

VERGLEICHS_METRIKEN = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]


def validiere(zeilen: list[dict]) -> dict:
    scores_echt = []
    scores_approx = []
    severity_echt_liste = []
    severity_approx_liste = []
    metrik_treffer: dict[str, dict] = {m: {"korrekt": 0, "falsch": 0} for m in VERGLEICHS_METRIKEN}
    fehler = []

    for z in zeilen:
        v31_vektor = z.get("cvss_v31_vector", "")
        v40_vektor_echt = z.get("cvss_v40_vector", "")

        if not v31_vektor or not v40_vektor_echt:
            continue

        v31 = parse_vector(v31_vektor)
        v40_echt = parse_vector(v40_vektor_echt)

        v40_approx_metriken = mappe_v31_auf_v40(v31)
        v40_approx_vektor = baue_v40_vektor(v40_approx_metriken)

        try:
            score_approx, _ = berechne_score(v40_approx_vektor)
        except Exception as e:
            fehler.append({"cve_id": z.get("cve_id", "?"), "fehler": str(e)})
            continue

        try:
            score_echt = float(z["cvss_v40_base_score"])
        except (TypeError, ValueError):
            continue

        severity_echt = z.get("cvss_v40_base_severity", "").upper()
        if not severity_echt:
            severity_echt = severity_aus_score(score_echt)
        severity_approx = severity_aus_score(score_approx)

        scores_echt.append(score_echt)
        scores_approx.append(score_approx)
        severity_echt_liste.append(severity_echt)
        severity_approx_liste.append(severity_approx)

        for m in VERGLEICHS_METRIKEN:
            wert_echt = v40_echt.get(m, "?")
            wert_approx = v40_approx_metriken.get(m, "?")
            if wert_echt == wert_approx:
                metrik_treffer[m]["korrekt"] += 1
            else:
                metrik_treffer[m]["falsch"] += 1

    n = len(scores_echt)
    if n == 0:
        return {"fehler": "Keine auswertbaren Zeilen"}

    # --- MAE ---
    mae = round(sum(abs(e - a) for e, a in zip(scores_echt, scores_approx)) / n, 4)

    # --- Severity-Übereinstimmung ---
    severity_korrekt = sum(1 for e, a in zip(severity_echt_liste, severity_approx_liste) if e == a)
    severity_rate = round(severity_korrekt / n, 4)

    # --- Konfusionsmatrix ---
    konfusion: dict[str, dict[str, int]] = {}
    for klasse in SEVERITY_KLASSEN:
        konfusion[klasse] = {k: 0 for k in SEVERITY_KLASSEN}
    for e, a in zip(severity_echt_liste, severity_approx_liste):
        if e in konfusion and a in konfusion[e]:
            konfusion[e][a] += 1

    # --- Vektor-Übereinstimmung pro Metrik ---
    metrik_raten = {}
    for m in VERGLEICHS_METRIKEN:
        gesamt = metrik_treffer[m]["korrekt"] + metrik_treffer[m]["falsch"]
        rate = round(metrik_treffer[m]["korrekt"] / gesamt, 4) if gesamt else 0
        metrik_raten[m] = {
            "korrekt": metrik_treffer[m]["korrekt"],
            "falsch": metrik_treffer[m]["falsch"],
            "uebereinstimmung": rate,
        }

    # --- Score-Statistiken ---
    deltas = [round(a - e, 2) for e, a in zip(scores_echt, scores_approx)]
    delta_abs = [abs(d) for d in deltas]

    return {
        "n_ausgewertet": n,
        "n_fehler": len(fehler),
        "mae": mae,
        "severity_uebereinstimmung": severity_rate,
        "severity_korrekt": severity_korrekt,
        "severity_falsch": n - severity_korrekt,
        "score_delta": {
            "mittel": round(sum(deltas) / n, 4),
            "mittel_abs": mae,
            "min": min(deltas),
            "max": max(deltas),
            "median": round(sorted(deltas)[n // 2], 2),
        },
        "konfusionsmatrix": konfusion,
        "metrik_uebereinstimmung": metrik_raten,
        "fehler_details": fehler[:20],
    }


def drucke_ergebnis(erg: dict):
    print(f"\n{'=' * 60}")
    print(f"VALIDIERUNGSERGEBNIS (n = {erg['n_ausgewertet']})")
    print(f"{'=' * 60}")

    print(f"\n--- Akzeptanzschwellen ---")
    sev_pct = erg["severity_uebereinstimmung"] * 100
    mae = erg["mae"]
    print(f"  Severity-Übereinstimmung: {sev_pct:.1f}%  (Schwelle: ≥ 80%)  {'OK' if sev_pct >= 80 else 'NICHT ERREICHT'}")
    print(f"  MAE:                      {mae:.2f}    (Schwelle: ≤ 1.0)  {'OK' if mae <= 1.0 else 'NICHT ERREICHT'}")

    print(f"\n--- Score-Delta (approx - echt) ---")
    sd = erg["score_delta"]
    print(f"  Mittel:  {sd['mittel']:>+6.2f}")
    print(f"  Median:  {sd['median']:>+6.2f}")
    print(f"  Spanne:  [{sd['min']:>+5.2f} .. {sd['max']:>+5.2f}]")

    print(f"\n--- Konfusionsmatrix (Zeile = echt, Spalte = approx) ---")
    km = erg["konfusionsmatrix"]
    header = "".join(f"{k[:4]:>8}" for k in SEVERITY_KLASSEN)
    print(f"  {'':>8}{header}")
    for zeile_name in SEVERITY_KLASSEN:
        werte = "".join(f"{km[zeile_name][k]:>8}" for k in SEVERITY_KLASSEN)
        print(f"  {zeile_name[:8]:>8}{werte}")

    print(f"\n--- Vektor-Übereinstimmung pro Metrik ---")
    for m, stat in erg["metrik_uebereinstimmung"].items():
        pct = stat["uebereinstimmung"] * 100
        print(f"  {m:<4}  {pct:>6.1f}%  ({stat['korrekt']} korrekt, {stat['falsch']} falsch)")

    if erg.get("n_fehler", 0):
        print(f"\n  {erg['n_fehler']} Zeile(n) mit Berechnungsfehler (Details in JSON)")


def main():
    parser = argparse.ArgumentParser(
        description="Validiert das Mapping-Verfahren anhand der A_30 (Out-of-Sample)"
    )
    parser.add_argument("--in", dest="in_path", default=DEFAULT_IN, help="Eingabe-CSV (A_30)")
    parser.add_argument("--out", default=DEFAULT_OUT, help="Ausgabe-JSON mit Validierungsergebnis")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8")

    pfad = Path(args.in_path)
    zeilen = lade_gruppe_a(pfad)

    print(f"Eingelesen: {pfad}")
    print(f"Zeilen mit vollständigem v3.1- UND v4.0-Vektor: {len(zeilen)}")

    erg = validiere(zeilen)
    drucke_ergebnis(erg)

    ausgabe = ergebnis_huelle("mapping_validierung.py", pfad, len(zeilen), erg)

    out_pfad = Path(args.out)
    with out_pfad.open("w", encoding="utf-8") as f:
        json.dump(ausgabe, f, ensure_ascii=False, indent=2)

    print(f"\nErgebnis gespeichert in: {out_pfad}")


if __name__ == "__main__":
    main()
