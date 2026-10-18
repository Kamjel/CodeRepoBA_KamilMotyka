# Berechnet Prioritätspunkte aus Supplemental Metrics für zwei
# Unternehmensszenarien (Fertigung und Krankenhaus) und erzeugt
# je Szenario eine nach Severity-Klasse und Prioritätspunkten
# sortierte CSV-Ausgabe.
#
# Eingabe:  supplemental_cves.csv (erzeugt durch filter_supplemental.py)
# Ausgabe:  priorisierung_fertigung.csv
#           priorisierung_ohne_limit_fertigung.csv
#           priorisierung_krankenhaus.csv
#           priorisierung_ohne_limit_krankenhaus.csv
#
# Nutzung:
#     python priorisierung_supplemental.py [--in supplemental_cves.csv]

import argparse
import csv
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_IN = SCRIPT_DIR / "supplemental_cves.csv"
DEFAULT_OUT_FERTIGUNG = SCRIPT_DIR / "priorisierung_fertigung.csv"
DEFAULT_OUT_KRANKENHAUS = SCRIPT_DIR / "priorisierung_krankenhaus.csv"
DEFAULT_OUT_FERTIGUNG_OL = SCRIPT_DIR / "priorisierung_ohne_limit_fertigung.csv"
DEFAULT_OUT_KRANKENHAUS_OL = SCRIPT_DIR / "priorisierung_ohne_limit_krankenhaus.csv"

SEVERITY_RANG = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
}

# Gewichtungsregeln je Szenario (Tabelle 3-13 der Arbeit).
# Jeder Eintrag: Metrik-Kürzel -> {Wert: Punktänderung}
# Werte ohne Eintrag oder mit 0 haben keine Auswirkung.

GEWICHTUNG_FERTIGUNG = {
    "S":  {"P": +1, "N": 0},
    "AU": {"Y": +1, "N": 0},
    "R":  {"I": +1, "U": 0, "A": -1},
    "V":  {"C": 0, "D": 0},
    "RE": {"H": +1, "M": 0, "L": -1},
    "U":  {"Red": +1, "Amber": 0, "Green": -1, "Clear": -1},
}

GEWICHTUNG_KRANKENHAUS = {
    "S":  {"P": +1, "N": 0},
    "AU": {"Y": +1, "N": 0},
    "R":  {"I": +1, "U": 0, "A": 0},
    "V":  {"C": +1, "D": 0},
    "RE": {"H": +1, "M": 0, "L": -1},
    "U":  {"Red": +1, "Amber": 0, "Green": -1, "Clear": -1},
}

SUPPLEMENTAL_METRIKEN = ["S", "AU", "R", "V", "RE", "U"]


def berechne_prioritaet(zeile, gewichtung):
    """Berechnet die Prioritätspunkte einer CVE anhand der Gewichtungsregeln."""
    punkte = 0
    einzelwerte = {}

    for metrik in SUPPLEMENTAL_METRIKEN:
        wert = zeile.get(metrik, "").strip()
        if not wert:
            einzelwerte[metrik] = ""
            continue

        delta = gewichtung.get(metrik, {}).get(wert, 0)
        punkte += delta
        if delta > 0:
            einzelwerte[metrik] = f"+{delta}"
        elif delta < 0:
            einzelwerte[metrik] = str(delta)
        else:
            einzelwerte[metrik] = "0"

    return punkte, einzelwerte


def erstelle_rangliste(zeilen, gewichtung):
    """Erstellt die sortierte Rangliste für ein Szenario."""
    eintraege = []

    for z in zeilen:
        severity = z.get("v40_severity", "").strip()
        score_str = z.get("v40_score", "").strip()

        if not severity or severity not in SEVERITY_RANG:
            continue
        if not score_str:
            continue

        score = float(score_str)
        punkte, einzelwerte = berechne_prioritaet(z, gewichtung)

        prio_score = score + punkte

        eintraege.append({
            "cve_id": z["cve_id"],
            "severity": severity,
            "score": score,
            "prioritaets_punkte": punkte,
            "prioritaets_score": prio_score,
            "einzelwerte": einzelwerte,
            "severity_rang": SEVERITY_RANG[severity],
        })

    # Sortierung: 1. Severity (Critical zuerst), 2. Prioritätspunkte (höchste zuerst),
    # 3. Score (höchster zuerst)
    eintraege.sort(key=lambda e: (e["severity_rang"], -e["prioritaets_punkte"], -e["score"]))

    for i, eintrag in enumerate(eintraege, start=1):
        eintrag["rang"] = i

    return eintraege


def erstelle_rangliste_ohne_limit(zeilen, gewichtung):
    """Erstellt eine Rangliste ohne Severity-Klassengrenzen."""
    eintraege = []

    for z in zeilen:
        severity = z.get("v40_severity", "").strip()
        score_str = z.get("v40_score", "").strip()

        if not severity or severity not in SEVERITY_RANG:
            continue
        if not score_str:
            continue

        score = float(score_str)
        punkte, einzelwerte = berechne_prioritaet(z, gewichtung)

        prio_score = score + punkte

        eintraege.append({
            "cve_id": z["cve_id"],
            "severity": severity,
            "score": score,
            "prioritaets_punkte": punkte,
            "prioritaets_score": prio_score,
            "einzelwerte": einzelwerte,
            "severity_rang": SEVERITY_RANG[severity],
        })

    eintraege.sort(key=lambda e: (-e["prioritaets_score"], -e["score"]))

    # Rang vergeben
    for i, eintrag in enumerate(eintraege, start=1):
        eintrag["rang"] = i

    return eintraege


def schreibe_csv(eintraege, pfad, mit_prio_score=False):
    """Schreibt die Rangliste als CSV."""
    felder = ["Rang", "CVE_ID", "Severity", "Score", "Prioritaets_Punkte",
              "S", "AU", "R", "V", "RE", "U"]
    if mit_prio_score:
        felder.append("Prioritaets_Score")

    with pfad.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=felder)
        writer.writeheader()

        for e in eintraege:
            row = {
                "Rang": e["rang"],
                "CVE_ID": e["cve_id"],
                "Severity": e["severity"],
                "Score": e["score"],
                "Prioritaets_Punkte": e["prioritaets_punkte"],
            }
            for m in SUPPLEMENTAL_METRIKEN:
                row[m] = e["einzelwerte"][m]
            if mit_prio_score:
                row["Prioritaets_Score"] = e["prioritaets_score"]

            writer.writerow(row)


def drucke_zusammenfassung(name, eintraege):
    """Gibt eine kurze Übersicht auf der Konsole aus."""
    print(f"\n{'=' * 60}")
    print(f"Szenario: {name}")
    print(f"{'=' * 60}")
    print(f"Anzahl CVEs in Rangliste: {len(eintraege)}")

    # Verteilung der Prioritätspunkte
    punkte_verteilung = {}
    for e in eintraege:
        p = e["prioritaets_punkte"]
        punkte_verteilung[p] = punkte_verteilung.get(p, 0) + 1

    print(f"\nVerteilung der Prioritätspunkte:")
    for p in sorted(punkte_verteilung.keys(), reverse=True):
        print(f"  {p:+d}: {punkte_verteilung[p]} CVEs")

    # Verschiebungen pro Severity
    print(f"\nVerschiebungen pro Severity-Klasse:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_eintraege = [e for e in eintraege if e["severity"] == sev]
        if not sev_eintraege:
            continue
        n_hoch = sum(1 for e in sev_eintraege if e["prioritaets_punkte"] > 0)
        n_runter = sum(1 for e in sev_eintraege if e["prioritaets_punkte"] < 0)
        n_gleich = sum(1 for e in sev_eintraege if e["prioritaets_punkte"] == 0)
        print(f"  {sev:<10} n={len(sev_eintraege):>4}  "
              f"hoch: {n_hoch:>4}  runter: {n_runter:>4}  gleich: {n_gleich:>4}")

    # Top 5
    print(f"\nTop 5:")
    for e in eintraege[:5]:
        print(f"  #{e['rang']:<4} {e['cve_id']:<20} {e['severity']:<10} "
              f"Score={e['score']:<5} Prio={e['prioritaets_punkte']:+d}")


def main():
    parser = argparse.ArgumentParser(
        description="Berechnet Priorisierungslisten mit Supplemental Metrics für Fertigungs- und Krankenhausszenario"
    )
    parser.add_argument("--in", dest="in_path", default=DEFAULT_IN,
                        help="Eingabe-CSV (supplemental_cves.csv)")
    parser.add_argument("--out-fertigung", default=DEFAULT_OUT_FERTIGUNG,
                        help="Ausgabe-CSV Fertigungsszenario")
    parser.add_argument("--out-krankenhaus", default=DEFAULT_OUT_KRANKENHAUS,
                        help="Ausgabe-CSV Krankenhausszenario")
    parser.add_argument("--out-ol-fertigung", default=DEFAULT_OUT_FERTIGUNG_OL,
                        help="Ausgabe-CSV Fertigung ohne Severity-Limit")
    parser.add_argument("--out-ol-krankenhaus", default=DEFAULT_OUT_KRANKENHAUS_OL,
                        help="Ausgabe-CSV Krankenhaus ohne Severity-Limit")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8")

    pfad = Path(args.in_path)
    with pfad.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        zeilen = list(reader)

    print(f"Eingelesen: {pfad} ({len(zeilen)} CVEs)")

    # Fertigung
    liste_fertigung = erstelle_rangliste(zeilen, GEWICHTUNG_FERTIGUNG)
    schreibe_csv(liste_fertigung, Path(args.out_fertigung), mit_prio_score=True)
    drucke_zusammenfassung("Fertigungsunternehmen", liste_fertigung)
    print(f"\nCSV gespeichert: {args.out_fertigung}")

    # Krankenhaus
    liste_krankenhaus = erstelle_rangliste(zeilen, GEWICHTUNG_KRANKENHAUS)
    schreibe_csv(liste_krankenhaus, Path(args.out_krankenhaus), mit_prio_score=True)
    drucke_zusammenfassung("Krankenhaus", liste_krankenhaus)
    print(f"\nCSV gespeichert: {args.out_krankenhaus}")

    # Ohne Severity-Limit: Fertigung
    liste_ol_fertigung = erstelle_rangliste_ohne_limit(zeilen, GEWICHTUNG_FERTIGUNG)
    schreibe_csv(liste_ol_fertigung, Path(args.out_ol_fertigung), mit_prio_score=True)
    drucke_zusammenfassung("Fertigungsunternehmen (ohne Limit)", liste_ol_fertigung)
    print(f"\nCSV gespeichert: {args.out_ol_fertigung}")

    # Ohne Severity-Limit: Krankenhaus
    liste_ol_krankenhaus = erstelle_rangliste_ohne_limit(zeilen, GEWICHTUNG_KRANKENHAUS)
    schreibe_csv(liste_ol_krankenhaus, Path(args.out_ol_krankenhaus), mit_prio_score=True)
    drucke_zusammenfassung("Krankenhaus (ohne Limit)", liste_ol_krankenhaus)
    print(f"\nCSV gespeichert: {args.out_ol_krankenhaus}")

    # Vergleich: CVEs mit unterschiedlicher Priorisierung
    unterschiede = 0
    for f_eintrag in liste_fertigung:
        k_eintrag = next((k for k in liste_krankenhaus
                          if k["cve_id"] == f_eintrag["cve_id"]), None)
        if k_eintrag and f_eintrag["prioritaets_punkte"] != k_eintrag["prioritaets_punkte"]:
            unterschiede += 1

    print(f"\n{'=' * 60}")
    print(f"CVEs mit unterschiedlichen Prioritätspunkten zwischen Szenarien: {unterschiede}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
