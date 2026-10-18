# Gemeinsame Hilfsfunktionen für alle Mapping-Analyse-Scripte:
# CVSS-Vektor-Parsing, Einlesen der Kalibrierungsmenge (A_70) und
# einheitliche JSON-Ausgabehülle für konsistente Ergebnisformate.

import csv
from datetime import datetime, timezone
from pathlib import Path

SCRIPTE_ROOT = Path(__file__).resolve().parent.parent


def parse_vector(vector: str) -> dict:
    if not vector:
        return {}

    teile = vector.split("/")
    ergebnis = {}
    for teil in teile:
        if ":" not in teil:
            continue
        schluessel, _, wert = teil.partition(":")
        if schluessel == "CVSS":
            continue
        ergebnis[schluessel] = wert
    return ergebnis


def lade_gruppe_a(pfad: Path) -> list[dict]:
    with pfad.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        zeilen = list(reader)

    vollstaendig = [
        z for z in zeilen
        if z.get("cvss_v31_vector") and z.get("cvss_v40_vector")
    ]
    uebersprungen = len(zeilen) - len(vollstaendig)
    if uebersprungen:
        print(f"Hinweis: {uebersprungen} Zeile(n) ohne vollständiges Vektorpaar übersprungen.")

    return vollstaendig


def quelle_relativ(pfad: Path) -> str:
    aufgeloest = pfad.resolve()
    try:
        return aufgeloest.relative_to(SCRIPTE_ROOT).as_posix()
    except ValueError:
        return aufgeloest.as_posix()


def ergebnis_huelle(script_name: str, quelle: Path, n_gesamt: int, ergebnis: dict) -> dict:
    return {
        "script": script_name,
        "quelle": quelle_relativ(quelle),
        "n_gesamt": n_gesamt,
        "erstellt_am": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ergebnis": ergebnis,
    }
