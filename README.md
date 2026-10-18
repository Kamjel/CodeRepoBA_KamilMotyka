# CodeRepoBA_KamilMotyk -- Scripte - Übersicht

Dieses Repository enthält alle Skripte und Datensätze, die in der Bachelorarbeit erwähnt werden.
Die Struktur orientiert sich an den Kapiteln der Arbeit.

---

## Datenbeschaffung & Vorverarbeitung (Kap. 3.2 -- 3.3)

| Datei | Beschreibung |
|-------|-------------|
| `fetch_cves_2025.py` | Ruft CVE-Daten des Jahres 2025 über die NVD-API ab und speichert sie als `cves_2025.csv`. |
| `cves_2025.csv` | Rohdatensatz aller 48.162 abgerufenen CVEs. |
| `split_groups.py` | Teilt den Gesamtdatensatz in Gruppe A (v3.1 + v4.0 vorhanden) und Gruppe B (nur v3.1). |
| `cves_2025_group_A.csv` | Gruppe A: 10.419 CVEs mit beiden CVSS-Versionen. |
| `cves_2025_group_B.csv` | Gruppe B: 33.658 CVEs mit nur CVSS v3.1. |
| `visualize_severity.py` | Erzeugt Balkendiagramme zur Severity-Verteilung (v3.1 vs. v4.0). |

## Score- und Severity-Analyse (Kap. 4.1)

| Datei | Beschreibung |
|-------|-------------|
| `analyze_score_severity.py` | Berechnet deskriptive Lagemaße, Score-Differenzen, Severity-Übergangsmatrix, Wilcoxon-Test und Cliff's Delta. |
| `score_deskriptiv.csv` | Deskriptive Lagemaße der Base Scores (Min, Q1, Median, Mittelwert, Q3, Max, Standardabweichung). |
| `score_differenzen.csv` | Verteilung der paarweisen Score-Differenzen (v4.0 minus v3.1). |
| `severity_uebergang.csv` | Severity-Übergangsmatrix v3.1 nach v4.0. |
| `score_statistik.csv` | Ergebnisse des Wilcoxon-Tests und Cliff's Delta. |

## Kalibrierungs-/Validierungsaufteilung (Kap. 3.5)

Ordner: `Verteilung_GroupA/`

| Datei | Beschreibung |
|-------|-------------|
| `split_random_70_30.py` | Teilt Gruppe A zufällig in Kalibrierungsmenge A70 (70 %) und Validierungsmenge A30 (30 %). |
| `check_split_balance.py` | Prüft, ob die 70/30-Aufteilung bezüglich Severity-Verteilung ausgewogen ist. |
| `build_contingency_tables_csv.py` | Erstellt Kontingenztabellen (AC/AT und UI). Ausgabe: CSV. |
| `cves_group_A70.csv` | Kalibrierungsmenge: 7.293 CVEs. |
| `cves_group_A30.csv` | Validierungsmenge: 3.126 CVEs. |
| `kontingenz_ac_at.csv` | Kontingenztabelle AC (v3.1) vs. AT (v4.0). |
| `kontingenz_ui.csv` | Kontingenztabelle UI (v3.1) vs. UI (v4.0). |

## Mapping-Verfahren und Hilfsfunktionen (Kap. 3.5 / 4.2)

Ordner: `Mapping/`

| Datei | Beschreibung |
|-------|-------------|
| `common.py` | Gemeinsame Hilfsfunktionen: CVSS-Vektor-Parsing, CSV-Einlesen. |
| `mapping.py` | Implementiert das Mapping von CVSS v3.1 auf v4.0 (Regeln je Metrik, Score-Berechnung). |
| `cves_mapped.csv` | Ergebnis des Mappings: alle CVEs mit approximiertem v4.0-Vektor und Score. |

## Metrik-Übergänge (Kap. 4.2)

### Attack Vector -- `Mapping/AV/`

| Datei | Beschreibung |
|-------|-------------|
| `analyze_av_csv.py` | Analysiert AV-Übergänge (N/A/L/P) v3.1 nach v4.0. |
| `av_uebergaenge.csv` | Übergangsverteilung Attack Vector. |

### Attack Complexity -- `Mapping/AC/`

| Datei | Beschreibung |
|-------|-------------|
| `analyze_ac_csv.py` | Analysiert AC-Übergänge (L/H) v3.1 nach v4.0. |
| `ac_uebergaenge.csv` | Übergangsverteilung Attack Complexity. |

### Attack Requirements -- `Mapping/AT/`

| Datei | Beschreibung |
|-------|-------------|
| `analyze_at_csv.py` | Analysiert die neue AT-Metrik (N/P) und ihre Verteilung. |
| `at_korrelation_csv.py` | Kreuztabelle AT vs. alle v4.0-Metriken (welche Metrik erklärt AT am besten). |
| `find_ac_l_to_h.py` | Findet CVEs, bei denen AC von Low (v3.1) auf High (v4.0) wechselt. |
| `ac_v31_to_at_csv.py` | Kreuztabelle AC (v3.1) vs. AT (v4.0). |
| `at_uebergaenge.csv` | Übergangsverteilung Attack Requirements. |
| `at_korrelation.csv` | Korrelationsdaten AT vs. andere Metriken. |
| `ac_v31_to_at.csv` | Kreuztabelle AC (v3.1) nach AT (v4.0). |
| `ac_l_to_h_beispiele.csv` | Beispiel-CVEs mit AC Low nach High Wechsel. |

### User Interaction -- `Mapping/UI/`

| Datei | Beschreibung |
|-------|-------------|
| `analyze_ui_csv.py` | Analysiert UI-Übergänge (N/R) v3.1 nach (N/P/A) v4.0. |
| `ui_uebergaenge.csv` | Übergangsverteilung User Interaction. |

### Privileges Required -- `Mapping/PR/`

| Datei | Beschreibung |
|-------|-------------|
| `analyze_pr_csv.py` | Analysiert PR-Übergänge (N/L/H) v3.1 nach v4.0. |
| `pr_uebergaenge.csv` | Übergangsverteilung Privileges Required. |

### Scope-Auflösung -- `Mapping/Scope/`

| Datei | Beschreibung |
|-------|-------------|
| `analyze_scope_csv.py` | Analysiert Scope-Mapping (S:U/C nach VC/VI/VA + SC/SI/SA). |
| `scope_uebergaenge.csv` | Übergangsverteilung Scope und Impact-Metriken. |

### Zusätzliche Metriken -- `Mapping/Extras/`

| Datei | Beschreibung |
|-------|-------------|
| `analyze_extra_metrics_csv.py` | Berechnet die Befüllungsrate der nicht-Base-Metriken in A70. |
| `filter_supplemental.py` | Filtert CVEs mit mindestens einer Supplemental Metric. |
| `extra_metrics.csv` | Befüllungsrate je Metrik (Temporal, Environmental, Supplemental). |
| `supplemental_cves.csv` | Gefilterte CVEs mit Supplemental Metrics (425 CVEs). |

## Validierung (Kap. 3.6 / 4.3)

Ordner: `Mapping/`

| Datei | Beschreibung |
|-------|-------------|
| `mapping_validierung_csv.py` | Validiert das Mapping auf A30: MAE, Severity-Übereinstimmung, Konfusionsmatrix. |
| `validierung_metriken.csv` | Validierungsergebnisse: Score-Abweichung, Vektor-Übereinstimmung je Metrik. |
| `validierung_konfusion.csv` | Konfusionsmatrix der Severity-Stufen auf A30. |

## Anwendung auf Gruppe B (Kap. 4.4)

Ordner: `Mapping/`

| Datei | Beschreibung |
|-------|-------------|
| `gruppe_b_auswertung_csv.py` | Wendet das Mapping auf Gruppe B an und berechnet Lagemaße und Severity-Verteilung. |
| `gruppe_b_lagemasse.csv` | Deskriptive Lagemaße v3.1 vs. approximiertes v4.0 in Gruppe B. |
| `gruppe_b_severity.csv` | Severity-Kreuztabelle in Gruppe B. |

## Priorisierung mit Supplemental Metrics (Kap. 3.7 / 4.5)

Ordner: `Mapping/Extras/`

| Datei | Beschreibung |
|-------|-------------|
| `priorisierung_supplemental.py` | Berechnet die Priorisierung je Unternehmensszenario mit und ohne Severity-Limit. |
| `priorisierung_fertigung.csv` | Top-CVEs nach Priorisierung im Fertigungsszenario (mit Severity-Limit). |
| `priorisierung_krankenhaus.csv` | Top-CVEs nach Priorisierung im Krankenhausszenario (mit Severity-Limit). |
| `priorisierung_ohne_limit_fertigung.csv` | Top-CVEs im Fertigungsszenario ohne Severity-Limit. |
| `priorisierung_ohne_limit_krankenhaus.csv` | Top-CVEs im Krankenhausszenario ohne Severity-Limit. |

---
