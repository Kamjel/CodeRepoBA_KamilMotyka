# CodeRepoBA_KamilMotyka -- Scripte und Datensaetze

Dieses Repository enthaelt alle Skripte und Datensaetze, die in der Bachelorarbeit erwaehnt werden.
Die Struktur orientiert sich an den Kapiteln der Arbeit.

---

## Ordnerstruktur

```
CodeRepoBA_KamilMotyka/
├── Kap3_Methodik/
│   ├── 3.2_Datenbeschaffung/
│   ├── 3.3_Gruppenbildung/
│   ├── 3.5_Mapping_Entwicklung/
│   ├── 3.6_Validierung/
│   └── 3.7_Unternehmensszenarien/
├── Kap4_Auswertung/
│   ├── 4.1_Score_Severity/
│   ├── 4.2_Metrik_Uebergaenge/
│   ├── 4.3_Validierung/
│   ├── 4.4_Gruppe_B/
│   └── 4.5_Supplemental_Priorisierung/
└── README.md
```

---

## Kap3_Methodik

### 3.2_Datenbeschaffung

| Datei | Beschreibung |
|-------|-------------|
| `fetch_cves_2025.py` | Ruft CVE-Daten des Jahres 2025 ueber die NVD-API ab und speichert sie als `cves_2025.csv`. |
| `cves_2025.csv` | Rohdatensatz aller 48.162 abgerufenen CVEs. |

### 3.3_Gruppenbildung

| Datei | Beschreibung |
|-------|-------------|
| `split_groups.py` | Teilt den Gesamtdatensatz in Gruppe A (v3.1 + v4.0 vorhanden) und Gruppe B (nur v3.1). |
| `cves_2025_group_A.csv` | Gruppe A: 10.419 CVEs mit beiden CVSS-Versionen. |
| `cves_2025_group_B.csv` | Gruppe B: 33.658 CVEs mit nur CVSS v3.1. |

### 3.5_Mapping_Entwicklung

| Datei | Beschreibung |
|-------|-------------|
| `split_random_70_30.py` | Teilt Gruppe A zufaellig in Kalibrierungsmenge A70 (70 %) und Validierungsmenge A30 (30 %). |
| `check_split_balance.py` | Prueft, ob die 70/30-Aufteilung bezueglich Severity-Verteilung ausgewogen ist. |
| `build_contingency_tables_csv.py` | Erstellt Kontingenztabellen (AC/AT und UI). Ausgabe: CSV. |
| `cves_group_A70.csv` | Kalibrierungsmenge: 7.293 CVEs. |
| `cves_group_A30.csv` | Validierungsmenge: 3.126 CVEs. |
| `kontingenz_ac_at.csv` | Kontingenztabelle AC (v3.1) vs. AT (v4.0). |
| `kontingenz_ui.csv` | Kontingenztabelle UI (v3.1) vs. UI (v4.0). |

### 3.6_Validierung

| Datei | Beschreibung |
|-------|-------------|
| `mapping_validierung.py` | Validiert das Mapping auf A30: MAE, Severity-Uebereinstimmung, Konfusionsmatrix. |
| `validierung_konfusion.csv` | Konfusionsmatrix der Severity-Stufen auf A30. |
| `validierung_metriken.csv` | Validierungsergebnisse: Score-Abweichung, Vektor-Uebereinstimmung je Metrik. |

### 3.7_Unternehmensszenarien

| Datei | Beschreibung |
|-------|-------------|
| `filter_supplemental.py` | Filtert CVEs mit mindestens einer Supplemental Metric. |
| `supplemental_cves.csv` | Gefilterte CVEs mit Supplemental Metrics (425 CVEs). |

---

## Kap4_Auswertung

### 4.1_Score_Severity

| Datei | Beschreibung |
|-------|-------------|
| `analyze_score_severity.py` | Berechnet deskriptive Lagemasse, Score-Differenzen, Severity-Uebergangsmatrix, Wilcoxon-Test und Cliff's Delta. |
| `visualize_severity.py` | Erzeugt Balkendiagramme zur Severity-Verteilung (v3.1 vs. v4.0). |
| `score_deskriptiv.csv` | Deskriptive Lagemasse der Base Scores (Min, Q1, Median, Mittelwert, Q3, Max, Standardabweichung). |
| `score_differenzen.csv` | Verteilung der paarweisen Score-Differenzen (v4.0 minus v3.1). |
| `severity_uebergang.csv` | Severity-Uebergangsmatrix v3.1 nach v4.0. |
| `score_statistik.csv` | Ergebnisse des Wilcoxon-Tests und Cliff's Delta. |

### 4.2_Metrik_Uebergaenge

| Datei | Beschreibung |
|-------|-------------|
| `common.py` | Gemeinsame Hilfsfunktionen: CVSS-Vektor-Parsing, CSV-Einlesen. |
| `mapping.py` | Implementiert das Mapping von CVSS v3.1 auf v4.0 (Regeln je Metrik, Score-Berechnung). |
| `analyze_av_csv.py` | Analysiert AV-Uebergaenge (N/A/L/P) v3.1 nach v4.0. |
| `analyze_ac_csv.py` | Analysiert AC-Uebergaenge (L/H) v3.1 nach v4.0. |
| `analyze_at_csv.py` | Analysiert die neue AT-Metrik (N/P) und ihre Verteilung. |
| `at_korrelation_csv.py` | Kreuztabelle AT vs. alle v4.0-Metriken (welche Metrik erklaert AT am besten). |
| `find_ac_l_to_h.py` | Findet CVEs, bei denen AC von Low (v3.1) auf High (v4.0) wechselt. |
| `ac_v31_to_at_csv.py` | Kreuztabelle AC (v3.1) vs. AT (v4.0). |
| `analyze_ui_csv.py` | Analysiert UI-Uebergaenge (N/R) v3.1 nach (N/P/A) v4.0. |
| `analyze_pr_csv.py` | Analysiert PR-Uebergaenge (N/L/H) v3.1 nach v4.0. |
| `analyze_scope_csv.py` | Analysiert Scope-Mapping (S:U/C nach VC/VI/VA + SC/SI/SA). |
| `analyze_extra_metrics_csv.py` | Berechnet die Befuellungsrate der nicht-Base-Metriken in A70. |
| `av_uebergaenge.csv` | Uebergangsverteilung Attack Vector. |
| `ac_uebergaenge.csv` | Uebergangsverteilung Attack Complexity. |
| `at_uebergaenge.csv` | Uebergangsverteilung Attack Requirements. |
| `ac_v31_to_at.csv` | Kreuztabelle AC (v3.1) nach AT (v4.0). |
| `ac_l_to_h_beispiele.csv` | Beispiel-CVEs mit AC Low nach High Wechsel. |
| `ui_uebergaenge.csv` | Uebergangsverteilung User Interaction. |
| `pr_uebergaenge.csv` | Uebergangsverteilung Privileges Required. |
| `scope_uebergaenge.csv` | Uebergangsverteilung Scope und Impact-Metriken. |
| `extra_metrics.csv` | Befuellungsrate je Metrik (Temporal, Environmental, Supplemental). |

### 4.3_Validierung

| Datei | Beschreibung |
|-------|-------------|
| `mapping_validierung_csv.py` | Validiert das Mapping auf A30: MAE, Severity-Uebereinstimmung, Konfusionsmatrix. |
| `validierung_konfusion.csv` | Konfusionsmatrix der Severity-Stufen auf A30. |
| `validierung_metriken.csv` | Validierungsergebnisse: Score-Abweichung, Vektor-Uebereinstimmung je Metrik. |

### 4.4_Gruppe_B

| Datei | Beschreibung |
|-------|-------------|
| `gruppe_b_auswertung_csv.py` | Wendet das Mapping auf Gruppe B an und berechnet Lagemasse und Severity-Verteilung. |
| `cves_mapped.csv` | Ergebnis des Mappings: alle CVEs mit approximiertem v4.0-Vektor und Score. |
| `gruppe_b_lagemasse.csv` | Deskriptive Lagemasse v3.1 vs. approximiertes v4.0 in Gruppe B. |
| `gruppe_b_severity.csv` | Severity-Kreuztabelle in Gruppe B. |

### 4.5_Supplemental_Priorisierung

| Datei | Beschreibung |
|-------|-------------|
| `priorisierung_supplemental.py` | Berechnet die Priorisierung je Unternehmensszenario mit und ohne Severity-Limit. |
| `priorisierung_fertigung.csv` | Top-CVEs nach Priorisierung im Fertigungsszenario (mit Severity-Limit). |
| `priorisierung_krankenhaus.csv` | Top-CVEs nach Priorisierung im Krankenhausszenario (mit Severity-Limit). |
| `priorisierung_ohne_limit_fertigung.csv` | Top-CVEs im Fertigungsszenario ohne Severity-Limit. |
| `priorisierung_ohne_limit_krankenhaus.csv` | Top-CVEs im Krankenhausszenario ohne Severity-Limit. |

---
