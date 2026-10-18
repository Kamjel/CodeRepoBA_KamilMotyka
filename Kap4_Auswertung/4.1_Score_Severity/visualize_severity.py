# Erzeugt zwei gruppierte Balkendiagramme (PNG):
# 1) Severity-Verteilung CVSS v3.1 vs. v4.0 (alle CVEs)
# 2) Severity-Verteilung Gruppe A vs. Gruppe B (jeweils nach v3.1-Severity)
#
# Nutzung:
#     python visualize_severity.py

import csv
from pathlib import Path

import matplotlib.pyplot as plt

IN_ALL = "cves_2025.csv"
IN_GROUP_A = "cves_2025_group_A.csv"
IN_GROUP_B = "cves_2025_group_B.csv"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

COLOR_1 = "#2b6cb0"  # v3.1 / Gruppe A
COLOR_2 = "#dd6b20"  # v4.0 / Gruppe B


def count_severity(path: str, field: str) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sev = (row.get(field) or "").strip().upper()
            if sev in counts:
                counts[sev] += 1
    return counts


def grouped_bar_chart(counts_1: dict, counts_2: dict, label_1: str, label_2: str, title: str, out_path: str):
    x = range(len(SEVERITY_ORDER))
    width = 0.38

    values_1 = [counts_1[s] for s in SEVERITY_ORDER]
    values_2 = [counts_2[s] for s in SEVERITY_ORDER]

    fig, ax = plt.subplots(figsize=(9, 5.5))

    bars_1 = ax.bar([i - width / 2 for i in x], values_1, width, label=label_1, color=COLOR_1)
    bars_2 = ax.bar([i + width / 2 for i in x], values_2, width, label=label_2, color=COLOR_2)

    ax.set_xticks(list(x))
    ax.set_xticklabels([s.capitalize() for s in SEVERITY_ORDER])
    ax.set_ylabel("Anzahl CVEs")
    ax.set_title(title)
    ax.legend(frameon=False)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", color="#e2e8f0", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)

    for bars in (bars_1, bars_2):
        ax.bar_label(bars, padding=3, fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    print(f"Gespeichert: {out_path}")


def main():
    counts_v31 = count_severity(IN_ALL, "cvss_v31_base_severity")
    counts_v40 = count_severity(IN_ALL, "cvss_v40_base_severity")
    grouped_bar_chart(
        counts_v31, counts_v40,
        "CVSS v3.1", "CVSS v4.0",
        "Severity-Verteilung: CVSS v3.1 vs. v4.0 (CVEs 2025)",
        "severity_v31_vs_v40.png",
    )

    counts_a = count_severity(IN_GROUP_A, "cvss_v31_base_severity")
    counts_b = count_severity(IN_GROUP_B, "cvss_v31_base_severity")
    grouped_bar_chart(
        counts_a, counts_b,
        "Gruppe A (v3.1 + v4.0)", "Gruppe B (nur v3.1)",
        "Severity-Verteilung: Gruppe A vs. Gruppe B (CVSS v3.1)",
        "severity_group_a_vs_b.png",
    )


if __name__ == "__main__":
    main()
