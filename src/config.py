"""Configuration centrale du simulateur de micro-segmentation réseau."""
from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DASHBOARD_OUTPUT_PATH = BASE_DIR / "dashboard.html"
REPORT_OUTPUT_PATH = BASE_DIR / "rapport_microsegmentation.md"
PCAP_OUTPUT_PATH = BASE_DIR / "capture_demo.pcap"

RANDOM_SEED = 42

# Poids de criticité par type d'hôte -- même principe de pondération
# contextuelle que mes autres projets (Governance RAG Copilot, Mini-DSPM,
# SOC Alert Triage), appliqué ici à la criticité d'un actif réseau plutôt
# qu'à un risque applicatif.
HOST_CRITICALITY_WEIGHTS = {
    "poste_utilisateur": 1.0,
    "serveur_applicatif": 2.5,
    "serveur_base_donnees": 4.0,
    "controleur_domaine": 5.0,
    "serveur_exposition_externe": 3.5,  # exposé à Internet -> surface d'attaque d'entrée
}
