#!/usr/bin/env python3
"""
Pipeline complet : génère la topologie réseau héritée, calcule son
exposition, conçoit une politique de micro-segmentation adaptative, la
compare au réseau hérité, puis génère le rapport et le dashboard.

Usage :
    python scripts/run_pipeline.py
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import DASHBOARD_OUTPUT_PATH, PCAP_OUTPUT_PATH, REPORT_OUTPUT_PATH
from src.dashboard.dashboard_builder import build_dashboard_html
from src.evaluation.metrics import run_full_comparison
from src.network.topology import generate_legacy_topology
from src.reporting.report_generator import generate_report, save_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    logger.info("Étape 1/4 -- Génération de la topologie réseau héritée...")
    topology = generate_legacy_topology()
    logger.info("%d hôtes, %d connexions autorisées.", len(topology.hosts), len(topology.edges))

    logger.info("Étape 2/4 -- Conception de la politique de segmentation, comparaison, et validation par capture réseau (pcap)...")
    comparison = run_full_comparison(topology, pcap_output_path=str(PCAP_OUTPUT_PATH))
    logger.info(
        "Rayon de compromission direct : %.2f -> %.2f",
        comparison.legacy_exposure.average_direct_blast_radius, comparison.segmented_exposure.average_direct_blast_radius,
    )
    before_crit, after_crit = comparison.critical_direct_exposure_reduction
    logger.info("Hôtes critiques directement exposés : %d -> %d", before_crit, after_crit)
    logger.info("Règles de pare-feu : %d -> %d", len(comparison.legacy_rules), len(comparison.segmented_rules))

    logger.info("Étape 3/4 -- Validation sur trafic réseau capturé (%s)...", PCAP_OUTPUT_PATH)
    pv = comparison.pcap_validation
    logger.info(
        "Capture : %d flux analysés, %d tentatives de mouvement latéral (%d autorisées par le réseau hérité, %d bloquées par la segmentation adaptative)",
        pv.n_flows_analyzed, pv.n_lateral_movement_attempts, pv.n_lateral_allowed_by_legacy, pv.n_lateral_blocked_by_adaptive,
    )
    logger.info(
        "Flux métier légitimes toujours autorisés après segmentation : %d/%d",
        pv.n_legit_flows_still_allowed_by_adaptive, pv.n_legit_flows_total,
    )

    logger.info("Étape 4/4 -- Génération du rapport et du dashboard...")
    report_md = generate_report(comparison)
    save_report(report_md, str(REPORT_OUTPUT_PATH))
    logger.info("Rapport sauvegardé : %s", REPORT_OUTPUT_PATH)

    build_dashboard_html(comparison, str(DASHBOARD_OUTPUT_PATH))
    logger.info("Dashboard sauvegardé : %s", DASHBOARD_OUTPUT_PATH)

    print("\n" + "=" * 70)
    print("RÉSUMÉ")
    print("=" * 70)
    print(f"Rayon de compromission direct : {comparison.legacy_exposure.average_direct_blast_radius} -> "
          f"{comparison.segmented_exposure.average_direct_blast_radius}")
    print(f"Hôtes critiques directement exposés : {before_crit} -> {after_crit}")
    print(f"Règles de pare-feu : {len(comparison.legacy_rules)} -> {len(comparison.segmented_rules)}")
    print(f"Capture pcap : {pv.n_lateral_allowed_by_legacy}/{pv.n_lateral_movement_attempts} mouvements latéraux "
          f"autorisés (hérité) -> {pv.n_lateral_blocked_by_adaptive}/{pv.n_lateral_movement_attempts} bloqués (adaptatif)")
    print(f"Continuité métier : {pv.n_legit_flows_still_allowed_by_adaptive}/{pv.n_legit_flows_total} flux légitimes préservés")


if __name__ == "__main__":
    main()
