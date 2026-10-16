"""Compare les métriques d'exposition, le nombre de règles de pare-feu, et
les résultats de la validation par capture réseau (pcap), avant/après
application de la politique de micro-segmentation adaptative."""
from __future__ import annotations

from dataclasses import dataclass

from src.firewall.rule_generator import FirewallRule, generate_rules_from_graph
from src.network.exposure_metrics import ExposureReport, build_graph, compute_exposure
from src.network.topology import NetworkTopology
from src.pcap.flow_validator import PcapValidationSummary, summarize_validation, validate_flows
from src.pcap.pcap_analyzer import read_pcap_flows
from src.pcap.pcap_generator import simulate_flows, write_pcap
from src.segmentation.policy_engine import SegmentationPolicy, build_segmented_graph, design_segmentation_policy

CRITICAL_TYPES = {"serveur_base_donnees", "controleur_domaine"}


@dataclass
class SegmentationComparison:
    legacy_exposure: ExposureReport
    segmented_exposure: ExposureReport
    legacy_rules: list[FirewallRule]
    segmented_rules: list[FirewallRule]
    policy: SegmentationPolicy
    pcap_validation: PcapValidationSummary

    @property
    def blast_radius_reduction_pct(self) -> float:
        if self.legacy_exposure.average_blast_radius == 0:
            return 0.0
        delta = self.legacy_exposure.average_blast_radius - self.segmented_exposure.average_blast_radius
        return round(100 * delta / self.legacy_exposure.average_blast_radius, 1)

    @property
    def critical_exposure_reduction(self) -> tuple[int, int]:
        return self.legacy_exposure.critical_hosts_exposed_count, self.segmented_exposure.critical_hosts_exposed_count

    @property
    def critical_direct_exposure_reduction(self) -> tuple[int, int]:
        return (self.legacy_exposure.critical_hosts_directly_exposed_count,
                self.segmented_exposure.critical_hosts_directly_exposed_count)


def run_full_comparison(topology: NetworkTopology, pcap_output_path: str = "capture.pcap") -> SegmentationComparison:
    legacy_graph = build_graph(topology)
    legacy_exposure = compute_exposure(legacy_graph, CRITICAL_TYPES)
    legacy_segment_by_host = {h.host_id: h.zone for h in topology.hosts}
    legacy_rules = generate_rules_from_graph(legacy_graph, legacy_segment_by_host)

    policy = design_segmentation_policy(topology)
    segmented_graph = build_segmented_graph(topology, policy)
    segmented_exposure = compute_exposure(segmented_graph, CRITICAL_TYPES)
    segmented_rules = generate_rules_from_graph(segmented_graph, policy.segment_by_host)

    # Validation par capture réseau simulée (pcap) : génère un trafic
    # simulé (métier légitime + tentatives de mouvement latéral ciblées par
    # reconnaissance), l'écrit dans un vrai fichier .pcap, le relit comme le
    # ferait un analyste avec Wireshark, puis confronte chaque flux observé
    # à la politique de segmentation.
    simulated_flows = simulate_flows(topology, legacy_graph)
    write_pcap(simulated_flows, pcap_output_path)
    observed_flows = read_pcap_flows(pcap_output_path)
    validation_results = validate_flows(observed_flows, simulated_flows, topology, legacy_graph, segmented_graph, policy)
    pcap_validation = summarize_validation(validation_results)

    return SegmentationComparison(
        legacy_exposure=legacy_exposure, segmented_exposure=segmented_exposure,
        legacy_rules=legacy_rules, segmented_rules=segmented_rules, policy=policy,
        pcap_validation=pcap_validation,
    )
