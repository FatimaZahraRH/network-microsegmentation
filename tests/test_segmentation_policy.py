"""Tests unitaires du moteur de segmentation adaptative et de la comparaison globale."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation.metrics import run_full_comparison
from src.network.topology import generate_legacy_topology
from src.segmentation.policy_engine import (
    LEGITIMATE_TYPE_FLOWS,
    build_segmented_graph,
    design_segmentation_policy,
    is_legitimate_flow,
)


class TestSegmentationPolicy:
    def test_critical_hosts_get_individual_granularity(self):
        topo = generate_legacy_topology()
        policy = design_segmentation_policy(topo)
        db_hosts = [h for h in topo.hosts if h.host_type == "serveur_base_donnees"]
        for h in db_hosts:
            assert policy.granularity_by_host[h.host_id] == "individuel"

    def test_user_workstations_get_large_granularity(self):
        topo = generate_legacy_topology()
        policy = design_segmentation_policy(topo)
        user_hosts = [h for h in topo.hosts if h.host_type == "poste_utilisateur"]
        for h in user_hosts:
            assert policy.granularity_by_host[h.host_id] == "large"

    def test_individual_hosts_have_unique_segments(self):
        topo = generate_legacy_topology()
        policy = design_segmentation_policy(topo)
        individual_hosts = [h_id for h_id, g in policy.granularity_by_host.items() if g == "individuel"]
        segments = [policy.segment_by_host[h_id] for h_id in individual_hosts]
        assert len(segments) == len(set(segments))


class TestSegmentedGraph:
    def test_individual_hosts_only_reachable_via_legitimate_type_pairs(self):
        topo = generate_legacy_topology()
        policy = design_segmentation_policy(topo)
        graph = build_segmented_graph(topo, policy)
        host_by_id = {h.host_id: h for h in topo.hosts}

        individual_hosts = [h_id for h_id, g in policy.granularity_by_host.items() if g == "individuel"]
        for h_id in individual_hosts:
            host_type = host_by_id[h_id].host_type
            for neighbor_id in graph.neighbors(h_id):
                neighbor_type = host_by_id[neighbor_id].host_type
                pair = (host_type, neighbor_type)
                assert pair in LEGITIMATE_TYPE_FLOWS or (pair[1], pair[0]) in LEGITIMATE_TYPE_FLOWS

    def test_individual_hosts_not_connected_to_illegitimate_types(self):
        topo = generate_legacy_topology()
        policy = design_segmentation_policy(topo)
        graph = build_segmented_graph(topo, policy)
        host_by_id = {h.host_id: h for h in topo.hosts}

        db_hosts = [h.host_id for h in topo.hosts if h.host_type == "serveur_base_donnees"]
        for db_id in db_hosts:
            for neighbor_id in graph.neighbors(db_id):
                assert host_by_id[neighbor_id].host_type != "poste_utilisateur"


class TestIsLegitimateFlow:
    def test_kerberos_to_domain_controller_is_legitimate(self):
        assert is_legitimate_flow("poste_utilisateur", "controleur_domaine", 88) is True

    def test_smb_to_domain_controller_is_not_legitimate(self):
        assert is_legitimate_flow("poste_utilisateur", "controleur_domaine", 445) is False

    def test_direct_user_to_database_is_never_legitimate(self):
        assert is_legitimate_flow("poste_utilisateur", "serveur_base_donnees", 5432) is False

    def test_applicatif_to_database_is_legitimate_on_correct_port(self):
        assert is_legitimate_flow("serveur_applicatif", "serveur_base_donnees", 5432) is True


class TestFullComparison:
    def test_direct_critical_exposure_not_worse_than_legacy(self):
        topo = generate_legacy_topology()
        comparison = run_full_comparison(topo, pcap_output_path="test_comparison.pcap")
        before, after = comparison.critical_direct_exposure_reduction
        assert after <= before

    def test_pcap_validation_blocks_all_lateral_movement(self):
        topo = generate_legacy_topology()
        comparison = run_full_comparison(topo, pcap_output_path="test_comparison.pcap")
        pv = comparison.pcap_validation
        assert pv.n_lateral_blocked_by_adaptive == pv.n_lateral_movement_attempts
        assert pv.n_lateral_movement_attempts > 0

    def test_pcap_validation_preserves_all_legitimate_business_flows(self):
        topo = generate_legacy_topology()
        comparison = run_full_comparison(topo, pcap_output_path="test_comparison.pcap")
        pv = comparison.pcap_validation
        assert pv.n_legit_flows_still_allowed_by_adaptive == pv.n_legit_flows_total


class TestSegmentationIsAFilter:
    """Défaut n°3 : une segmentation ne doit jamais AJOUTER de connexion."""

    def test_segmented_graph_is_subset_of_legacy(self):
        from src.network.exposure_metrics import build_graph
        topo = generate_legacy_topology()
        legacy = {frozenset(e) for e in build_graph(topo).edges}
        segmented = {frozenset(e) for e in build_segmented_graph(topo, design_segmentation_policy(topo)).edges}
        assert segmented <= legacy

    def test_no_workstation_to_workstation_traffic(self):
        topo = generate_legacy_topology()
        graph = build_segmented_graph(topo, design_segmentation_policy(topo))
        host_by_id = {h.host_id: h for h in topo.hosts}
        for u, v in graph.edges:
            assert not (host_by_id[u].host_type == "poste_utilisateur"
                        and host_by_id[v].host_type == "poste_utilisateur")

    def test_direct_blast_radius_decreases_after_segmentation(self):
        topo = generate_legacy_topology()
        comparison = run_full_comparison(topo, pcap_output_path="test_comparison.pcap")
        assert (comparison.segmented_exposure.average_direct_blast_radius
                < comparison.legacy_exposure.average_direct_blast_radius)
