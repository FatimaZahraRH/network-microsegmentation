"""Tests unitaires de la topologie réseau et des métriques d'exposition."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.network.exposure_metrics import build_graph, compute_exposure
from src.network.topology import generate_legacy_topology


class TestTopologyGeneration:
    def test_generates_expected_host_count(self):
        topo = generate_legacy_topology()
        assert len(topo.hosts) == 46

    def test_all_host_types_present(self):
        topo = generate_legacy_topology()
        types = {h.host_type for h in topo.hosts}
        assert "serveur_base_donnees" in types
        assert "controleur_domaine" in types
        assert "poste_utilisateur" in types

    def test_reproducible_with_fixed_seed(self):
        topo1 = generate_legacy_topology()
        topo2 = generate_legacy_topology()
        assert len(topo1.edges) == len(topo2.edges)


class TestExposureMetrics:
    def test_legacy_network_has_high_blast_radius(self):
        topo = generate_legacy_topology()
        graph = build_graph(topo)
        exposure = compute_exposure(graph, critical_types={"serveur_base_donnees"})
        assert exposure.average_blast_radius > 10

    def test_isolated_host_has_zero_blast_radius(self):
        import networkx as nx
        graph = nx.Graph()
        graph.add_node("isolated-01", host_type="poste_utilisateur", zone="Test")
        exposure = compute_exposure(graph, critical_types=set())
        assert exposure.blast_radius_by_host["isolated-01"] == 0

    def test_critical_hosts_exposed_detects_reachability(self):
        import networkx as nx
        graph = nx.Graph()
        graph.add_node("user-01", host_type="poste_utilisateur", zone="A")
        graph.add_node("db-01", host_type="serveur_base_donnees", zone="A")
        graph.add_edge("user-01", "db-01")
        exposure = compute_exposure(graph, critical_types={"serveur_base_donnees"})
        assert exposure.critical_hosts_exposed_count == 1

    def test_no_exposure_when_critical_host_isolated(self):
        import networkx as nx
        graph = nx.Graph()
        graph.add_node("user-01", host_type="poste_utilisateur", zone="A")
        graph.add_node("db-01", host_type="serveur_base_donnees", zone="B")
        exposure = compute_exposure(graph, critical_types={"serveur_base_donnees"})
        assert exposure.critical_hosts_exposed_count == 0
