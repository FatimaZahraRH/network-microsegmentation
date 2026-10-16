"""Tests unitaires du générateur de règles de pare-feu."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation.metrics import run_full_comparison
from src.firewall.rule_generator import generate_rules_from_graph
from src.network.topology import generate_legacy_topology
from src.segmentation.policy_engine import build_segmented_graph, design_segmentation_policy


class TestRuleGenerator:
    def test_generates_rules_for_segmented_network(self):
        topo = generate_legacy_topology()
        policy = design_segmentation_policy(topo)
        graph = build_segmented_graph(topo, policy)
        rules = generate_rules_from_graph(graph, policy.segment_by_host)
        assert len(rules) > 0

    def test_no_duplicate_segment_pairs(self):
        topo = generate_legacy_topology()
        policy = design_segmentation_policy(topo)
        graph = build_segmented_graph(topo, policy)
        rules = generate_rules_from_graph(graph, policy.segment_by_host)
        pairs = [(r.source_segment, r.destination_segment) for r in rules]
        assert len(pairs) == len(set(pairs))

    def test_adaptive_rules_are_more_precise_not_necessarily_fewer(self):
        """Point d'honnêteté : contrairement à une première version de ce
        projet, la segmentation adaptative corrigée (avec exceptions
        point-à-point légitimes) ne réduit plus nécessairement le nombre
        brut de règles -- elle les rend plus précises (par type ET port).
        Ce test vérifie juste que des règles sont bien générées, sans
        prétendre à une réduction qui n'est plus la réalité mesurée."""
        topo = generate_legacy_topology()
        comparison = run_full_comparison(topo, pcap_output_path="test_rules.pcap")
        assert len(comparison.segmented_rules) > 0
        assert len(comparison.legacy_rules) > 0
