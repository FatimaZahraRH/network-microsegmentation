"""Tests unitaires du module de capture réseau (pcap) : génération, lecture,
et validation de flux contre la politique de segmentation."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.network.exposure_metrics import build_graph
from src.network.topology import generate_legacy_topology
from src.pcap.pcap_analyzer import read_pcap_flows
from src.pcap.pcap_generator import simulate_flows, write_pcap
from src.pcap.flow_validator import summarize_validation, validate_flows
from src.segmentation.policy_engine import build_segmented_graph, design_segmentation_policy

_TEST_PCAP_PATH = "test_unit.pcap"


def teardown_module(module):
    if os.path.exists(_TEST_PCAP_PATH):
        os.remove(_TEST_PCAP_PATH)


class TestPcapGeneration:
    def test_simulate_flows_produces_legit_and_lateral_movement(self):
        topo = generate_legacy_topology()
        legacy_graph = build_graph(topo)
        flows = simulate_flows(topo, legacy_graph)
        assert any(not f.is_lateral_movement_attempt for f in flows)
        assert any(f.is_lateral_movement_attempt for f in flows)

    def test_write_pcap_creates_valid_file(self):
        topo = generate_legacy_topology()
        legacy_graph = build_graph(topo)
        flows = simulate_flows(topo, legacy_graph)
        write_pcap(flows, _TEST_PCAP_PATH)
        assert os.path.exists(_TEST_PCAP_PATH)
        assert os.path.getsize(_TEST_PCAP_PATH) > 0


class TestPcapAnalysis:
    def test_read_pcap_flows_recovers_all_packets(self):
        topo = generate_legacy_topology()
        legacy_graph = build_graph(topo)
        flows = simulate_flows(topo, legacy_graph)
        write_pcap(flows, _TEST_PCAP_PATH)
        observed = read_pcap_flows(_TEST_PCAP_PATH)
        assert len(observed) == len(flows)

    def test_observed_flows_match_source_ips(self):
        topo = generate_legacy_topology()
        legacy_graph = build_graph(topo)
        flows = simulate_flows(topo, legacy_graph)
        write_pcap(flows, _TEST_PCAP_PATH)
        observed = read_pcap_flows(_TEST_PCAP_PATH)
        observed_ips = {f.src_ip for f in observed}
        expected_ips = {f.src_host.ip_address for f in flows}
        assert observed_ips == expected_ips


class TestFlowValidation:
    def test_lateral_movement_flagged_as_allowed_by_legacy(self):
        topo = generate_legacy_topology()
        legacy_graph = build_graph(topo)
        policy = design_segmentation_policy(topo)
        segmented_graph = build_segmented_graph(topo, policy)

        flows = simulate_flows(topo, legacy_graph)
        write_pcap(flows, _TEST_PCAP_PATH)
        observed = read_pcap_flows(_TEST_PCAP_PATH)

        results = validate_flows(observed, flows, topo, legacy_graph, segmented_graph, policy)
        lateral_results = [r for r in results if r.is_lateral_movement_attempt]
        assert len(lateral_results) > 0
        assert all(r.allowed_by_legacy for r in lateral_results)

    def test_lateral_movement_blocked_by_adaptive_segmentation(self):
        topo = generate_legacy_topology()
        legacy_graph = build_graph(topo)
        policy = design_segmentation_policy(topo)
        segmented_graph = build_segmented_graph(topo, policy)

        flows = simulate_flows(topo, legacy_graph)
        write_pcap(flows, _TEST_PCAP_PATH)
        observed = read_pcap_flows(_TEST_PCAP_PATH)

        results = validate_flows(observed, flows, topo, legacy_graph, segmented_graph, policy)
        lateral_results = [r for r in results if r.is_lateral_movement_attempt]
        assert all(not r.allowed_by_adaptive_segmentation for r in lateral_results)

    def test_summarize_validation_counts_correctly(self):
        topo = generate_legacy_topology()
        legacy_graph = build_graph(topo)
        policy = design_segmentation_policy(topo)
        segmented_graph = build_segmented_graph(topo, policy)

        flows = simulate_flows(topo, legacy_graph)
        write_pcap(flows, _TEST_PCAP_PATH)
        observed = read_pcap_flows(_TEST_PCAP_PATH)

        results = validate_flows(observed, flows, topo, legacy_graph, segmented_graph, policy)
        summary = summarize_validation(results)
        assert summary.n_flows_analyzed == len(results)
        assert summary.n_lateral_movement_attempts + summary.n_legit_flows_total == summary.n_flows_analyzed
