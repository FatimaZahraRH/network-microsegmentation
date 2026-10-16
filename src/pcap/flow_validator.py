"""
Croise les flux RÉELLEMENT extraits d'une capture réseau (.pcap, relue via
scapy) avec la politique de segmentation, pour répondre à la question
opérationnelle centrale : parmi le trafic effectivement observé, combien de
tentatives de mouvement latéral le réseau hérité aurait-il laissé passer,
et combien la segmentation adaptative bloque-t-elle ?

C'est la différence entre un raisonnement purement théorique sur un graphe
et une validation sur un artefact réseau réel -- même si la capture est ici
simulée, le pipeline d'analyse (lecture pcap -> extraction de flux ->
confrontation à une politique) est celui d'une vraie investigation réseau.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from src.network.topology import NetworkTopology
from src.pcap.pcap_analyzer import ObservedFlow
from src.pcap.pcap_generator import SimulatedFlow


@dataclass
class FlowValidationResult:
    src_host_id: str
    dst_host_id: str
    dst_port: int
    is_lateral_movement_attempt: bool
    allowed_by_legacy: bool
    allowed_by_adaptive_segmentation: bool


def _build_ip_lookup(topology: NetworkTopology) -> dict[str, str]:
    return {h.ip_address: h.host_id for h in topology.hosts}


def _build_ground_truth_lookup(simulated_flows: list[SimulatedFlow]) -> dict[tuple, bool]:
    return {
        (f.src_host.ip_address, f.dst_host.ip_address, f.dst_port): f.is_lateral_movement_attempt
        for f in simulated_flows
    }


def validate_flows(
    observed_flows: list[ObservedFlow],
    simulated_flows: list[SimulatedFlow],
    topology: NetworkTopology,
    legacy_graph: nx.Graph,
    segmented_graph: nx.Graph,
    policy,
) -> list[FlowValidationResult]:
    from src.segmentation.policy_engine import is_legitimate_flow

    ip_lookup = _build_ip_lookup(topology)
    type_lookup = {h.host_id: h.host_type for h in topology.hosts}
    ground_truth = _build_ground_truth_lookup(simulated_flows)

    results: list[FlowValidationResult] = []
    for flow in observed_flows:
        src_id = ip_lookup.get(flow.src_ip)
        dst_id = ip_lookup.get(flow.dst_ip)
        if src_id is None or dst_id is None:
            continue

        is_lateral = ground_truth.get((flow.src_ip, flow.dst_ip, flow.dst_port), False)
        allowed_legacy = legacy_graph.has_edge(src_id, dst_id)

        # Si l'une des deux extrémités est en granularité "individuelle"
        # (actif critique), seule une vérification PRÉCISE type+port fait
        # foi -- le graphe agrégé, port-agnostique, ne doit pas servir de
        # filet de secours ici (c'est exactement le second défaut trouvé
        # par cette validation : sans cette restriction, un port illégitime
        # comme SMB/445 seraot accepté au même titre que Kerberos/88, dès
        # lors qu'une arête de type existait entre les deux hôtes).
        src_granularity = policy.granularity_by_host.get(src_id)
        dst_granularity = policy.granularity_by_host.get(dst_id)
        if src_granularity == "individuel" or dst_granularity == "individuel":
            allowed_adaptive = is_legitimate_flow(type_lookup[src_id], type_lookup[dst_id], flow.dst_port)
        else:
            allowed_adaptive = segmented_graph.has_edge(src_id, dst_id)

        results.append(FlowValidationResult(
            src_host_id=src_id, dst_host_id=dst_id, dst_port=flow.dst_port,
            is_lateral_movement_attempt=is_lateral,
            allowed_by_legacy=allowed_legacy, allowed_by_adaptive_segmentation=allowed_adaptive,
        ))

    return results


@dataclass
class PcapValidationSummary:
    n_flows_analyzed: int
    n_lateral_movement_attempts: int
    n_lateral_allowed_by_legacy: int
    n_lateral_blocked_by_adaptive: int
    n_legit_flows_still_allowed_by_adaptive: int
    n_legit_flows_total: int


def summarize_validation(results: list[FlowValidationResult]) -> PcapValidationSummary:
    lateral = [r for r in results if r.is_lateral_movement_attempt]
    legit = [r for r in results if not r.is_lateral_movement_attempt]

    return PcapValidationSummary(
        n_flows_analyzed=len(results),
        n_lateral_movement_attempts=len(lateral),
        n_lateral_allowed_by_legacy=sum(1 for r in lateral if r.allowed_by_legacy),
        n_lateral_blocked_by_adaptive=sum(1 for r in lateral if not r.allowed_by_adaptive_segmentation),
        n_legit_flows_still_allowed_by_adaptive=sum(1 for r in legit if r.allowed_by_adaptive_segmentation),
        n_legit_flows_total=len(legit),
    )
