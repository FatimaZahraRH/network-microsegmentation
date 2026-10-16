"""
Génère des règles de pare-feu concrètes (format allow-list simplifié) à
partir de la politique de segmentation -- transforme une décision de
granularité en artefact directement exploitable par une équipe réseau,
plutôt que de rester à un niveau purement conceptuel.

Point méthodologique documenté dans la littérature (cf.
docs/methodology_notes.md) : une micro-segmentation trop fine fait exploser
le nombre de règles à maintenir ("rule explosion"), un problème opérationnel
réel signalé par plusieurs études de terrain. Ce module permet de mesurer
ce compromis explicitement plutôt que de l'ignorer.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx


@dataclass
class FirewallRule:
    rule_id: str
    source_segment: str
    destination_segment: str
    action: str
    justification: str


def generate_rules_from_graph(graph: nx.Graph, segment_by_host: dict[str, str]) -> list[FirewallRule]:
    segment_pairs_seen: set[tuple[str, str]] = set()
    rules: list[FirewallRule] = []
    rule_counter = 1

    for u, v in graph.edges:
        seg_u, seg_v = segment_by_host[u], segment_by_host[v]
        pair = tuple(sorted((seg_u, seg_v)))
        if pair in segment_pairs_seen:
            continue
        segment_pairs_seen.add(pair)

        rules.append(FirewallRule(
            rule_id=f"FW-{rule_counter:04d}",
            source_segment=pair[0],
            destination_segment=pair[1],
            action="ALLOW",
            justification="Flux métier légitime identifié" if pair[0] != pair[1] else "Communication intra-segment",
        ))
        rule_counter += 1

    return rules
