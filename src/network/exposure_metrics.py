"""
Construction du graphe réseau et calcul des métriques d'exposition --
inspiré du cadre d'évaluation de Basta, N. et al. (2021), "Towards a
Zero-Trust Micro-segmentation Network Security Strategy: An Evaluation
Framework" (arXiv:2111.10967), qui propose d'évaluer la connectivité réseau
via un graphe pour quantifier l'exposition et la robustesse.

Métrique principale : le **rayon de compromission** (blast radius) d'un
hôte -- le nombre d'autres hôtes qu'un attaquant pourrait atteindre s'il
compromettait ce point d'entrée, en suivant uniquement les connexions
autorisées. C'est la mesure la plus directement actionnable pour un
architecte réseau : elle répond à la question "si CET hôte tombe, jusqu'où
l'attaquant peut-il aller ?"
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from src.network.topology import NetworkTopology


def build_graph(topology: NetworkTopology) -> nx.Graph:
    graph = nx.Graph()
    for host in topology.hosts:
        graph.add_node(host.host_id, host_type=host.host_type, zone=host.zone)
    graph.add_edges_from(topology.edges)
    return graph


@dataclass
class ExposureReport:
    blast_radius_by_host: dict[str, int]
    average_blast_radius: float
    max_blast_radius: int
    critical_hosts_exposed_count: int  # nb d'hôtes critiques atteignables depuis AU MOINS un poste utilisateur
    direct_blast_radius_by_host: dict[str, int]
    average_direct_blast_radius: float
    critical_hosts_directly_exposed_count: int  # nb d'hôtes critiques directement voisins d'un poste utilisateur


def compute_exposure(graph: nx.Graph, critical_types: set[str]) -> ExposureReport:
    """Calcule deux niveaux de "rayon de compromission" :

    - **Direct** (`direct_blast_radius`, = degré du nœud) : le nombre
      d'hôtes qu'un attaquant peut atteindre EN UN SEUL SAUT depuis l'hôte
      compromis, sans avoir à compromettre d'hôte intermédiaire au préalable.
      C'est la métrique directement pilotée par une politique de
      segmentation/pare-feu -- une règle contrôle des connexions directes,
      pas des chemins transitifs.
    - **Transitif** (`blast_radius`, = composante connexe complète) :
      l'ensemble des hôtes atteignables en supposant qu'un attaquant puisse
      pivoter librement à travers chaque hôte intermédiaire du chemin. Cette
      hypothèse est PESSIMISTE : elle traite chaque saut comme trivialement
      franchissable, alors qu'en réalité chaque hôte intermédiaire doit être
      lui-même compromis. C'est précisément la limite que la littérature
      (Basta et al., 2021) résout avec un second graphe dédié -- un graphe
      d'attaque pondéré par l'exploitabilité de chaque saut -- plutôt qu'un
      unique graphe de connectivité. Ce projet ne modélise pas ce second
      graphe (cf. limites, docs/methodology_notes.md) ; le rayon transitif
      est donc conservé à titre indicatif, mais le rayon DIRECT est la
      métrique principale de ce rapport, car directement actionnable par
      une politique de segmentation.
    """
    blast_radius: dict[str, int] = {}
    direct_blast_radius: dict[str, int] = {}
    for node in graph.nodes:
        reachable = nx.node_connected_component(graph, node)
        blast_radius[node] = len(reachable) - 1
        direct_blast_radius[node] = graph.degree(node)

    critical_nodes = {n for n, d in graph.nodes(data=True) if d.get("host_type") in critical_types}
    user_nodes = {n for n, d in graph.nodes(data=True) if d.get("host_type") == "poste_utilisateur"}

    exposed_critical_transitive = set()
    exposed_critical_direct = set()
    for user_node in user_nodes:
        reachable = nx.node_connected_component(graph, user_node)
        exposed_critical_transitive |= (reachable & critical_nodes)
        direct_neighbors = set(graph.neighbors(user_node))
        exposed_critical_direct |= (direct_neighbors & critical_nodes)

    values = list(blast_radius.values())
    direct_values = list(direct_blast_radius.values())
    return ExposureReport(
        blast_radius_by_host=blast_radius,
        average_blast_radius=round(sum(values) / len(values), 2) if values else 0.0,
        max_blast_radius=max(values) if values else 0,
        critical_hosts_exposed_count=len(exposed_critical_transitive),
        direct_blast_radius_by_host=direct_blast_radius,
        average_direct_blast_radius=round(sum(direct_values) / len(direct_values), 2) if direct_values else 0.0,
        critical_hosts_directly_exposed_count=len(exposed_critical_direct),
    )
