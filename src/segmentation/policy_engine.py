"""
Moteur de micro-segmentation à granularité adaptative -- inspiré de la
méthodologie proposée dans *"Network microsegmentation design methodology
in zero-trust architecture"* (CEUR-WS Vol-4024, 2025), qui préconise une
granularité de segmentation VARIABLE selon la criticité de chaque hôte
plutôt qu'un seul niveau de segmentation appliqué uniformément partout.

Principe : un hôte critique (base de données, contrôleur de domaine) reçoit
son propre micro-segment individuel (granularité fine). Un poste utilisateur
standard reste regroupé avec ses pairs (granularité grossière). Même
principe de pondération contextuelle que mes autres projets, appliqué ici à
une décision de granularité réseau plutôt qu'à un score de risque applicatif.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from src.config import HOST_CRITICALITY_WEIGHTS
from src.network.topology import NetworkTopology

_GRANULARITY_THRESHOLDS = [
    (4.0, "individuel"),
    (2.0, "restreint"),
    (0.0, "large"),
]


def _granularity_for(host_type: str) -> str:
    weight = HOST_CRITICALITY_WEIGHTS.get(host_type, 1.0)
    for threshold, granularity in _GRANULARITY_THRESHOLDS:
        if weight >= threshold:
            return granularity
    return "large"


_LEGITIMATE_ZONE_FLOWS = {
    ("Utilisateurs", "Applicatif"),
    ("Applicatif", "Donnees"),
    ("Applicatif", "Annuaire"),
    ("DMZ", "Applicatif"),
    ("Utilisateurs", "Annuaire"),
}

# Flux métier légitimes par PAIRE DE TYPES **ET PORT AUTORISÉ**, utilisés
# comme exceptions explicites d'accès point-à-point aux hôtes en
# granularité "individuelle". Un premier correctif de ce moteur autorisait
# la paire de types sans vérifier le port -- ce qui laissait passer une
# attaque SMB/445 vers un contrôleur de domaine aussi facilement qu'une
# authentification Kerberos/88 légitime, puisque les deux partagent la même
# paire de types (poste_utilisateur, controleur_domaine). Ce second défaut a
# lui aussi été détecté en validant la politique contre un trafic réseau
# réellement capturé (cf. src/pcap/) : une vraie règle de pare-feu filtre
# par port, pas seulement par zone/segment -- corrigé ici en conséquence.
LEGITIMATE_TYPE_FLOWS_WITH_PORTS: dict[tuple[str, str], set[int]] = {
    ("poste_utilisateur", "serveur_applicatif"): {443},
    ("serveur_applicatif", "serveur_base_donnees"): {5432},
    ("serveur_applicatif", "controleur_domaine"): {389},
    ("poste_utilisateur", "controleur_domaine"): {88},  # Kerberos SEULEMENT -- pas SMB/445
    ("serveur_exposition_externe", "serveur_applicatif"): {443},
}

# Dérivé du dict ci-dessus : ensemble des paires de types légitimes, sans le
# détail des ports -- utilisé pour la construction du graphe agrégé
# (blast radius), qui reste par nature une approximation au niveau du type
# d'hôte plutôt qu'au niveau du port (limite documentée dans
# docs/methodology_notes.md : le graphe de connectivité ne remplace pas une
# vraie règle de pare-feu port-précise, c'est le rôle de
# `is_legitimate_flow` ci-dessous et du module src/pcap/ qui l'utilise).
LEGITIMATE_TYPE_FLOWS = set(LEGITIMATE_TYPE_FLOWS_WITH_PORTS.keys())


def _is_legitimate_type_pair(type_a: str, type_b: str) -> bool:
    return (type_a, type_b) in LEGITIMATE_TYPE_FLOWS or (type_b, type_a) in LEGITIMATE_TYPE_FLOWS


def is_legitimate_flow(type_a: str, type_b: str, port: int) -> bool:
    """Vérification PRÉCISE (type de paire + port), utilisée pour valider un
    flux réseau réel observé -- contrairement à `_is_legitimate_type_pair`,
    utilisée uniquement pour la construction du graphe agrégé."""
    allowed_ports = LEGITIMATE_TYPE_FLOWS_WITH_PORTS.get((type_a, type_b)) or \
        LEGITIMATE_TYPE_FLOWS_WITH_PORTS.get((type_b, type_a))
    return allowed_ports is not None and port in allowed_ports


@dataclass
class SegmentationPolicy:
    segment_by_host: dict[str, str]
    granularity_by_host: dict[str, str]


def design_segmentation_policy(topology: NetworkTopology) -> SegmentationPolicy:
    segment_by_host: dict[str, str] = {}
    granularity_by_host: dict[str, str] = {}

    for host in topology.hosts:
        granularity = _granularity_for(host.host_type)
        granularity_by_host[host.host_id] = granularity

        if granularity == "individuel":
            segment_id = f"seg-{host.host_id}"
        elif granularity == "restreint":
            segment_id = f"seg-{host.zone}-{host.host_type}"
        else:
            segment_id = f"seg-{host.zone}"

        segment_by_host[host.host_id] = segment_id

    return SegmentationPolicy(segment_by_host=segment_by_host, granularity_by_host=granularity_by_host)


def build_segmented_graph(topology: NetworkTopology, policy: SegmentationPolicy) -> nx.Graph:
    """Reconstruit le graphe réseau en n'autorisant QUE les connexions
    légitimes : à l'intérieur d'un même segment, entre segments dont les
    zones ont un flux métier justifié, OU -- pour un hôte en granularité
    individuelle -- via une exception point-à-point explicite correspondant
    à un besoin métier réel (cf. LEGITIMATE_TYPE_FLOWS)."""
    graph = nx.Graph()
    for host in topology.hosts:
        graph.add_node(host.host_id, host_type=host.host_type, zone=host.zone)

    hosts = topology.hosts
    legit_zone_pairs = {tuple(sorted(p)) for p in _LEGITIMATE_ZONE_FLOWS}

    for i, h1 in enumerate(hosts):
        for h2 in hosts[i + 1:]:
            g1, g2 = policy.granularity_by_host[h1.host_id], policy.granularity_by_host[h2.host_id]

            if g1 == "individuel" or g2 == "individuel":
                # Exception explicite : seul un besoin métier reconnu ouvre
                # un accès point-à-point vers un actif en granularité
                # individuelle -- tout le reste reste bloqué.
                if _is_legitimate_type_pair(h1.host_type, h2.host_type):
                    graph.add_edge(h1.host_id, h2.host_id)
                continue

            same_segment = policy.segment_by_host[h1.host_id] == policy.segment_by_host[h2.host_id]
            zone_pair = tuple(sorted((h1.zone, h2.zone)))
            legit_flow = zone_pair in legit_zone_pairs

            if same_segment or (legit_flow and h1.zone != h2.zone):
                graph.add_edge(h1.host_id, h2.host_id)

    return graph
