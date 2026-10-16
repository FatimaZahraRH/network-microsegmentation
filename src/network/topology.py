"""
Génère une topologie réseau d'entreprise synthétique mais réaliste : un
réseau "hérité" (legacy) faiblement segmenté, où la plupart des hôtes d'une
même zone peuvent communiquer librement entre eux -- la situation typique
qui motive un projet de micro-segmentation (cf. docs/methodology_notes.md).

Chaque hôte porte un type (poste utilisateur, serveur applicatif, base de
données, contrôleur de domaine, serveur exposé) qui détermine sa criticité
et sert ensuite au moteur de segmentation à granularité adaptative.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from src.config import RANDOM_SEED


@dataclass
class Host:
    host_id: str
    host_type: str
    zone: str
    ip_address: str = ""


@dataclass
class NetworkTopology:
    hosts: list[Host] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)


_ZONES = {
    "DMZ": {"n_hosts": 4, "types": ["serveur_exposition_externe"], "subnet": "10.10.1"},
    "Utilisateurs": {"n_hosts": 25, "types": ["poste_utilisateur"], "subnet": "10.10.2"},
    "Applicatif": {"n_hosts": 10, "types": ["serveur_applicatif"], "subnet": "10.10.3"},
    "Donnees": {"n_hosts": 5, "types": ["serveur_base_donnees"], "subnet": "10.10.4"},
    "Annuaire": {"n_hosts": 2, "types": ["controleur_domaine"], "subnet": "10.10.5"},
}


def generate_legacy_topology() -> NetworkTopology:
    """Réseau hérité : forte connectivité interne à chaque zone (quasi
    maillage complet), et des passerelles inter-zones larges plutôt que
    ciblées -- reflète une segmentation par VLAN large plutôt qu'une
    politique fine par hôte."""
    _rng = random.Random(RANDOM_SEED)  # RNG local et re-seedé à chaque appel
    # pour garantir un résultat reproductible indépendamment de l'ordre
    # ou du nombre d'appels précédents (bug corrigé : un RNG module-level
    # partagé produisait des résultats différents au 2e appel).
    topology = NetworkTopology()

    for zone, cfg in _ZONES.items():
        for i in range(cfg["n_hosts"]):
            host_type = _rng.choice(cfg["types"])
            ip = f"{cfg['subnet']}.{i + 10}"
            topology.hosts.append(Host(host_id=f"{zone}-{i:02d}", host_type=host_type, zone=zone, ip_address=ip))

    hosts_by_zone: dict[str, list[Host]] = {}
    for h in topology.hosts:
        hosts_by_zone.setdefault(h.zone, []).append(h)

    for zone, hosts in hosts_by_zone.items():
        for i, h1 in enumerate(hosts):
            for h2 in hosts[i + 1:]:
                if _rng.random() < 0.85:
                    topology.edges.append((h1.host_id, h2.host_id))

    inter_zone_pairs = [
        ("DMZ", "Applicatif"), ("Applicatif", "Utilisateurs"),
        ("Applicatif", "Donnees"), ("Utilisateurs", "Annuaire"),
        ("Applicatif", "Annuaire"),
    ]
    for zone_a, zone_b in inter_zone_pairs:
        hosts_a, hosts_b = hosts_by_zone[zone_a], hosts_by_zone[zone_b]
        bridge_a = _rng.sample(hosts_a, k=min(3, len(hosts_a)))
        bridge_b = _rng.sample(hosts_b, k=min(3, len(hosts_b)))
        for ha in bridge_a:
            for hb in bridge_b:
                topology.edges.append((ha.host_id, hb.host_id))

    return topology
