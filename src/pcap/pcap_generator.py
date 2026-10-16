"""
Génère un fichier de capture réseau (.pcap) RÉEL et ouvrable dans Wireshark,
via scapy -- construit à partir de la topologie réseau, avec deux
catégories de flux :

  1. Trafic métier légitime, calqué sur les connexions effectivement
     autorisées par le réseau (ports réalistes : HTTPS pour la DMZ,
     requêtes SQL pour les accès base de données, LDAP/Kerberos pour
     l'authentification auprès des contrôleurs de domaine).
  2. Tentatives de mouvement latéral simulées : un poste utilisateur
     compromis qui tente d'atteindre directement une base de données ou un
     contrôleur de domaine (SMB/445), en contournant l'architecture
     applicative normale -- le scénario exact que la micro-segmentation
     doit empêcher.

La vérité terrain (quel flux est légitime vs suspect) est connue puisque
c'est ce générateur qui la construit -- même principe que mes autres
projets (Mini-DSPM, SOC Alert Triage) : un corpus de test où le label
correct est maîtrisé, indispensable pour une évaluation rigoureuse.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from src.config import RANDOM_SEED
from src.network.topology import Host, NetworkTopology

_LEGIT_PORTS = {
    ("serveur_exposition_externe", "serveur_applicatif"): 443,
    ("serveur_applicatif", "serveur_base_donnees"): 5432,
    ("serveur_applicatif", "controleur_domaine"): 389,
    ("poste_utilisateur", "serveur_applicatif"): 443,
    ("poste_utilisateur", "controleur_domaine"): 88,  # Kerberos (authentification normale)
}

# Ports typiquement ciblés lors d'un mouvement latéral (accès direct à une
# ressource sensible en contournant le tiers applicatif normal).
_LATERAL_MOVEMENT_PORTS = {
    "serveur_base_donnees": 5432,
    "controleur_domaine": 445,  # SMB -- technique classique (pass-the-hash, etc.)
}


@dataclass
class SimulatedFlow:
    src_host: Host
    dst_host: Host
    src_port: int
    dst_port: int
    is_lateral_movement_attempt: bool  # vérité terrain


def _find_legit_port(src: Host, dst: Host) -> int | None:
    return _LEGIT_PORTS.get((src.host_type, dst.host_type))


def simulate_flows(
    topology: NetworkTopology, legacy_graph, n_legit: int = 40, n_lateral_movement: int = 6,
) -> list[SimulatedFlow]:
    """`legacy_graph` (networkx.Graph) est utilisé pour cibler les
    tentatives de mouvement latéral de façon réaliste : un attaquant ne
    choisit pas une cible au hasard, il vise en priorité les hôtes qu'une
    reconnaissance préalable (scan, énumération) lui a révélés comme
    effectivement atteignables dans le réseau hérité."""
    rng = random.Random(RANDOM_SEED + 1)
    hosts_by_type: dict[str, list[Host]] = {}
    for h in topology.hosts:
        hosts_by_type.setdefault(h.host_type, []).append(h)
    host_by_id = {h.host_id: h for h in topology.hosts}

    flows: list[SimulatedFlow] = []

    # --- Trafic métier légitime ---
    legit_pairs = list(_LEGIT_PORTS.keys())
    attempts = 0
    while len(flows) < n_legit and attempts < n_legit * 20:
        attempts += 1
        src_type, dst_type = rng.choice(legit_pairs)
        if src_type not in hosts_by_type or dst_type not in hosts_by_type:
            continue
        src = rng.choice(hosts_by_type[src_type])
        dst = rng.choice(hosts_by_type[dst_type])
        port = _find_legit_port(src, dst)
        if port is None:
            continue
        flows.append(SimulatedFlow(
            src_host=src, dst_host=dst, src_port=rng.randint(40000, 60000),
            dst_port=port, is_lateral_movement_attempt=False,
        ))

    # --- Tentatives de mouvement latéral ---
    # Priorité aux paires déjà directement joignables dans le réseau hérité
    # (scénario réaliste : l'attaquant cible ce que sa reconnaissance a
    # révélé comme atteignable) ; complété par des cibles aléatoires pour
    # la diversité si pas assez de paires exploitables trouvées.
    exploitable_pairs: list[tuple[Host, Host, int]] = []
    for target_type, port in _LATERAL_MOVEMENT_PORTS.items():
        for target_host in hosts_by_type.get(target_type, []):
            if target_host.host_id not in legacy_graph:
                continue
            for neighbor_id in legacy_graph.neighbors(target_host.host_id):
                neighbor = host_by_id[neighbor_id]
                if neighbor.host_type == "poste_utilisateur":
                    exploitable_pairs.append((neighbor, target_host, port))

    rng.shuffle(exploitable_pairs)
    n_from_recon = min(n_lateral_movement, len(exploitable_pairs))
    for src, dst, port in exploitable_pairs[:n_from_recon]:
        flows.append(SimulatedFlow(
            src_host=src, dst_host=dst, src_port=rng.randint(40000, 60000),
            dst_port=port, is_lateral_movement_attempt=True,
        ))

    # Complément aléatoire si la reconnaissance n'a pas fourni assez de cibles.
    remaining = n_lateral_movement - n_from_recon
    user_hosts = hosts_by_type.get("poste_utilisateur", [])
    for _ in range(max(0, remaining)):
        target_type = rng.choice(list(_LATERAL_MOVEMENT_PORTS.keys()))
        if target_type not in hosts_by_type or not user_hosts:
            continue
        src = rng.choice(user_hosts)
        dst = rng.choice(hosts_by_type[target_type])
        flows.append(SimulatedFlow(
            src_host=src, dst_host=dst, src_port=rng.randint(40000, 60000),
            dst_port=_LATERAL_MOVEMENT_PORTS[target_type], is_lateral_movement_attempt=True,
        ))

    rng.shuffle(flows)
    return flows


def write_pcap(flows: list[SimulatedFlow], output_path: str) -> None:
    """Écrit un fichier .pcap réel (format binaire standard), directement
    ouvrable dans Wireshark -- chaque flux devient un paquet TCP SYN
    minimal mais structurellement valide (en-têtes Ethernet/IP/TCP réels)."""
    from scapy.all import IP, TCP, Ether, wrpcap

    packets = []
    for flow in flows:
        pkt = (
            Ether()
            / IP(src=flow.src_host.ip_address, dst=flow.dst_host.ip_address)
            / TCP(sport=flow.src_port, dport=flow.dst_port, flags="S")
        )
        packets.append(pkt)

    wrpcap(output_path, packets)
