"""
Analyse une capture réseau (.pcap) et en extrait les flux (5-tuple
src_ip/dst_ip/src_port/dst_port/protocole) -- la première étape de tout
travail d'investigation réseau réel, qu'on utilise Wireshark manuellement ou
un pipeline automatisé.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ObservedFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str


def read_pcap_flows(pcap_path: str) -> list[ObservedFlow]:
    from scapy.all import IP, TCP, rdpcap

    packets = rdpcap(pcap_path)
    flows: list[ObservedFlow] = []

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            flows.append(ObservedFlow(
                src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                src_port=int(pkt[TCP].sport), dst_port=int(pkt[TCP].dport),
                protocol="TCP",
            ))

    return flows
