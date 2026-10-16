# Network Microsegmentation — Segmentation Adaptative, Validée sur Capture Réseau Simulée

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white) ![Tests](https://img.shields.io/badge/tests-29%20passed-brightgreen) ![Licence](https://img.shields.io/badge/licence-MIT-blue)

**Simulateur de micro-segmentation réseau à granularité adaptative, fondé sur la recherche académique, avec génération de règles de pare-feu et validation sur un fichier de capture réseau (.pcap généré avec scapy, ouvrable dans Wireshark).**

> **En bref** — un réseau « à plat » laisse un attaquant rebondir de machine en machine. Ce projet modélise un réseau hérité sous forme de graphe, calcule une politique de micro-segmentation adaptée à la criticité de chaque actif, en tire des règles de pare-feu précises au port près, puis rejoue un vrai fichier `.pcap` (ouvrable dans Wireshark) pour vérifier que la politique bloque l'attaque sans casser le trafic métier.
>
> **6/6 mouvements latéraux bloqués · 40/40 flux métier préservés** · 2 défauts de conception révélés par la capture et corrigés · 29 tests.

---

## 🎯 Le problème traité

Trois questions pratiques mal couvertes par la littérature de vulgarisation sur la micro-segmentation : **comment mesurer objectivement le gain de sécurité obtenu**, **quelle granularité appliquer où**, et surtout **une politique qui réduit l'exposition casse-t-elle le fonctionnement métier normal ?** Ce projet répond aux trois avec une politique fondée sur des graphes, une pondération contextuelle par criticité, et une **validation sur une capture réseau (.pcap) simulée** plutôt qu'un raisonnement purement théorique.

---

## 🏗️ Architecture

```
Topologie réseau héritée (synthétique)
      │
      ├──▶ Graphe de connectivité (networkx) → Rayon de compromission
      │
      ▼
Politique de segmentation adaptative (granularité + exceptions port-précises)
      │
      ├──▶ Génération de règles de pare-feu
      │
      ├──▶ Simulation de trafic (légitime + mouvement latéral)
      │         │
      │         ▼
      │    Fichier .pcap (généré avec scapy) → Relecture (comme Wireshark) → Validation
      │
      └──▶ Dashboard + rapport comparatif
```

---

## 📂 Structure du projet

```
network-microsegmentation/
├── src/
│   ├── network/
│   │   ├── topology.py           # topologie réseau héritée synthétique (avec IP)
│   │   └── exposure_metrics.py   # rayon direct + transitif (Basta et al. 2021)
│   ├── segmentation/
│   │   └── policy_engine.py      # segmentation adaptative + exceptions port-précises (CEUR 2025)
│   ├── firewall/
│   │   └── rule_generator.py     # génère des règles ALLOW à partir de la politique
│   ├── pcap/
│   │   ├── pcap_generator.py     # génère un vrai fichier .pcap (scapy)
│   │   ├── pcap_analyzer.py      # relit le pcap, extrait les flux (5-tuple)
│   │   └── flow_validator.py     # confronte les flux observés à la politique
│   ├── evaluation/
│   │   └── metrics.py            # comparaison avant/après (exposition + règles + pcap)
│   ├── dashboard/
│   │   └── dashboard_builder.py  # dashboard HTML interactif (Plotly)
│   └── reporting/
│       └── report_generator.py   # rapport Markdown
├── scripts/
│   └── run_pipeline.py           # pipeline complet
├── tests/                        # 29 tests unitaires
└── docs/
    └── methodology_notes.md      # références, 2 bugs trouvés, limites assumées
```

---

## 🚀 Installation et démarrage rapide

```bash
git clone https://github.com/FatimaZahraRH/network-microsegmentation.git
cd network-microsegmentation

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Pipeline complet : topologie -> segmentation -> pcap -> validation -> rapport + dashboard
python scripts/run_pipeline.py

# Ouvrir dashboard.html et capture_demo.pcap (ce dernier dans Wireshark)
# Consulter rapport_microsegmentation.md

# Tests
pytest tests/ -v
```

---

## 📊 Résultats mesurés

### Le résultat principal : validation sur capture réseau simulée

Un trafic a été simulé (flux métier légitimes + tentatives de mouvement latéral ciblées par reconnaissance), écrit dans un **fichier `.pcap` au format standard** via scapy, puis relu comme le ferait un·e analyste avec Wireshark :

| | Réseau hérité | Segmentation adaptative |
|---|---|---|
| Tentatives de mouvement latéral autorisées | **6/6** | **0/6** |
| Flux métier légitimes préservés | 40/40 | **40/40** |

**100 % des mouvements latéraux simulés sont bloqués, 0 % de disruption du trafic légitime.**

### Résultats complémentaires

| Métrique | Réseau hérité | Segmentation adaptative |
|---|---|---|
| Hôtes critiques directement exposés | 2 | 2 (accès désormais précisément scopé par port) |
| Règles de pare-feu | 9 (larges, peu précises) | 14 (plus nombreuses mais port-précises) |

### Tests unitaires

29 tests couvrant : la génération de topologie, les métriques d'exposition, le moteur de segmentation adaptative, le générateur de règles, et le module pcap complet (génération, lecture, validation).

```bash
pytest tests/ -v
# 29 passed
```

---

## 🧠 Deux défauts de conception trouvés et corrigés grâce à la validation pcap

Le vrai intérêt d'ajouter une validation sur trafic simulé plutôt que de s'arrêter à un raisonnement par graphe : elle a activement révélé deux défauts de conception qui seraient passés inaperçus autrement.

1. **Isolement total des actifs critiques** : la première version de la politique bloquait 21 des 40 flux métier légitimes (authentification, requêtes base de données) en isolant complètement les actifs critiques. Corrigé par des exceptions point-à-point explicites.
2. **Confusion de port** : cette première correction, elle, autorisait n'importe quel port dès lors que la paire de types était légitime -- une attaque SMB/445 devenait indiscernable d'une authentification Kerberos/88 légitime vers le même contrôleur de domaine. Corrigé en rendant la vérification précise par port, pas seulement par type d'hôte.

Voir `docs/methodology_notes.md` pour le détail complet.

---

## ⚠️ Limites assumées

- Topologie et capture réseau **synthétiques**.
- Modèle de flux légitimes simplifié (types + ports codés en dur).
- Pas d'intégration à un outil de production réel (Morpheus, ALGOSEC CARMEN).
- Capture réseau simulée (paquets TCP SYN minimaux, pas de session applicative complète).
- Le rayon de compromission "transitif" (multi-sauts) reste une approximation pessimiste -- limite documentée et assumée (cf. `docs/methodology_notes.md`).

---

## 🛠️ Stack technique

Python 3.12 · networkx (graphes) · scapy (génération/lecture pcap) · Plotly (dashboard) · pytest

---

## Licence

Distribué sous licence MIT (voir [`LICENSE`](LICENSE)). Projet personnel à but pédagogique et de démonstration. Topologie et capture réseau entièrement synthétiques.
