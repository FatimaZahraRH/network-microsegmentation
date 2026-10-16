# Rapport de Micro-segmentation Réseau Adaptative
*Généré le 16/10/2026 à 14:43*

## Synthèse
- **Rayon de compromission direct moyen : 31.04 → 19.57 hôtes** joignables en un saut
- Hôtes critiques directement joignables depuis un poste utilisateur : 2 → 2 (les contrôleurs de domaine restent joignables pour l'authentification, mais seulement sur Kerberos/88)
- **Règles de pare-feu : 9 → 13**
- **Validation sur capture réseau simulée (pcap)** : 6/6 tentatives de mouvement latéral auraient été autorisées par le réseau hérité, **6/6 sont bloquées par la segmentation adaptative**, tout en préservant **40/40 flux métier légitimes**.

## Validation par capture réseau (pcap)
Un trafic réseau a été simulé (flux métier légitimes + tentatives de mouvement latéral ciblées par reconnaissance) et écrit dans un véritable fichier `.pcap`, ouvrable dans Wireshark. Ce fichier a ensuite été relu comme le ferait un·e analyste, et chaque flux observé confronté à la politique de segmentation -- plutôt que de raisonner uniquement sur un modèle théorique du réseau.

| | Réseau hérité | Segmentation adaptative |
|---|---|---|
| Tentatives de mouvement latéral autorisées | 6/6 | 0/6 |
| Flux métier légitimes préservés | 40/40 | 40/40 |

## Trois défauts trouvés et corrigés
1. **Une première version de la politique isolait totalement les actifs critiques**, bloquant 21 des 40 flux métier légitimes du test (authentification, requêtes base de données). Corrigé par des exceptions point-à-point explicites vers les actifs individuellement segmentés.
2. **Cette première correction, elle, autorisait alors n'importe quel port** vers un actif critique dès lors que la paire de types était légitime -- une attaque SMB/445 devenait indiscernable d'une authentification Kerberos/88. Corrigé en rendant la vérification précise par port.
3. **Le graphe segmenté ajoutait des connexions au lieu d'en retirer** : il était construit sur toutes les paires d'hôtes plutôt qu'en filtrant le réseau hérité, et laissait les postes utilisateurs communiquer entre eux. Le rayon de compromission direct augmentait après segmentation. Corrigé en appliquant la politique comme un filtre sur les connexions existantes et en interdisant le trafic poste à poste.

## Répartition de la granularité de segmentation
| Granularité | Nombre d'hôtes | Principe |
|---|---|---|
| Individuelle | 7 | Micro-segment dédié + exceptions point-à-point port-précises |
| Restreinte | 14 | Groupée par type dans la zone |
| Large | 25 | Segment de zone, sans trafic poste à poste |

## Limite assumée : rayon de compromission transitif
Le rayon transitif (composante connexe complète) reste élevé dans les deux configurations (45.0 → 45.0 hôtes) car des flux métier légitimes relient nécessairement les segments entre eux -- limite connue (Basta et al., 2021), résolue dans la littérature par un second graphe d'attaque pondéré par l'exploitabilité de chaque saut, non implémenté ici (cf. docs/methodology_notes.md).

---
*Rapport généré automatiquement. Méthodologie détaillée dans docs/methodology_notes.md.*