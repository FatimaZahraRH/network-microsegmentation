# Notes méthodologiques et références

## 1. Le problème traité

La micro-segmentation réseau (diviser un réseau en zones isolées pour limiter le mouvement latéral d'un attaquant) est largement documentée comme efficace, mais deux questions pratiques restent peu traitées dans les déploiements réels : **comment mesurer objectivement le gain de sécurité obtenu**, et **quelle granularité appliquer où** (segmenter finement partout crée une explosion du nombre de règles à maintenir). Une troisième question, tout aussi importante mais souvent négligée dans les démonstrations théoriques : **une politique de segmentation qui réduit l'exposition casse-t-elle le fonctionnement métier normal ?** Ce projet traite les trois avec la même approche : une politique fondée sur des faits mesurables (y compris sur du trafic réellement capturé), pas sur une intuition.

## 2. Références principales

- **Basta, N., Ikram, M., Kaafar, M.A., Walker, A. (2021).** *"Towards a Zero-Trust Micro-segmentation Network Security Strategy: An Evaluation Framework"*, arXiv:2111.10967. Propose un cadre d'évaluation à double graphe (connectivité et graphe d'attaque) pour quantifier objectivement l'exposition et la robustesse d'un réseau micro-segmenté.
- **"Network microsegmentation design methodology in zero-trust architecture"** (2025), CEUR Workshop Proceedings, Vol-4024. Propose une méthode d'analyse par **matrice de risque double** pour déterminer la granularité optimale de micro-segmentation selon la criticité de chaque hôte, plutôt qu'un niveau de segmentation uniforme.
- **Rose, S., Borchert, O., Mitchell, S., Connelly, S. (2020).** *"Zero Trust Architecture"*, NIST Special Publication 800-207.
- **Sheikh, N., Pawar, M., Lawrence, V. (2021).** *"Zero trust using network micro segmentation"*, IEEE INFOCOM Workshops.
- **CISA (2025).** *"The Journey to Zero Trust Microsegmentation"*, guide de planification.

## 3. Ce que ce projet démontre

Sur une topologie synthétique de 46 hôtes (5 zones), une politique de segmentation à granularité adaptative a été conçue, puis **validée sur une capture réseau simulée** (fichier `.pcap`, format libpcap standard, généré via scapy et relu comme le ferait un·e analyste avec Wireshark) :

- **6/6 tentatives de mouvement latéral simulées** (ciblées par reconnaissance, technique SMB/445 vers un contrôleur de domaine) **auraient été autorisées par le réseau hérité**, et sont **toutes bloquées par la segmentation adaptative**.
- **40/40 flux métier légitimes** (authentification Kerberos, requêtes applicatives vers les bases de données, etc.) **restent fonctionnels** après segmentation.

## 4. Trois défauts de conception trouvés et corrigés

Cette section documente honnêtement le processus itératif -- la validation sur trafic simulé n'a pas seulement confirmé le bon fonctionnement du projet, elle a révélé les deux premiers défauts, qui seraient passés inaperçus avec une évaluation purement théorique par graphe. Le troisième a été trouvé en relisant les métriques du pipeline.

**Défaut n°1 -- isolement total des actifs critiques.** La première version du moteur de segmentation coupait purement et simplement tout accès aux hôtes en granularité "individuelle" (bases de données, contrôleurs de domaine). La validation pcap a montré que cela bloquait aussi **21 des 40 flux métier légitimes** du test (authentification, requêtes applicatives). **Correction** : ajout d'exceptions point-à-point explicites (`LEGITIMATE_TYPE_FLOWS_WITH_PORTS`), n'ouvrant que les flux correspondant à un besoin métier reconnu.

**Défaut n°2 -- confusion de port au sein d'un type légitime.** Cette première correction autorisait la connexion dès que la **paire de types** d'hôtes était légitime (ex. poste utilisateur vers contrôleur de domaine, nécessaire pour Kerberos), sans vérifier le **port**. Une attaque de mouvement latéral utilisant SMB (port 445) vers le même contrôleur de domaine devenait alors indiscernable, au niveau du graphe, d'une authentification Kerberos (port 88) légitime. **Correction** : la fonction `is_legitimate_flow()` vérifie désormais le port exact, pas seulement le type d'hôte, pour toute connexion impliquant un actif en granularité individuelle.

**Défaut n°3 -- une segmentation qui ajoutait des connexions.** En relançant le pipeline, le rayon de compromission direct, présenté comme la métrique principale, *augmentait* après segmentation (14,91 → 33,09). Deux causes : (1) le graphe segmenté était construit sur toutes les paires d'hôtes que la politique autorisait, au lieu de filtrer les connexions du réseau hérité, et les postes utilisateurs, placés dans un même segment « large », y étaient tous reliés entre eux ; (2) le réseau hérité ne reliait que 3 hôtes tirés au hasard de chaque côté entre deux zones routées, contrairement à sa description (« passerelles larges »), si bien que la plupart des flux métier légitimes n'y étaient pas possibles. **Correction** : passerelles inter-zones réellement larges dans le réseau hérité ; politique appliquée comme un **filtre** (une connexion n'est conservée que si elle existait déjà et que la politique l'autorise) ; trafic poste à poste interdit. Résultat : rayon direct 31,04 → 19,57 (−37 %), 32,3 → 12,0 depuis un poste utilisateur ; résultats pcap inchangés (6/6 bloqués, 40/40 préservés). Trois tests de non-régression vérifient que le graphe segmenté est inclus dans le graphe hérité, qu'aucun lien poste à poste ne subsiste, et que le rayon direct baisse.

Le rayon des serveurs applicatifs (43,4) et des contrôleurs de domaine (35) ne baisse pas : ils servent légitimement tous les postes. Leur protection repose sur le filtrage par port, que le graphe agrégé par type d'hôte ne représente pas -- d'où l'importance de la validation pcap.

Ces trois défauts illustrent une limite générale des évaluations purement graphiques (par type/segment) : elles peuvent donner une fausse impression de sécurité tant qu'elles ne sont pas confrontées à des flux réels, port par port.

## 5. Limite assumée : rayon de compromission "transitif"

Le rayon de compromission par composante connexe complète (accessible en supposant qu'un attaquant puisse pivoter librement à travers chaque hôte intermédiaire) reste élevé dans les deux configurations, car des flux métier légitimes relient nécessairement les segments entre eux. C'est une limite documentée dans la littérature (Basta et al., 2021), qui la résout avec un **second graphe dédié** : un graphe d'attaque pondéré par l'exploitabilité réelle de chaque saut. Ce projet ne modélise pas ce second graphe -- c'est pourquoi le **rayon de compromission direct** (voisinage immédiat, directement piloté par une règle de pare-feu) est utilisé comme métrique principale, et pourquoi la validation par capture réseau (section 3) complète le tableau avec des résultats directement actionnables.

## 6. Portée et limites assumées

- **Topologie et capture réseau synthétiques** -- ne reflètent pas un audit d'infrastructure réelle.
- **Modèle de flux légitimes simplifié** (types + ports codés en dur) : un vrai projet nécessiterait une phase de découverte des flux réels (NetFlow, logs de pare-feu existants).
- **Pas d'intégration à un outil de production réel** (Morpheus, ALGOSEC CARMEN, ou équivalent).
- **Format de règles simplifié** (allow-list par paire de segments) -- un vrai pare-feu de production gère des règles bien plus riches (horaires, NAT, inspection applicative).
- **La capture réseau est simulée** (paquets TCP SYN minimaux, pas de session complète ni de charge utile applicative) -- suffisante pour valider une politique de connectivité, pas pour une inspection approfondie du contenu.
