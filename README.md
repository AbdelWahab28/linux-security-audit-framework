# LSAF — Linux Security Audit Framework

LSAF automatise une méthodologie d'audit de sécurité de serveurs Linux en **18 contrôles** (C01 à C18) :
il collecte les preuves sur chaque serveur, vérifie qu'elles sont complètes, croise les résultats (C18) et
produit un registre Excel puis un rapport Word.

> **LSAF ne remplace pas l'auditeur.** Il collecte et organise les faits. La conformité, le niveau de
> priorité, le risque, la référence et la recommandation restent décidés par l'auditeur.

---

## En bref : ce que fait LSAF, et ce qu'il ne fait pas

| LSAF fait automatiquement | L'auditeur fait |
|---|---|
| Exécuter sur le serveur les commandes du document de méthodologie, **en lecture seule** | Choisir les serveurs et lancer la collecte |
| Enregistrer chaque sortie dans un fichier de preuve horodaté, avec une empreinte SHA-256 | Copier les preuves sur son poste |
| Vérifier que les preuves sont complètes et non modifiées | Corriger ou relancer une collecte incomplète |
| Extraire les valeurs observées (version d'OS, ports en écoute, paramètres SSH…) | Renseigner l'**état initial** (Conforme / Non conforme…) |
| Croiser les contrôles (C18) et proposer des **pistes « À QUALIFIER »** | Qualifier chaque piste : référence, risque, **priorité**, recommandation, action, responsable, échéance |
| Produire le classeur Excel (même structure que le registre de traçabilité) | Valider le classeur |
| Produire le rapport Word **à partir du classeur qualifié** et vérifier la cohérence Excel ↔ Word | Relire et diffuser le rapport |

Un contrôle sans preuve n'est **jamais** compté comme conforme.

---

## Le déroulé en 6 étapes

```
 SERVEUR AUDITÉ                       POSTE DE L'AUDITEUR
 ──────────────                       ───────────────────
 1. sudo ./collecteur/lsaf-collecte.sh
        │  (preuves .txt + .json)
        └──── 2. copie du dossier de session ───►  3. lsaf valider
                                                   4. lsaf classeur   → registre Excel (pistes « À QUALIFIER »)
                                                   5. qualification dans Excel (par l'auditeur)
                                                   6. lsaf rapport    → rapport Word + contrôle de cohérence
```

### 1. Collecter les preuves sur le serveur

Copiez le dossier `collecteur/` sur le serveur (il ne contient que des scripts bash), puis :

```bash
sudo ./collecteur/lsaf-collecte.sh
```

Le script affiche ce qu'il va faire et demande une confirmation. Il crée un dossier de session :

```
lsaf-sessions/<SERVEUR>_<AAAAMMJJ>_<HHMMSS>/
├── session.json          description de la collecte (serveur, date, statut de chaque contrôle)
├── SHA256SUMS            empreintes de tous les fichiers
├── journal/collecte.log  déroulement de la collecte
└── preuves/
    ├── C01_<SERVEUR>_<AAAAMMJJ>_<HHMMSS>.txt     sortie brute des commandes
    ├── C01_<SERVEUR>_<AAAAMMJJ>_<HHMMSS>.json    exécution structurée (codes retour, durées, empreinte)
    ├── …
    └── C17_<SERVEUR>_<AAAAMMJJ>_<HHMMSS>.lynis.txt   sortie complète de Lynis
```

Options utiles (`--aide` pour la liste complète) :

| Option | Effet |
|---|---|
| `-c C01,C09,C17-02` | ne lancer que certains contrôles |
| `--sans-lynis`, `--sans-debsecan` | ne pas lancer ces outils (contrôles marqués « non exécuté ») |
| `--comptes "compte1 compte2"` | comptes examinés par C17-02 et C17-03 (défaut : comptes dont l'UID est ≥ 1000) |
| `--ports-tls "443 8443"` | ports testés en TLS par C17-05 (défaut : `443 8443 9443`) |
| `--alias-hote NOM` | nom utilisé dans les fichiers à la place du nom réel du serveur |
| `--simulation` | afficher les commandes sans les exécuter |

Le collecteur **ne modifie rien** : aucune installation, aucune modification de configuration, aucun
redémarrage, aucune suppression, aucun envoi réseau. Lynis et Debsecan doivent déjà être installés ; s'ils
ne le sont pas, les contrôles concernés sont marqués « collecte impossible » (rien n'est installé).

### 2. Copier la session sur le poste de l'auditeur

Avec l'outil habituel de l'organisation (par exemple `scp`, lancé **depuis le poste de l'auditeur**). Les
preuves contiennent des informations sensibles : ne les déposez jamais dans un dépôt Git.

### 3. Vérifier les preuves

Sur le poste de l'auditeur, installez LSAF (Python 3.9 ou plus) :

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install .
```

Puis :

```bash
lsaf valider lsaf-sessions/
```

Pour chaque serveur : nombre de contrôles avec preuve, contrôles sans preuve, preuves modifiées ou
tronquées. Code retour 1 en cas d'erreur bloquante.

### 4. Produire le registre Excel

```bash
lsaf classeur lsaf-sessions/ --inventaire inventaire.yaml -o livrables/
```

Résultat : `livrables/LSAF_Audit_<LIBELLÉ>_<AAAAMMJJ>.xlsx` et `LSAF_Consolide_<LIBELLÉ>_<AAAAMMJJ>.json`.
Un fichier existant n'est jamais écrasé (suffixe `_2`, `_3`…). L'inventaire (facultatif, voir
`exemples/inventaire.exemple.yaml`) apporte ce que les preuves ne disent pas : rôle, environnement,
criticité, responsable.

Le classeur reprend les feuilles du registre de traçabilité : **INVENTAIRE_AUDIT**,
**CONTROLES_ET_PREUVES**, **ANALYSE**, **DASHBOARD**, plus trois feuilles LSAF : **C18_CROISEMENTS**,
**C18_TRANSVERSAL**, **LIMITES_COLLECTE**. Détail : [docs/livrables.md](docs/livrables.md).

### 5. Qualifier (travail de l'auditeur)

Dans la feuille **ANALYSE**, chaque ligne générée par LSAF est une piste marquée « À QUALIFIER » en
colonne S. Pour chacune : compléter la référence, le risque, le niveau de priorité, la recommandation,
l'action, le responsable et l'échéance ; supprimer la piste si elle n'est pas retenue ; ajouter les
constats que LSAF ne peut pas détecter. Dans **CONTROLES_ET_PREUVES**, renseigner l'état initial.

### 6. Produire le rapport Word

```bash
lsaf rapport livrables/LSAF_Audit_<LIBELLÉ>_<AAAAMMJJ>.xlsx --config lsaf.yaml
```

Le rapport est refusé tant qu'une piste reste « À QUALIFIER » (l'option `--brouillon` produit une version de
travail clairement marquée). Après génération, LSAF compare automatiquement le rapport et le classeur
(nombre de constats, criticités, serveurs, fiches) et affiche le résultat.

---

## Essayer sans serveur : la démonstration

```bash
lsaf demo -o lsaf-demo
```

Crée trois serveurs **fictifs** (SRV-EXEMPLE-01 à 03, adresses réservées à la documentation), le classeur,
un rapport brouillon, un classeur qualifié avec des textes **fictifs** et le rapport correspondant.

---

## Les statuts

**Statut de collecte** d'un contrôle (colonne « Statut de collecte LSAF ») — il ne dit rien de la conformité :

| Statut | Signification |
|---|---|
| Réussi | commandes exécutées, preuve exploitable |
| À vérifier | preuve exploitable, mais un point doit être vérifié (message d'erreur dans une sortie, outil inadapté…) |
| Partiel | une partie des commandes n'a pas pu être exécutée |
| Preuve insuffisante | preuve présente mais incomplète ou modifiée |
| Collecte impossible | les commandes principales n'ont pas pu être exécutées (outil absent, délai dépassé…) |
| En échec | preuve absente, tronquée ou illisible |
| Non exécuté | contrôle non lancé |

**État initial** (Conforme, Partiellement conforme, Non conforme, Non vérifié) : renseigné par l'auditeur
uniquement.

---

## Documentation

| Document | Contenu |
|---|---|
| [docs/methodologie.md](docs/methodologie.md) | démarche, rôle de chaque étape, principes |
| [docs/controles.md](docs/controles.md) | les 18 contrôles et **toutes les commandes exécutées** |
| [docs/corrections-commandes.md](docs/corrections-commandes.md) | chaque différence avec le document de méthodologie, et pourquoi |
| [docs/nommage-preuves.md](docs/nommage-preuves.md) | noms des fichiers et détection du nom du serveur |
| [docs/format-resultats.md](docs/format-resultats.md) | contenu des fichiers JSON |
| [docs/regles-c18.md](docs/regles-c18.md) | les règles de croisement C18 (R01 à R11) |
| [docs/livrables.md](docs/livrables.md) | le classeur Excel et le rapport Word |
| [docs/erreurs.md](docs/erreurs.md) | gestion des erreurs et codes d'anomalie |
| [docs/limites.md](docs/limites.md) | limites connues et validation humaine nécessaire |
| [docs/publication.md](docs/publication.md) | vérifications avant toute publication du dépôt |
| [docs/feuille-de-route.md](docs/feuille-de-route.md) | ce qui reste à développer |

## Organisation du dépôt

```
collecteur/            scripts bash exécutés sur le serveur (lecture seule)
  lsaf-collecte.sh     lanceur
  lib/commun.sh        fonctions communes (enregistrement des preuves, JSON, empreintes)
  controles/           un script par contrôle (C01.sh … C17-07.sh)
lsaf/                  programme Python exécuté sur le poste de l'auditeur
config/                exemple de configuration du rapport
exemples/              inventaire et session entièrement fictifs
modeles/               emplacement d'un éventuel modèle Word de l'organisation
outils/                vérificateur avant publication
tests/                 tests automatiques (données synthétiques)
docs/                  documentation
```

## Sécurité et confidentialité

- Lecture seule : voir [SECURITY.md](SECURITY.md) et [docs/limites.md](docs/limites.md) (Lynis écrit son
  propre journal dans `/var/log`, comme dans le document de méthodologie).
- Aucune donnée d'audit dans ce dépôt : le `.gitignore` exclut sessions, preuves, classeurs et rapports.
  Avant toute publication : `python3 outils/verifier_publication.py .` puis relecture humaine
  ([docs/publication.md](docs/publication.md)).
- Ne lancez pas les tests ni des collectes d'essai sur un serveur de production.

## Licence

MIT — voir [LICENSE](LICENSE).
