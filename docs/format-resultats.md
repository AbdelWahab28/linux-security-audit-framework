# Format des fichiers JSON

Les schémas JSON sont dans `lsaf/donnees/` ; ils sont vérifiés automatiquement si le module `jsonschema`
est installé (`pip install .[validation]`).

## 1. Exécution d'un contrôle — `Cxx_<SERVEUR>_<DATE>_<HEURE>.json` (schéma `lsaf.execution/1`)

Écrit par le collecteur, à côté du fichier `.txt`.

| Champ | Contenu |
|---|---|
| `controle`, `intitule` | identifiant et intitulé du contrôle |
| `session`, `hote`, `hote_detecte` | session et nom du serveur ; `hote_detecte` vaut `false` si le libellé par défaut est utilisé |
| `execute_en_root` | collecte lancée en root (`sudo`) ou non |
| `debut`, `fin` | horodatages ISO 8601 |
| `statut_execution` | `termine`, `partiel`, `collecte_impossible`, `non_execute`, `simulation`, `en_echec` |
| `fichier_preuve`, `sha256_preuve` | nom du `.txt` et son empreinte |
| `blocs[]` | un élément par bloc : `id`, `titre`, `commande` (texte exact exécuté), `programmes_absents`, `code_retour`, `statut` (`ok`, `code_non_nul`, `outil_absent`, `delai_depasse`, `erreur`, `simulation`), `duree_ms` |
| `annexes[]` | fichiers joints (sortie Lynis) avec leur empreinte |
| `notes[]` | remarques du collecteur |

Un code retour non nul n'est pas forcément une erreur : `grep` renvoie 1 quand il ne trouve rien. Le statut
`code_non_nul` le signale sans conclure ; l'analyse décide à partir du contenu.

## 2. Session — `session.json` (schéma `lsaf.session/1`)

| Champ | Contenu |
|---|---|
| `session`, `hote`, `hote_detecte`, `source_libelle`, `alias` | identification ; `source_libelle` indique d'où vient le nom (hostnamectl, hostname, /etc/hostname, alias) |
| `version_collecteur`, `debut`, `fin`, `horodatage` | version et dates |
| `execute_en_root` | `true` / `false` |
| `systeme` | `id`, `version`, `nom` lus dans `/etc/os-release` |
| `parametres` | options utilisées (Lynis, Debsecan, simulation, ports TLS, comptes, paquets) |
| `controles_demandes`, `controles` | contrôles demandés, et statut d'exécution de chacun des 24 contrôles collectés |

## 3. Résultat d'analyse — `resultats/Cxx.json` (schéma `lsaf.resultat/1`)

Écrit par `lsaf analyser` (et par `lsaf classeur`) dans le dossier de session.

| Champ | Contenu |
|---|---|
| `controle`, `statut`, `statut_execution` | statut de collecte LSAF (voir ci-dessous) |
| `resume` | valeur observée, reprise dans la colonne H de CONTROLES_ET_PREUVES |
| `valeurs` | valeurs extraites (par exemple `configuration` pour C09, `ecoutes_hors_boucle_locale` pour C07) |
| `a_verifier[]` | points à vérifier (message d'erreur dans une sortie, outil inadapté…) |
| `limites[]` | limites d'interprétation |
| `erreurs[]` | erreurs d'analyse |
| `fichier_preuve`, `fichier_json`, `sha256_preuve`, `integrite` | traçabilité (`integrite` : `verifiee`, `modifiee`, `absente`, `non_verifiable`) |

### Statuts de collecte LSAF

L'ordre de priorité est : non exécuté › en échec › collecte impossible › preuve insuffisante › partiel ›
à vérifier › réussi.

| Statut | Règle |
|---|---|
| `non_execute` | contrôle non lancé (ou lancé en simulation) |
| `en_echec` | preuve absente, tronquée, illisible, ou erreur d'analyse |
| `collecte_impossible` | aucun bloc principal du contrôle n'a été exécuté (outil absent, délai dépassé…) |
| `preuve_insuffisante` | preuve modifiée depuis la collecte (empreinte différente) ou valeurs attendues introuvables |
| `partiel` | certains blocs n'ont pas été exécutés |
| `a_verifier` | preuve exploitable, avec au moins un point à vérifier |
| `reussi` | preuve complète et exploitable — **ce n'est pas une conformité** |

## 4. Données consolidées — `LSAF_Consolide_<LIBELLÉ>_<DATE>.json` (`lsaf.consolide/1`)

Produit par `lsaf classeur`, utilisé par `lsaf rapport`. Contient : `serveurs[]` (identifiant SRV-LINUX-nn,
système, adresse IP, informations Lynis, statuts), `controles[]` (une ligne par ligne du classeur), `c18`
(`regles`, `evaluations`, `pistes`, `transversal`), `limites[]` et `indicateurs`. Ce fichier contient des
données d'audit : il est créé avec les droits 0600 et exclu du dépôt par le `.gitignore`.
