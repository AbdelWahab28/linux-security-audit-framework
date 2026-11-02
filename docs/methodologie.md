# Méthodologie

## Chaîne de traitement

Chaque élément audité suit la même chaîne, de l'observation à la vérification après remédiation.

| Étape | Responsable | Outil |
|---|---|---|
| 1. Observation | collecteur | `collecteur/lsaf-collecte.sh` |
| 2. Preuve | collecteur | fichiers `Cxx_<SERVEUR>_<DATE>_<HEURE>.txt` / `.json`, empreintes SHA-256 |
| 3. Analyse | LSAF | `lsaf valider`, `lsaf analyser` : valeurs observées, statut de collecte |
| 4. Croisement | LSAF | règles C18 : pistes factuelles « À QUALIFIER » |
| 5. Référence | auditeur | feuille ANALYSE, colonnes D et E |
| 6. Constat | LSAF (proposition), auditeur (validation) | colonne F : faits et fichiers de preuve |
| 7. Risque et priorité | auditeur | colonnes G et H |
| 8. Recommandation et remédiation | auditeur | colonnes I à M |
| 9. Vérification | auditeur | nouvelle collecte, colonnes N à R |

## Contrôles

| Contrôle | Thème |
|---|---|
| C01 | Identification du système : OS, noyau, architecture, virtualisation |
| C02 | État et ressources : CPU, mémoire, disques, charge |
| C03 | Mises à jour : paquets, noyau, redémarrage requis, sources APT |
| C04 | Logiciels installés |
| C05 | Interfaces réseau, adressage, routage, DNS |
| C06 | Services actifs |
| C07 | Ports en écoute |
| C08 | Pare-feu et filtrage réseau |
| C09 | SSH : configuration effective |
| C10 | Comptes, shells et groupes privilégiés |
| C11 | Permissions des fichiers et répertoires sensibles |
| C12 | Journalisation |
| C13 | Heure et synchronisation |
| C14 | Tâches planifiées |
| C15 | Mécanismes de sécurité : agents, antivirus, EDR |
| C16 | Vulnérabilités (Debsecan) : analyse, puis qualification des correctifs |
| C17 | Durcissement : audit Lynis global, puis C17-01 à C17-07 (systemd, authentification, permissions, sysctl, réseau et TLS, journalisation, intégrité) |
| C18 | Analyse croisée |

Les commandes exécutées sont détaillées dans [controles.md](controles.md).

## Principes

1. **Lecture seule.** La collecte ne modifie pas le serveur (voir [limites.md](limites.md) pour le journal
   écrit par Lynis).
2. **Traçabilité.** Chaque valeur du classeur et chaque fait d'une piste C18 renvoient au nom exact d'un
   fichier de preuve, dont l'empreinte SHA-256 est vérifiée.
3. **Absence de preuve.** Un contrôle non exécuté, en échec ou sans preuve exploitable apparaît comme tel ;
   il n'est jamais considéré comme conforme.
4. **Erreurs visibles.** Chaque bloc de commandes a son code retour, son statut et sa durée ; un outil
   absent, un délai dépassé ou un message d'erreur dans une sortie est signalé.
5. **Résultats d'outils.** Un indice Lynis, un service « UNSAFE », une CVE Debsecan ou l'absence d'un
   outil sont des faits à interpréter dans leur contexte, pas des vulnérabilités en soi.
6. **Qualification humaine.** L'état initial, la criticité, la référence, le risque et la recommandation
   sont renseignés par l'auditeur.

## Analyse croisée C18

L'analyse se fait à trois niveaux :

1. **par contrôle** : lecture des valeurs observées ;
2. **par serveur** : croisement des contrôles entre eux (par exemple : un port exposé, un service peu
   confiné et l'absence de filtrage local) ;
3. **entre serveurs** : regroupement d'un même constat observé sur plusieurs serveurs et comparaison des
   valeurs (CVE, avertissements Lynis, paramètres communs).

LSAF automatise la partie factuelle des niveaux 2 et 3 avec onze règles ; la décision de retenir un
constat et sa qualification relèvent de l'auditeur. Voir [regles-c18.md](regles-c18.md).
