# Nommage des preuves et des livrables

## Nom du serveur

Le collecteur détecte le nom du serveur dans cet ordre : `hostnamectl --static`, puis `hostname`, puis la
première ligne de `/etc/hostname`. Le nom est ensuite normalisé pour pouvoir figurer dans un nom de fichier
(lettres, chiffres, `.`, `_` et `-` uniquement).

- Si aucun nom n'est trouvé, le libellé **`HOTE-INCONNU`** est utilisé et la session porte l'anomalie
  `HOTE_NON_DETECTE` : `lsaf valider` la signale.
- L'option `--alias-hote NOM` remplace le nom dans les **noms de fichiers** (par exemple pour ne pas exposer
  le nom réel dans une arborescence partagée). Le **contenu** des preuves n'est pas modifié : il peut
  toujours contenir le vrai nom.

Dans le classeur, chaque serveur reçoit en plus un identifiant `SRV-LINUX-01`, `SRV-LINUX-02`… (ordre
alphabétique des noms).

## Dossier de session

```
<SERVEUR>_<AAAAMMJJ>_<HHMMSS>/
```

Si le dossier existe déjà (deux collectes dans la même seconde), un suffixe `-2`, `-3`… est ajouté : une
session n'est jamais écrasée.

## Fichiers de preuve

| Fichier | Contenu |
|---|---|
| `C09_<SERVEUR>_20261102_101500.txt` | sortie brute des commandes du contrôle C09, bloc par bloc |
| `C09_<SERVEUR>_20261102_101500.json` | description de l'exécution : commandes, codes retour, durées, statuts, empreinte SHA-256 du `.txt` |
| `C17_<SERVEUR>_20261102_101500.lynis.txt` | sortie complète de Lynis (variable `REPORT`), annexe de C17 |
| `C17-02_<SERVEUR>_20261102_101500.txt` | les sous-contrôles C17 gardent leur numéro complet |

L'horodatage est celui du début de la session : tous les fichiers d'une même collecte portent le même.

Dans la colonne « Preuve » du classeur, on trouve le nom exact du fichier, sans chemin ; plusieurs fichiers
sont séparés par « ; ».

## Livrables

| Livrable | Nom |
|---|---|
| Classeur | `LSAF_Audit_<LIBELLÉ>_<AAAAMMJJ>.xlsx` |
| Données consolidées | `LSAF_Consolide_<LIBELLÉ>_<AAAAMMJJ>.json` |
| Rapport | `LSAF_Rapport_<LIBELLÉ>_<AAAAMMJJ>.docx` |
| Rapport de travail | `LSAF_Rapport_BROUILLON_<LIBELLÉ>_<AAAAMMJJ>.docx` |

`<LIBELLÉ>` est le nom du serveur s'il n'y en a qu'un, sinon le nom de campagne (`--campagne`), sinon
`MULTI-<n>SRV`. Exemple : `LSAF_Audit_HOST-EXAMPLE_20261102.xlsx`. Si le fichier existe, un suffixe `_2`,
`_3`… est ajouté : aucun livrable n'est écrasé.
