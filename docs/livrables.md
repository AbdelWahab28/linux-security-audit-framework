# Classeur et rapport

## Classeur Excel (`lsaf classeur`)

### INVENTAIRE_AUDIT

Une ligne par serveur. Colonnes A à W : identification (ID, nom, adresse IP, OS, version, rôle,
environnement, criticité, domaine, responsable), planification (dates, statut, outils), constats calculés
depuis ANALYSE (nombre, critiques, élevés, moyens, faibles), remédiation et re-audit, commentaire.

Les informations absentes des preuves (rôle, environnement, criticité, domaine, responsable) proviennent du
fichier d'inventaire ou sont saisies dans le classeur.

### CONTROLES_ET_PREUVES

Une ligne par contrôle et par serveur, soit 25 lignes par serveur (C16 occupe deux lignes : analyse
Debsecan, puis qualification des correctifs).

| Colonnes | Contenu | Renseigné par |
|---|---|---|
| A–H | identifiant, serveur, domaine, élément contrôlé, valeur observée | LSAF |
| I | état initial (Conforme, Partiellement conforme, Non conforme, Non vérifié) | auditeur |
| J–M | date, méthode, outil, fichier(s) de preuve | LSAF |
| N–R | contrôle, statut de collecte, points à vérifier, fichier JSON, intégrité | LSAF |

Une cellule « Preuve » vide est surlignée en rouge.

### ANALYSE

Registre des constats (findings), colonnes A à S : serveur(s), domaine, élément (`Fnn – intitulé`),
référence, type de référence, constat, risque, niveau de priorité, recommandation, action, responsable,
échéance, statut de remédiation, vérification après remédiation, commentaire.

LSAF y écrit une ligne par piste C18 (colonnes A, B, C, F et S). Qualification :

1. retenir ou supprimer la piste ;
2. compléter la référence, le risque, le niveau de priorité, la recommandation, l'action et, si possible,
   le responsable, l'échéance et le statut ;
3. retirer la mention « À QUALIFIER » de la colonne S ;
4. ajouter les constats non couverts par les règles, au format `Fnn – intitulé` ;
5. trier par priorité (Critique, Haute, Moyenne, Faible), puis par nombre de serveurs concernés.

### DASHBOARD

Indicateurs et tableaux calculés par formules : serveurs audités, contrôles enregistrés, constats et
pistes à qualifier, couverture des preuves, contrôles à évaluer, constats transversaux, répartitions par
criticité, serveur, nombre de serveurs concernés et domaine, statut de collecte ; graphiques associés ;
listes de référence utilisées par les listes déroulantes.

### Feuilles complémentaires

| Feuille | Contenu |
|---|---|
| C18_CROISEMENTS | résultat de chaque règle sur chaque serveur, faits et preuves |
| C18_TRANSVERSAL | éléments identiques observés sur plusieurs serveurs |
| LIMITES_COLLECTE | anomalies de session, contrôles non réussis, limites d'interprétation |

## Rapport Word (`lsaf rapport`)

Le rapport est construit à partir du classeur qualifié ; tous les chiffres sont recalculés depuis le
classeur selon les mêmes règles que le DASHBOARD.

Plan :

- couverture, gestion du document, sommaire ;
- I. Introduction ;
- II. Périmètre de l'audit ;
- III. Méthodologie ;
- IV. Synthèse exécutive ;
- V. Résultats globaux ;
- VI. Analyse détaillée des constats (une fiche par constat) ;
- VII. Analyse transversale C18 ;
- VIII. Plan de remédiation ;
- IX. Conclusion ;
- X. Annexes : périmètre détaillé, matrice des contrôles, synthèse des preuves, références, glossaire.

Une information absente du classeur est indiquée « N.R. » (non renseigné). Le rapport définitif est
refusé tant qu'une ligne d'ANALYSE est marquée « À QUALIFIER » ou n'a pas de priorité, de risque ou de
recommandation.

### Configuration

Le fichier passé avec `--config` (voir `config/lsaf.exemple.yaml`) définit l'organisation, l'intitulé,
l'auteur, la version, le niveau de confidentialité, le logo, l'historique des versions, les textes rédigés
par l'auditeur (contexte, appréciation générale, conclusion, recommandation de pilotage), les éléments hors
périmètre, les référentiels et l'échelle de criticité. Sans texte d'appréciation ou de conclusion, le
rapport ne contient que des éléments factuels issus du classeur.

### Modèle Word

`--modele charte.docx` réutilise les styles, en-têtes et pieds de page d'un document Word existant ; son
contenu est ignoré. Les styles standard « Heading 1 » à « Heading 3 », « List Bullet » et « Table Grid »
doivent être présents.
