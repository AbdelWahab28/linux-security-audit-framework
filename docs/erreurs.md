# Gestion des erreurs

Principe : **aucune erreur n'est silencieuse**. Une commande qui échoue, un outil absent ou une preuve
abîmée est enregistré, signalé par `lsaf valider` et visible dans le classeur.

## Au moment de la collecte (collecteur bash)

| Situation | Comportement |
|---|---|
| Commande en erreur | sortie d'erreur conservée dans la preuve ; code retour et statut du bloc dans le JSON ; la collecte continue |
| Outil absent (Lynis, Debsecan) | bloc non lancé, statut `outil_absent` ; rien n'est installé |
| Commande trop longue | arrêt après le délai du bloc (variable `LSAF_DELAI`, 300 s par défaut ; Lynis : `LSAF_DELAI_LYNIS`, 1 800 s), statut `delai_depasse` |
| Lancement sans root | `sudo -v` demande le mot de passe une fois ; en cas de refus, les commandes `sudo` échouent et sont signalées |
| Nom du serveur introuvable | libellé `HOTE-INCONNU`, anomalie `HOTE_NON_DETECTE` |
| Contrôle inconnu dans `-c` | arrêt immédiat, code retour 2 |
| Interruption (Ctrl+C) | la session reste incomplète ; `lsaf valider` le détecte (preuves absentes ou tronquées) |

## Au moment de la validation (`lsaf valider`)

| Code | Niveau | Signification |
|---|---|---|
| `MANIFESTE_INVALIDE` | erreur | `session.json` absent ou illisible |
| `MANIFESTE_SCHEMA` | alerte | `session.json` ne respecte pas le schéma |
| `HOTE_NON_DETECTE` | alerte | libellé générique utilisé |
| `SIMULATION` | erreur | session produite avec `--simulation` : aucune preuve |
| `DOSSIER_PREUVES_ABSENT` | erreur | dossier `preuves/` absent |
| `FICHIER_INATTENDU` | alerte | fichier qui ne suit pas la convention de nommage |
| `HOTE_DIFFERENT`, `SESSION_DIFFERENTE` | erreur | fichier appartenant à une autre session ou à un autre serveur |
| `PREUVE_ABSENTE`, `JSON_ABSENT` | erreur | un des deux fichiers du contrôle manque |
| `JSON_INVALIDE`, `JSON_INCOHERENT` / `JSON_SCHEMA` | erreur / alerte | JSON illisible ou incohérent avec la preuve / hors schéma |
| `EMPREINTE_ABSENTE` | alerte | empreinte non enregistrée : intégrité non vérifiable |
| `PREUVE_MODIFIEE` | erreur | le fichier a été modifié depuis la collecte (empreinte SHA-256 différente) |
| `PREUVE_TRONQUEE` | erreur | marqueur de fin de bloc absent (collecte interrompue) |
| `ANNEXE_ABSENTE` / `ANNEXE_MODIFIEE` | alerte / erreur | sortie Lynis absente ou modifiée |
| `PREUVE_MANQUANTE` / `NON_EXECUTE` | erreur / information | contrôle demandé mais sans preuve / contrôle non demandé |

`lsaf valider` retourne 1 si une erreur est présente. `lsaf classeur` produit tout de même le classeur
(les contrôles concernés apparaissent avec leur statut et dans LIMITES_COLLECTE) et affiche chaque erreur.

## À l'analyse

Si une sortie contient un message d'erreur connu (`command not found`, `Permission denied`, `sudo:`,
`a password is required`, `Failed to connect to bus`, `System has not been booted`, `Operation not
permitted`), le contrôle passe à « À vérifier » avec le message en cause.

## Au moment des livrables

| Situation | Comportement |
|---|---|
| Deux sessions pour le même serveur | consolidation refusée : choisir une session par serveur |
| Fichier d'inventaire ou de configuration invalide | message précis (champ inconnu, YAML invalide, fichier logo introuvable), code retour 2 |
| Pistes non qualifiées | rapport définitif refusé, liste des lignes à compléter, code retour 2 |
| Incohérence Excel ↔ Word | bilan affiché, code retour 1 |
| Fichier de sortie existant | nouveau nom avec suffixe `_2`, `_3`… (jamais d'écrasement) |
