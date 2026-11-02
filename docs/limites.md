# Limites

## Périmètre de l'outil

- Le statut « Réussi » indique une preuve exploitable, pas une conformité.
- Les pistes C18 sont des combinaisons de faits ; leur qualification relève de l'auditeur.
- Le contexte n'est pas connu de l'outil : rôle réel du serveur, filtrage réseau amont, mesures
  compensatoires, exceptions acceptées.
- Aucun test d'intrusion ni scan réseau n'est réalisé.

## Données collectées

| Sujet | Limite |
|---|---|
| Lynis (C17) | Lynis écrit son journal et son rapport dans `/var/log` (`lynis.log`, `lynis-report.dat`) ; c'est le seul effet de bord de la collecte. `--sans-lynis` l'évite. L'indice de durcissement est un indicateur global, pas un taux de conformité. |
| Debsecan (C16) | Conçu pour Debian : sur une autre distribution, les résultats sont marqués « À vérifier ». Il a besoin des données de sécurité Debian et peut échouer sans accès réseau. |
| systemd-analyze security (C17-01) | Un score « UNSAFE » mesure le confinement d'un service, pas une vulnérabilité. |
| Mises à jour (C03) | La liste dépend de la dernière actualisation de l'index APT ; le collecteur n'exécute pas `apt update`. |
| Pare-feu (C08) | Seul le filtrage local est examiné (UFW, iptables, nftables, firewalld). |
| Comptes (C17-02, C17-03) | Seuls les comptes indiqués par `--comptes` (par défaut UID ≥ 1000) sont examinés. |
| TLS (C17-05) | Seuls les ports indiqués par `--ports-tls` sont testés, sur 127.0.0.1. |
| Droits | Sans droits `sudo` suffisants, certaines sorties contiennent des erreurs ; elles sont signalées (« À vérifier »). |
| Conteneurs | Le contenu des conteneurs n'est pas audité. |
| Distributions | Les commandes ciblent Debian et Ubuntu (apt, dpkg). Sur une autre famille, les blocs vides ou en erreur sont signalés et jamais comptés comme conformes. |
| Extraction | Une sortie dans un format inattendu donne « Preuve insuffisante » ou « À vérifier » plutôt qu'une valeur erronée. |

## Revue recommandée

1. Examiner le résultat de `lsaf valider` et la feuille LIMITES_COLLECTE ; relancer les contrôles en échec.
2. Contrôler par sondage les valeurs observées par rapport aux fichiers de preuve.
3. Renseigner l'état initial de chaque contrôle.
4. Qualifier ou supprimer chaque piste C18 ; ajouter les constats non couverts.
5. Vérifier les références citées.
6. Relire le rapport complet avant diffusion.
