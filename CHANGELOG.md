# Journal des modifications

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet applique le
[versionnage sémantique](https://semver.org/lang/fr/).

## [0.1.0] - 2026-11-02

### Ajouté

- Collecteur Bash en lecture seule pour les contrôles C01 à C17-07 : preuves `.txt` et `.json`,
  empreintes SHA-256, manifeste de session, détection du nom du serveur, options de sélection des
  contrôles, des comptes, des ports TLS et des paquets, mode simulation.
- Validation des sessions : complétude, intégrité, cohérence.
- Extraction des valeurs observées et statuts de collecte.
- Analyse croisée C18 : onze règles, regroupement des constats entre serveurs, comparaison transversale.
- Registre d'audit Excel avec tableau de bord calculé par formules.
- Rapport d'audit Word généré depuis le registre qualifié, avec contrôle de cohérence.
- Commande de démonstration sur des serveurs fictifs.
