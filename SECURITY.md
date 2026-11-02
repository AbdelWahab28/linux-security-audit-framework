# Politique de sécurité

## Collecteur

Le collecteur est conçu pour être exécuté sur des serveurs en production, en lecture seule :

- aucune installation, mise à jour ou suppression de paquet ;
- aucune modification de configuration, de paramètre noyau ou de règle de pare-feu ;
- aucun démarrage, arrêt ou redémarrage de service ou du serveur ;
- aucune suppression de fichier ;
- aucune connexion sortante ni transfert de données ;
- aucune action de remédiation.

Ces règles sont contrôlées par un test automatisé qui recherche les commandes interdites dans les scripts.

Lynis (C17) écrit son journal et son rapport dans `/var/log`. L'option `--sans-lynis` désactive son
exécution.

Les preuves contiennent des informations sensibles (comptes, configuration SSH effective, ports exposés).
Le dossier de session est créé avec les droits 0700 et les fichiers avec les droits 0600 ; ils doivent être
traités avec le même niveau de protection que le rapport d'audit.

## Programme d'analyse

`lsaf` s'exécute sur le poste de l'auditeur. Il n'établit aucune connexion réseau et n'exécute aucune
commande sur les serveurs audités.

## Signaler une vulnérabilité

Merci de ne pas ouvrir de ticket public. Utilisez le signalement privé de vulnérabilité de GitHub (onglet
« Security », bouton « Report a vulnerability »).
