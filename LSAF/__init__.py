"""LSAF - Linux Security Audit Framework (partie analyse, poste de l'auditeur).

Le collecteur (collecteur/lsaf-collecte.sh) s'exécute sur le serveur audité et
produit les preuves. Ce paquet Python :

1. valide les sessions de collecte (intégrité, nommage, complétude) ;
2. extrait les valeurs observées de chaque preuve (résultat structuré JSON) ;
3. prépare l'analyse croisée C18 (croisements factuels entre contrôles et entre
   serveurs, pistes « À QUALIFIER ») ;
4. produit le classeur Excel (registre d'audit) ;
5. génère le rapport Word à partir du classeur qualifié par l'auditeur.

Criticité, référence, responsable et échéance sont saisis par l'auditeur dans
la feuille ANALYSE.
"""

__version__ = "0.1.0"
