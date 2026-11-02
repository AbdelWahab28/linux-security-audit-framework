# Contribuer

## Règles

1. **Aucune donnée réelle.** Code, tests, exemples et tickets n'utilisent que des données fictives :
   serveurs `SRV-EXEMPLE-xx`, plages d'adresses de documentation (`192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`), domaine `example.org`.
2. **Lecture seule.** Le collecteur ne doit jamais modifier un serveur.
3. **Pas de qualification automatique.** Criticité, conformité, références et recommandations restent du
   ressort de l'auditeur.
4. **Erreurs visibles.** Toute erreur doit apparaître dans la preuve, le JSON ou le bilan affiché.
5. **Langue.** Code, messages et documentation sont rédigés en français.

## Environnement de développement

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Vérifications

```bash
python -m pytest
python -m pyflakes lsaf tests outils
shellcheck -x collecteur/*.sh collecteur/lib/*.sh collecteur/controles/*.sh
python3 outils/verifier_publication.py .
```

Certains tests exécutent les contrôles C01 et C02 sur la machine locale : ne lancez pas la suite de tests
sur un serveur de production.

`outils/verifier_publication.py` signale les fichiers d'audit (preuves, classeurs, rapports), les adresses
IP hors plages de documentation, les adresses électroniques et les secrets apparents. L'option
`--liste-interdite FICHIER` recherche en plus une liste locale de termes confidentiels (noms de serveurs,
de comptes, de domaines internes).

## Ajouter un contrôle

1. Script `collecteur/controles/Cxx.sh` utilisant `debut_controle`, `bloc` et `fin_controle`.
2. Entrée dans `lsaf/controles.py`.
3. Extracteur dans `lsaf/extraction/`.
4. Sortie fictive dans `lsaf/synthetique.py` et tests associés.
5. Documentation dans `docs/controles.md`.

Pour une règle de croisement, voir [docs/regles-c18.md](docs/regles-c18.md).
