# Session de collecte fictive

Session générée par `lsaf.synthetique`, au format exact produit par le collecteur :

- `session.json` : description de la collecte ;
- `preuves/Cxx_SRV-EXEMPLE-01_20261102_101500.txt` : sorties des commandes ;
- `preuves/Cxx_SRV-EXEMPLE-01_20261102_101500.json` : description de l'exécution.

Toutes les données sont synthétiques : serveur `SRV-EXEMPLE-01`, adresses des plages de documentation
(RFC 5737), comptes `auditeur` et `appli`, identifiants `CVE-2099-…`. Le serveur est volontairement mal
configuré afin que les règles C18 se déclenchent.

```bash
lsaf valider exemples/session-synthetique/
lsaf classeur exemples/session-synthetique/ -o /tmp/lsaf-essai
```
