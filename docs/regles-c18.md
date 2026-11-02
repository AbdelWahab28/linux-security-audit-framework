# Règles de croisement C18

Les règles sont définies dans `lsaf/c18.py`. Chacune croise des valeurs extraites de plusieurs contrôles
pour un même serveur.

## Résultat d'une règle

| Résultat | Signification |
|---|---|
| déclenchée | la combinaison de faits décrite par la règle est observée |
| non déclenchée | la combinaison n'est pas observée |
| non concluante | une preuve nécessaire est absente ou inexploitable ; ce n'est pas une absence de problème |

Les résultats de toutes les règles, serveur par serveur, figurent dans la feuille **C18_CROISEMENTS**.

Une règle déclenchée sur un ou plusieurs serveurs produit **une seule piste** dans la feuille ANALYSE. La
colonne A liste les serveurs concernés (`SRV-LINUX-01 ; SRV-LINUX-03`) et le constat (colonne F) détaille,
pour chacun, les faits relevés et le fichier de preuve correspondant. Certaines règles ajoutent un point de
vigilance d'interprétation.

Une piste ne contient ni criticité, ni référence, ni risque, ni recommandation : ces colonnes sont
renseignées par l'auditeur.

## Règles

| Règle | Axe | Contrôles | Déclenchée lorsque |
|---|---|---|---|
| R01 | Exposition réseau | C06, C07, C08, C17-05 | au moins un port écoute hors boucle locale et aucun filtrage local restrictif n'est identifié (UFW inactif, politique INPUT ACCEPT sans règle, aucune chaîne nftables en « drop ») |
| R02 | Vulnérabilités et correctifs | C03, C04, C16 | un paquet signalé par Debsecan figure parmi les mises à jour disponibles |
| R03 | Mises à jour | C03 | des paquets peuvent être mis à jour, un redémarrage est requis ou un noyau plus récent que le noyau actif est installé |
| R04 | Exposition réseau et confinement des services | C06, C07, C17-01 | une unité classée « UNSAFE » par `systemd-analyze security` correspond au processus d'un port exposé |
| R05 | Authentification et accès SSH | C07, C09, C10, C17-02 | `permitrootlogin` différent de `no`, `passwordauthentication yes`, aucun verrouillage PAM (faillock / tally) ou `PASS_MAX_DAYS 99999` |
| R06 | Permissions sensibles | C11, C17-03 | un fichier est modifiable par tous, ou un fichier de `/etc` ou `/usr/local` est modifiable par le groupe ou les autres |
| R07 | Journalisation et détection | C12, C15, C17-06 | aucune règle de transfert rsyslog, ou aucun service d'audit actif |
| R08 | Protection antimalware et intégrité | C15, C17-07 | aucun service de sécurité ni outil d'intégrité, antimalware ou IDS parmi ceux recherchés |
| R09 | Chiffrement TLS | C17-05 | certificat expiré à la date de collecte, ou émetteur identique au sujet |
| R10 | Synchronisation horaire | C13 | horloge non synchronisée, ou aucun service timesyncd, chrony ou ntp actif |
| R11 | Résultats Lynis | C17 | au moins un avertissement Lynis |

Aucune règle n'introduit de seuil de criticité : les conditions portent uniquement sur des valeurs lues
dans les preuves.

## Comparaison entre serveurs

La feuille **C18_TRANSVERSAL** liste les éléments identiques observés sur au moins deux serveurs : paquets
à mettre à jour, CVE, ports exposés, paramètres SSH, unités « UNSAFE », paramètres sysctl, politique de
mots de passe, avertissements Lynis, services de sécurité, fuseau horaire.

## Ajouter une règle

```python
@regle("R12", "Intitulé de la piste", "Axe d'analyse", ("C07", "C09"), "SSH / accès distant")
def r12(h: Hote):
    if not h.ok("C09"):
        return NON_CONCLUANTE, [], "C09 sans preuve exploitable"
    ...
    return DECLENCHEE, [h.fait("C09", "fait observé")], ""
```

`h.fait()` associe automatiquement le fait au fichier de preuve du contrôle. Ajoutez un test dans
`tests/test_c18.py` et documentez la règle dans ce fichier.
