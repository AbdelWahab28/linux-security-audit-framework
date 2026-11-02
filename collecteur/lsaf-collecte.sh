#!/usr/bin/env bash
# =============================================================================
# LSAF - Linux Security Audit Framework
# lsaf-collecte.sh - lanceur central de la collecte des preuves (C01 à C17-07)
#
# Exécute, sur le serveur audité, les commandes des contrôles C01 à C17-07,
# contrôle par contrôle, et enregistre pour chacun :
#   - un fichier de preuve lisible : Cxx_<HOTE>_<AAAAMMJJ>_<HHMMSS>.txt
#   - un fichier d'exécution JSON  : Cxx_<HOTE>_<AAAAMMJJ>_<HHMMSS>.json
# puis un manifeste de session (session.json) et les empreintes (SHA256SUMS).
#
# LECTURE SEULE : aucune modification de configuration, aucun redémarrage, aucune
# suppression, aucune installation, aucune remédiation, aucun envoi de données.
#
# Utilisation : sudo ./lsaf-collecte.sh [options]      (voir --aide)
# =============================================================================

set -u
umask 077

REPERTOIRE_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/commun.sh
. "$REPERTOIRE_SCRIPT/lib/commun.sh"
for f in "$REPERTOIRE_SCRIPT"/controles/*.sh; do
    # shellcheck disable=SC1090
    . "$f"
done

TOUS_LES_CONTROLES="C01 C02 C03 C04 C05 C06 C07 C08 C09 C10 C11 C12 C13 C14 C15 C16 C17 C17-01 C17-02 C17-03 C17-04 C17-05 C17-06 C17-07"
declare -A LSAF_STATUTS=()

# ---------------------------------------------------------------------------
# Paramètres (options ou variables d'environnement)
# ---------------------------------------------------------------------------
SORTIE="${LSAF_SORTIE:-$PWD/lsaf-sessions}"
DEMANDES=""
EXCLUS=""
ALIAS_HOTE=""
CONFIRME=0
LSAF_SIMULATION=0
LSAF_LYNIS="${LSAF_LYNIS:-1}"
LSAF_DEBSECAN="${LSAF_DEBSECAN:-1}"
LSAF_PORTS_TLS="${LSAF_PORTS_TLS:-443 8443 9443}"
LSAF_PAQUETS_POLICY="${LSAF_PAQUETS_POLICY:-linux-generic linux-image-generic network-manager netplan.io libaudit1 openssh-server}"
LSAF_COMPTES="${LSAF_COMPTES:-}"

aide() {
    cat <<EOF
LSAF $LSAF_VERSION - collecte des preuves d'audit Linux (lecture seule)

Utilisation : sudo $0 [options]

  -o, --sortie DOSSIER     dossier parent des sessions (défaut : ./lsaf-sessions)
  -c, --controles LISTE    contrôles à exécuter, séparés par des virgules
                           (défaut : tous ; exemple : C01,C09,C17-02)
  -x, --exclure LISTE      contrôles à ne pas exécuter
      --alias-hote NOM     libellé utilisé dans les noms de fichiers à la place
                           du nom détecté (le contenu des preuves n'est pas modifié)
      --comptes "a b"      comptes interrogés par chage (C17-02) et dont le
                           répertoire personnel est contrôlé (C17-03)
                           (défaut : comptes dont l'UID est >= 1000)
      --ports-tls "p1 p2"  ports testés en local par openssl (C17-05)
                           (défaut : "$LSAF_PORTS_TLS")
      --paquets "p1 p2"    paquets interrogés par apt-cache policy (C03)
      --sans-lynis         ne pas exécuter Lynis (C17 « non exécuté »)
      --sans-debsecan      ne pas exécuter Debsecan (C16 « non exécuté »)
      --simulation         écrire les commandes sans les exécuter
  -y, --oui                ne pas demander de confirmation
      --liste              afficher les contrôles et quitter
  -h, --aide               afficher cette aide
EOF
}

liste() {
    cat <<'EOF'
C01     Identification du système          C10     Utilisateurs, comptes, privilèges
C02     État et ressources                  C11     Permissions
C03     État des mises à jour               C12     Logs et journalisation
C04     Logiciels installés                 C13     Temps et synchronisation
C05     Réseau                              C14     Tâches planifiées
C06     Services                            C15     Mécanismes de sécurité
C07     Ports en écoute                     C16     Debsecan
C08     Pare-feu / filtrage réseau          C17     Durcissement - résultat global Lynis
C09     SSH                                 C17-01  systemd / isolation des services
                                            C17-02  Authentification / mots de passe
                                            C17-03  Permissions / répertoires personnels
                                            C17-04  Kernel hardening / sysctl
                                            C17-05  Réseau / firewall / exposition / TLS
                                            C17-06  Journalisation / audit / défense
                                            C17-07  Intégrité / protections complémentaires
C18 (analyse croisée) n'est pas exécuté sur le serveur : voir « lsaf classeur ».
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--sortie) SORTIE="$2"; shift 2 ;;
        -c|--controles) DEMANDES="$2"; shift 2 ;;
        -x|--exclure) EXCLUS="$2"; shift 2 ;;
        --alias-hote) ALIAS_HOTE="$2"; shift 2 ;;
        --comptes) LSAF_COMPTES="$2"; shift 2 ;;
        --ports-tls) LSAF_PORTS_TLS="$2"; shift 2 ;;
        --paquets) LSAF_PAQUETS_POLICY="$2"; shift 2 ;;
        --sans-lynis) LSAF_LYNIS=0; shift ;;
        --sans-debsecan) LSAF_DEBSECAN=0; shift ;;
        --simulation) LSAF_SIMULATION=1; shift ;;
        -y|--oui) CONFIRME=1; shift ;;
        --liste) liste; exit 0 ;;
        -h|--aide) aide; exit 0 ;;
        *) echo "Option inconnue : $1" >&2; aide >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Contrôles à exécuter
# ---------------------------------------------------------------------------
normaliser_liste() { printf '%s' "$1" | tr ',;' '  ' | tr '[:lower:]' '[:upper:]'; }

SELECTION=""
if [ -n "$DEMANDES" ]; then
    for c in $(normaliser_liste "$DEMANDES"); do
        if [ "$c" = "C18" ]; then
            echo "C18 n'est pas collecté sur le serveur : il est réalisé par « lsaf classeur »." >&2
            continue
        fi
        case " $TOUS_LES_CONTROLES " in
            *" $c "*) SELECTION="$SELECTION $c" ;;
            *) echo "Contrôle inconnu : $c (voir --liste)" >&2; exit 2 ;;
        esac
    done
else
    SELECTION="$TOUS_LES_CONTROLES"
fi
for c in $(normaliser_liste "$EXCLUS"); do
    SELECTION="$(printf '%s' " $SELECTION " | sed "s/ $c / /g")"
done
SELECTION="$(printf '%s' "$SELECTION" | xargs)"
[ -n "$SELECTION" ] || { echo "Aucun contrôle sélectionné." >&2; exit 2; }

# ---------------------------------------------------------------------------
# Préparation de la session
# ---------------------------------------------------------------------------
detecter_hote
if [ -n "$ALIAS_HOTE" ]; then
    LSAF_HOTE="$(normaliser_libelle "$ALIAS_HOTE")"
    [ -n "$LSAF_HOTE" ] || { echo "--alias-hote invalide" >&2; exit 2; }
    SOURCE_LIBELLE="alias"
else
    LSAF_HOTE="$LSAF_HOTE_BRUT"
    SOURCE_LIBELLE="$LSAF_SOURCE_HOTE"
fi
LSAF_HORODATAGE="$(date '+%Y%m%d_%H%M%S')"
LSAF_SESSION="${LSAF_HOTE}_${LSAF_HORODATAGE}"
DOSSIER_SESSION="$SORTIE/$LSAF_SESSION"
if [ -e "$DOSSIER_SESSION" ]; then
    n=2
    while [ -e "${DOSSIER_SESSION}-${n}" ]; do n=$((n + 1)); done
    LSAF_SESSION="${LSAF_SESSION}-${n}"
    DOSSIER_SESSION="$SORTIE/$LSAF_SESSION"
fi
LSAF_DOSSIER_PREUVES="$DOSSIER_SESSION/preuves"

# Comptes interrogés (C17-02, C17-03) : par défaut, comptes UID >= 1000.
if [ -z "$LSAF_COMPTES" ]; then
    LSAF_COMPTES="$(awk -F: '$3 >= 1000 && $1 != "nobody" {printf "%s ", $1}' /etc/passwd 2>/dev/null)"
fi

# Variables utilisées par les blocs de commandes (C17 à C17-07)
HOST="$(hostname)"
DATE_AUDIT="$(date '+%Y-%m-%d %H:%M:%S')"
REPORT="$LSAF_DOSSIER_PREUVES/$(nom_preuve C17).lynis.txt"
export HOST DATE_AUDIT REPORT LSAF_COMPTES LSAF_PORTS_TLS LSAF_PAQUETS_POLICY

cat >&2 <<EOF
================================================================
 LSAF $LSAF_VERSION - collecte des preuves en LECTURE SEULE
 Libellé de l'hôte : $LSAF_HOTE $( [ "$LSAF_HOTE_DETECTE" = "1" ] || [ -n "$ALIAS_HOTE" ] || echo "(NOM NON DÉTECTÉ : libellé générique)" )
 Session           : $LSAF_SESSION
 Dossier           : $DOSSIER_SESSION
 Privilèges        : $( est_root && echo "root" || echo "utilisateur $(id -un) : les commandes « sudo » seront utilisées" )
 Contrôles         : $SELECTION
 Comptes (C17-02/03): ${LSAF_COMPTES:-aucun}
 Ports TLS (C17-05): $LSAF_PORTS_TLS
 Lynis / Debsecan  : $( [ "$LSAF_LYNIS" = "1" ] && echo oui || echo non ) / $( [ "$LSAF_DEBSECAN" = "1" ] && echo oui || echo non )
 Simulation        : $( [ "$LSAF_SIMULATION" = "1" ] && echo oui || echo non )
 Aucune modification du système n'est effectuée. Les preuves peuvent contenir
 des informations sensibles : protégez-les et ne les publiez jamais.
================================================================
EOF

if [ $CONFIRME -eq 0 ] && [ -t 0 ]; then
    printf 'Continuer ? [o/N] ' >&2
    read -r reponse
    case "$reponse" in o|O|oui|OUI|y|Y) ;; *) echo "Abandon." >&2; exit 1 ;; esac
fi

mkdir -p "$LSAF_DOSSIER_PREUVES" "$DOSSIER_SESSION/journal" || { echo "Impossible de créer $DOSSIER_SESSION" >&2; exit 1; }
chmod 700 "$DOSSIER_SESSION" "$LSAF_DOSSIER_PREUVES" "$DOSSIER_SESSION/journal" 2>/dev/null
# shellcheck disable=SC2034  # utilisé par lib/commun.sh
LSAF_JOURNAL="$DOSSIER_SESSION/journal/collecte.log"
DEBUT_SESSION="$(maintenant)"
journal INFO "Session $LSAF_SESSION démarrée (collecteur $LSAF_VERSION)"
[ "$LSAF_HOTE_DETECTE" = "1" ] || journal ALERTE "Nom d'hôte non détecté : libellé générique « $LSAF_HOTE » utilisé"

# Privilèges : « sudo -v » valide les droits une fois pour toute la collecte.
if ! est_root && [ "$LSAF_SIMULATION" != "1" ]; then
    if command -v sudo >/dev/null 2>&1 && sudo -v; then
        journal INFO "Droits sudo validés (sudo -v)"
    else
        journal ALERTE "Droits sudo non disponibles : les commandes « sudo » échoueront (collecte partielle)"
    fi
fi

# ---------------------------------------------------------------------------
# Exécution : un contrôle en échec n'arrête jamais les suivants
# ---------------------------------------------------------------------------
for c in $SELECTION; do
    fonction="controle_${c//-/_}"
    if declare -F "$fonction" >/dev/null; then
        if ! "$fonction"; then
            journal ERREUR "[$c] le contrôle s'est terminé en erreur"
            LSAF_STATUTS["$c"]="${LSAF_STATUTS[$c]:-en_echec}"
        fi
    else
        journal ERREUR "[$c] aucune implémentation"
        LSAF_STATUTS["$c"]="collecte_impossible"
    fi
done
FIN_SESSION="$(maintenant)"

# ---------------------------------------------------------------------------
# Manifeste de session et empreintes
# ---------------------------------------------------------------------------
controles_json=""
for c in $TOUS_LES_CONTROLES; do
    st="${LSAF_STATUTS[$c]:-non_execute}"
    [ -n "$controles_json" ] && controles_json="$controles_json,"
    controles_json="$controles_json$(json_texte "$c"):$(json_texte "$st")"
done
valeur_os() { [ -r /etc/os-release ] && awk -F= -v k="$1" '$1==k {v=$2; gsub(/^"|"$/, "", v); print v; exit}' /etc/os-release; }

cat > "$DOSSIER_SESSION/session.json" <<EOF
{
  "schema": "lsaf.session/1",
  "session": $(json_texte "$LSAF_SESSION"),
  "hote": $(json_texte "$LSAF_HOTE"),
  "hote_detecte": $(json_booleen "$LSAF_HOTE_DETECTE"),
  "source_libelle": $(json_texte "$SOURCE_LIBELLE"),
  "alias": $( [ -n "$ALIAS_HOTE" ] && printf true || printf false ),
  "version_collecteur": $(json_texte "$LSAF_VERSION"),
  "debut": $(json_texte "$DEBUT_SESSION"),
  "fin": $(json_texte "$FIN_SESSION"),
  "horodatage": $(json_texte "$LSAF_HORODATAGE"),
  "execute_en_root": $(est_root && printf true || printf false),
  "systeme": {
    "id": $(json_texte "$(valeur_os ID)" nul_si_vide),
    "version": $(json_texte "$(valeur_os VERSION_ID)" nul_si_vide),
    "nom": $(json_texte "$(valeur_os PRETTY_NAME)" nul_si_vide)
  },
  "parametres": {
    "lynis": $(json_booleen "$LSAF_LYNIS"),
    "debsecan": $(json_booleen "$LSAF_DEBSECAN"),
    "simulation": $(json_booleen "$LSAF_SIMULATION"),
    "ports_tls": $(json_texte "$LSAF_PORTS_TLS"),
    "comptes": $(json_texte "$LSAF_COMPTES"),
    "paquets_policy": $(json_texte "$LSAF_PAQUETS_POLICY")
  },
  "controles_demandes": $(json_liste $SELECTION),
  "controles": { $controles_json }
}
EOF

( cd "$DOSSIER_SESSION" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS 2>/dev/null ) || true
chmod -R go-rwx "$DOSSIER_SESSION" 2>/dev/null
journal INFO "Session terminée : $DOSSIER_SESSION/session.json"

echo
echo "Collecte terminée : $DOSSIER_SESSION"
echo "Statut d'exécution par contrôle :"
for c in $SELECTION; do
    printf '  %-7s %s\n' "$c" "${LSAF_STATUTS[$c]:-non_execute}"
done
echo
echo "Étape suivante, sur le poste d'analyse :"
echo "  lsaf valider $DOSSIER_SESSION"
echo "  lsaf classeur $DOSSIER_SESSION"
