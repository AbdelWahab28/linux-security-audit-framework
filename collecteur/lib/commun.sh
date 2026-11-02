#!/usr/bin/env bash
# =============================================================================
# LSAF - Linux Security Audit Framework
# collecteur/lib/commun.sh - fonctions communes du collecteur
#
# Chargé par lsaf-collecte.sh : exécute les blocs de commandes des contrôles
# (collecteur/controles/*.sh), enregistre leur sortie dans le fichier de preuve
# TXT et décrit l'exécution dans un fichier JSON.
# =============================================================================

# shellcheck disable=SC2034  # variables utilisées par les fichiers chargés

LSAF_VERSION="0.1.0"
LSAF_SCHEMA_EXECUTION="lsaf.execution/1"

# ---------------------------------------------------------------------------
# Journal d'exécution
# ---------------------------------------------------------------------------
LSAF_JOURNAL=""

journal() {
    # usage : journal NIVEAU message...
    local niveau="$1"; shift
    local ligne
    ligne="$(date '+%Y-%m-%dT%H:%M:%S%z') [$niveau] $*"
    printf '%s\n' "$ligne" >&2
    if [ -n "$LSAF_JOURNAL" ]; then
        printf '%s\n' "$ligne" >> "$LSAF_JOURNAL"
    fi
}

# ---------------------------------------------------------------------------
# Écriture JSON sans dépendance (jq n'est pas forcément présent sur le serveur)
# ---------------------------------------------------------------------------
json_echapper() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\n'/\\n}"
    s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
    printf '%s' "$s"
}

json_texte() {
    # usage : json_texte valeur [nul_si_vide]
    if [ -z "$1" ] && [ "${2:-}" = "nul_si_vide" ]; then
        printf 'null'
    else
        printf '"%s"' "$(json_echapper "$1")"
    fi
}

json_booleen() {
    if [ "$1" = "1" ] || [ "$1" = "true" ]; then printf 'true'; else printf 'false'; fi
}

json_liste() {
    local premier=1 element
    printf '['
    for element in "$@"; do
        [ $premier -eq 0 ] && printf ','
        json_texte "$element"
        premier=0
    done
    printf ']'
}

# ---------------------------------------------------------------------------
# Date, empreinte
# ---------------------------------------------------------------------------
maintenant() { date '+%Y-%m-%dT%H:%M:%S%:z' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z'; }

maintenant_ms() {
    local t
    t="$(date '+%s%3N' 2>/dev/null)"
    case "$t" in
        *N|"") printf '%s000' "$(date '+%s')" ;;
        *) printf '%s' "$t" ;;
    esac
}

empreinte_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        printf 'indisponible'
    fi
}

est_root() { [ "$(id -u)" -eq 0 ]; }

# ---------------------------------------------------------------------------
# Identification de l'hôte et nommage des preuves
# ---------------------------------------------------------------------------
LSAF_HOTE_DETECTE=0
LSAF_SOURCE_HOTE=""
LSAF_HOTE_BRUT=""

normaliser_libelle() {
    # Nom court (le domaine est retiré), lettres, chiffres et tirets uniquement.
    local s="$1"
    s="${s%%.*}"
    s="$(printf '%s' "$s" | tr -c 'A-Za-z0-9-' '-' | sed -e 's/--*/-/g' -e 's/^-//' -e 's/-$//')"
    printf '%s' "$s"
}

detecter_hote() {
    # Renseigne LSAF_HOTE_BRUT, LSAF_HOTE_DETECTE et LSAF_SOURCE_HOTE.
    # À appeler sans sous-shell pour conserver les variables.
    local brut=""
    if command -v hostnamectl >/dev/null 2>&1; then
        brut="$(hostnamectl --static 2>/dev/null)"
        [ -n "$brut" ] && LSAF_SOURCE_HOTE="hostnamectl --static"
    fi
    if [ -z "$brut" ] && command -v hostname >/dev/null 2>&1; then
        brut="$(hostname 2>/dev/null)"
        [ -n "$brut" ] && LSAF_SOURCE_HOTE="hostname"
    fi
    if [ -z "$brut" ] && [ -r /etc/hostname ]; then
        brut="$(head -n1 /etc/hostname 2>/dev/null)"
        [ -n "$brut" ] && LSAF_SOURCE_HOTE="/etc/hostname"
    fi
    brut="$(normaliser_libelle "$brut")"
    if [ -z "$brut" ]; then
        LSAF_HOTE_DETECTE=0
        LSAF_SOURCE_HOTE="valeur par défaut"
        LSAF_HOTE_BRUT="HOTE-INCONNU"
    else
        LSAF_HOTE_DETECTE=1
        LSAF_HOTE_BRUT="$brut"
    fi
}

nom_preuve() {
    # usage : nom_preuve C09 -> C09_HOTE_20261102_101500
    printf '%s_%s_%s' "$1" "$LSAF_HOTE" "$LSAF_HORODATAGE"
}

# ---------------------------------------------------------------------------
# Cycle de vie d'un contrôle
# ---------------------------------------------------------------------------
CTRL_ID=""
CTRL_NOM=""
CTRL_PREUVE=""
CTRL_JSON=""
CTRL_DEBUT=""
CTRL_BLOCS=()
CTRL_NOTES=()
CTRL_ANNEXES=()
CTRL_NB_EXECUTES=0
CTRL_NB_DEGRADES=0
CTRL_STATUT_FORCE=""

debut_controle() {
    # usage : debut_controle C09 "SSH"
    CTRL_ID="$1"
    CTRL_NOM="$2"
    CTRL_BLOCS=()
    CTRL_NOTES=()
    CTRL_ANNEXES=()
    CTRL_NB_EXECUTES=0
    CTRL_NB_DEGRADES=0
    CTRL_STATUT_FORCE=""
    CTRL_DEBUT="$(maintenant)"
    CTRL_PREUVE="$LSAF_DOSSIER_PREUVES/$(nom_preuve "$CTRL_ID").txt"
    CTRL_JSON="$LSAF_DOSSIER_PREUVES/$(nom_preuve "$CTRL_ID").json"
    if [ -e "$CTRL_PREUVE" ]; then
        journal ERREUR "Le fichier de preuve existe déjà, il n'est pas écrasé : $CTRL_PREUVE"
        return 1
    fi
    {
        echo "################################################################"
        echo "# LSAF - fichier de preuve - NE PAS MODIFIER (empreinte SHA-256 contrôlée)"
        echo "# controle     : $CTRL_ID"
        echo "# intitule     : $CTRL_NOM"
        echo "# session      : $LSAF_SESSION"
        echo "# hote         : $LSAF_HOTE"
        echo "# date_collecte: $CTRL_DEBUT"
        echo "# collecteur   : lsaf-collecte $LSAF_VERSION"
        echo "# privileges   : $( est_root && echo root || echo "utilisateur $(id -un) (commandes sudo)" )"
        echo "################################################################"
        echo
    } > "$CTRL_PREUVE"
    journal INFO "[$CTRL_ID] $CTRL_NOM - début de la collecte"
}

ajouter_note() {
    CTRL_NOTES+=("$*")
    printf '# NOTE LSAF : %s\n\n' "$*" >> "$CTRL_PREUVE"
}

ajouter_annexe() {
    # usage : ajouter_annexe CHEMIN "description" - fichier produit par une commande
    # (sortie de Lynis) conservé à côté de la preuve.
    local chemin="$1" description="$2"
    if [ -s "$chemin" ]; then
        chmod 600 "$chemin" 2>/dev/null
        CTRL_ANNEXES+=("{\"fichier\":$(json_texte "$(basename "$chemin")"),\"description\":$(json_texte "$description"),\"sha256\":$(json_texte "$(empreinte_sha256 "$chemin")")}")
        echo "# LSAF : fichier annexe conservé : $(basename "$chemin")" >> "$CTRL_PREUVE"
    else
        ajouter_note "Fichier annexe absent ou vide : $(basename "$chemin") ($description)"
    fi
}

bloc() {
    # Exécute un bloc de commandes et enregistre sa sortie.
    # usage : bloc --id C09.ssh --titre "SSH" [--requiert "sshd"] [--delai 120] -- 'commandes'
    #   --requiert : programmes indispensables ; s'ils manquent, le bloc n'est pas
    #                exécuté (statut outil_absent) au lieu de produire une sortie vide.
    local id="" titre="" requiert="" delai="${LSAF_DELAI:-300}"
    while [ $# -gt 0 ]; do
        case "$1" in
            --id) id="$2"; shift 2 ;;
            --titre) titre="$2"; shift 2 ;;
            --requiert) requiert="$2"; shift 2 ;;
            --delai) delai="$2"; shift 2 ;;
            --) shift; break ;;
            *) journal ERREUR "bloc : option inconnue $1"; return 2 ;;
        esac
    done
    local commande="$1"
    local statut="" code="null" debut fin duree=0 manquants="" prog

    {
        echo "===== LSAF-BLOC DEBUT id=$id ====="
        echo "# titre    : $titre"
    } >> "$CTRL_PREUVE"

    for prog in $requiert; do
        command -v "$prog" >/dev/null 2>&1 || manquants="$manquants $prog"
    done
    manquants="${manquants# }"

    if [ "${LSAF_SIMULATION:-0}" = "1" ]; then
        statut="simulation"
        printf '%s\n' "$commande" | sed 's/^/# commande : /' >> "$CTRL_PREUVE"
    elif [ -n "$manquants" ]; then
        statut="outil_absent"
        echo "# LSAF : bloc non exécuté - programme(s) absent(s) : $manquants" >> "$CTRL_PREUVE"
    else
        debut="$(maintenant_ms)"
        LC_ALL=C timeout -k 5 "$delai" bash -c "$commande" </dev/null >> "$CTRL_PREUVE" 2>&1
        code=$?
        fin="$(maintenant_ms)"
        duree=$(( fin - debut ))
        case "$code" in
            0) statut="ok" ;;
            124|137) statut="delai_depasse" ;;
            126|127) statut="erreur" ;;
            *) statut="code_non_nul" ;;
        esac
    fi
    if [ -n "$(tail -c1 "$CTRL_PREUVE" 2>/dev/null)" ]; then echo >> "$CTRL_PREUVE"; fi
    echo "===== LSAF-BLOC FIN id=$id code=$code statut=$statut duree_ms=$duree =====" >> "$CTRL_PREUVE"
    echo >> "$CTRL_PREUVE"

    case "$statut" in
        ok|code_non_nul) CTRL_NB_EXECUTES=$((CTRL_NB_EXECUTES + 1)) ;;
        simulation) ;;
        *) CTRL_NB_DEGRADES=$((CTRL_NB_DEGRADES + 1)) ;;
    esac
    CTRL_BLOCS+=("{\"id\":$(json_texte "$id"),\"titre\":$(json_texte "$titre"),\"commande\":$(json_texte "$commande"),\"programmes_absents\":$(json_texte "$manquants" nul_si_vide),\"code_retour\":$code,\"statut\":$(json_texte "$statut"),\"duree_ms\":$duree}")
}

fin_controle() {
    local fin statut
    fin="$(maintenant)"
    if [ -n "$CTRL_STATUT_FORCE" ]; then
        statut="$CTRL_STATUT_FORCE"
    elif [ "${LSAF_SIMULATION:-0}" = "1" ]; then
        statut="simulation"
    elif [ $CTRL_NB_EXECUTES -eq 0 ]; then
        statut="collecte_impossible"
    elif [ $CTRL_NB_DEGRADES -gt 0 ]; then
        statut="partiel"
    else
        statut="termine"
    fi
    {
        echo "################################################################"
        echo "# fin du contrôle $CTRL_ID - statut d'exécution : $statut"
        echo "# fin          : $fin"
        echo "################################################################"
    } >> "$CTRL_PREUVE"
    chmod 600 "$CTRL_PREUVE" 2>/dev/null

    local blocs notes annexes
    blocs="$(IFS=,; printf '%s' "${CTRL_BLOCS[*]}")"
    annexes="$(IFS=,; printf '%s' "${CTRL_ANNEXES[*]}")"
    notes="$(json_liste "${CTRL_NOTES[@]}")"
    cat > "$CTRL_JSON" <<EOF
{
  "schema": "$LSAF_SCHEMA_EXECUTION",
  "controle": $(json_texte "$CTRL_ID"),
  "intitule": $(json_texte "$CTRL_NOM"),
  "session": $(json_texte "$LSAF_SESSION"),
  "hote": $(json_texte "$LSAF_HOTE"),
  "hote_detecte": $(json_booleen "$LSAF_HOTE_DETECTE"),
  "version_collecteur": $(json_texte "$LSAF_VERSION"),
  "execute_en_root": $(est_root && printf true || printf false),
  "debut": $(json_texte "$CTRL_DEBUT"),
  "fin": $(json_texte "$fin"),
  "statut_execution": $(json_texte "$statut"),
  "fichier_preuve": $(json_texte "$(basename "$CTRL_PREUVE")"),
  "sha256_preuve": $(json_texte "$(empreinte_sha256 "$CTRL_PREUVE")"),
  "blocs": [${blocs}],
  "annexes": [${annexes}],
  "notes": ${notes}
}
EOF
    chmod 600 "$CTRL_JSON" 2>/dev/null
    LSAF_STATUTS["$CTRL_ID"]="$statut"
    journal INFO "[$CTRL_ID] terminé - statut d'exécution : $statut"
}
