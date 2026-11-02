#!/usr/bin/env bash
# C17 - Durcissement : résultat global Lynis

controle_C17() {
    debut_controle C17 "Durcissement - résultat global Lynis" || return 1
    if [ "${LSAF_LYNIS:-1}" != "1" ]; then
        ajouter_note "Lynis désactivé par l'option --sans-lynis : contrôle non exécuté."
        # shellcheck disable=SC2034  # lu par fin_controle
        CTRL_STATUT_FORCE="non_execute"
        fin_controle
        return 0
    fi
    bloc --id C17.identification --titre "C17 - AUDIT LYNIS GLOBAL" -- "$(cat <<'DOC'
    echo "===== C17 - AUDIT LYNIS GLOBAL ====="
    echo "Serveur : $HOST"
    echo "Date/heure : $DATE_AUDIT"
    echo
    echo "===== VERSION LYNIS ====="
    command -v lynis
    lynis show version
    echo
    echo "===== VERIFICATION DES PRIVILEGES SUDO ====="
    sudo -v
    echo "Code retour sudo : $?"
    echo
    echo "===== IDENTITE COURANTE ====="
    id
    echo
    echo "===== HOSTNAME ====="
    hostnamectl 2>&1
    echo
    echo "===== SYSTEME ====="
    cat /etc/os-release
    uname -a
DOC
)"
    bloc --id C17.audit_lynis --titre "LANCEMENT AUDIT LYNIS" --requiert lynis --delai "${LSAF_DELAI_LYNIS:-1800}" -- "$(cat <<'DOC'
sudo lynis audit system --no-colors 2>&1 | tee "$REPORT"
DOC
)"
    [ "${LSAF_SIMULATION:-0}" = "1" ] || ajouter_annexe "$REPORT" "Sortie brute de Lynis (fichier REPORT)"
    bloc --id C17.sections --titre "SECTIONS LYNIS" -- "$(cat <<'DOC'
grep -nE '^\[[+!-]\]' "$REPORT" 2>/dev/null
DOC
)"
    bloc --id C17.resultats --titre "RESULTATS GLOBAUX LYNIS" -- "$(cat <<'DOC'
grep -niE 'hardening index|suggestions|warnings|tests performed' "$REPORT" 2>/dev/null
DOC
)"
    fin_controle
}
