#!/usr/bin/env bash
# C16 - Debsecan

controle_C16() {
    debut_controle C16 "Debsecan" || return 1
    if [ "${LSAF_DEBSECAN:-1}" != "1" ]; then
        ajouter_note "Debsecan désactivé par l'option --sans-debsecan : contrôle non exécuté."
        # shellcheck disable=SC2034  # lu par fin_controle
        CTRL_STATUT_FORCE="non_execute"
        fin_controle
        return 0
    fi
    bloc --id C16.identification --titre "DEBSECAN - IDENTIFICATION" -- "$(cat <<'DOC'
    echo "===== DEBSECAN - IDENTIFICATION ====="
    echo "Serveur : $(hostname)"
    echo "Date/heure : $(date)"
    echo
    echo "===== INSTALLATION ====="
    dpkg -l | grep debsecan || true
    echo
    echo "===== VERSION ====="
    debsecan --version 2>&1 || true
DOC
)"
    bloc --id C16.standard --titre "DEBSECAN - RAPPORT STANDARD" --requiert debsecan --delai 900 -- "$(cat <<'DOC'
sudo debsecan
DOC
)"
    bloc --id C16.detail --titre "DEBSECAN - RAPPORT DETAILLE" --requiert debsecan --delai 900 -- "$(cat <<'DOC'
sudo debsecan --format detail
DOC
)"
    bloc --id C16.systeme --titre "SYSTEME (os-release)" -- "$(cat <<'DOC'
cat /etc/os-release
DOC
)"
    fin_controle
}
