#!/usr/bin/env bash
# C17-02 - Authentification / mots de passe

controle_C17_02() {
    debut_controle C17-02 "Authentification / mots de passe" || return 1
    bloc --id C17-02.authentification --titre "C17-02 - AUTHENTIFICATION / MOTS DE PASSE" -- "$(cat <<'DOC'
    echo "===== C17-02 - AUTHENTIFICATION / MOTS DE PASSE ====="
    echo "Serveur : $HOST"
    echo "Date/heure : $DATE_AUDIT"
    echo
    echo "===== POLITIQUE /ETC/LOGIN.DEFS ====="
    grep -nE '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK)' \
        /etc/login.defs 2>/dev/null
    echo
    for u in $LSAF_COMPTES; do
        echo "===== COMPTE : $u ====="
        chage -l "$u" 2>&1
        echo
    done
    echo "===== PAM - PASSWORD STRENGTH ====="
    grep -RniE 'pam_(pwquality|cracklib|unix|passwdqc)' \
        /etc/pam.d 2>/dev/null
    echo
    echo "===== PAM - LOCKOUT / FAILED AUTHENTICATION ====="
    grep -RniE 'faillock|pam_tally|tally2' /etc/pam.d 2>/dev/null
    echo
    echo "===== COMMAND FAILLOCK ====="
    command -v faillock 2>&1
    echo
    echo "===== AUTHENTIFICATIONS ECHOUEES - 24H ====="
    journalctl --since "24 hours ago" --no-pager 2>/dev/null \
        | grep -Ei 'failed|failure|invalid|authentication' \
        | tail -200
DOC
)"
    fin_controle
}
