#!/usr/bin/env bash
# C10 - Utilisateurs, comptes et privilèges

controle_C10() {
    debut_controle C10 "Utilisateurs, comptes et privilèges" || return 1
    bloc --id C10.comptes --titre "COMPTES, GROUPES PRIVILEGIES, VERROUILLAGE" -- "$(cat <<'DOC'
    echo "===== COMPTES UTILISATEURS ====="
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd
    echo
    echo "===== COMPTE ROOT ====="
    sudo passwd -S root
    echo
    echo "===== GROUPES PRIVILEGIES ====="
    getent group sudo
    getent group adm
    echo
    echo "===== COMPTES AVEC SHELL INTERACTIF ====="
    awk -F: '$7 !~ /(nologin|false)/ {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd
    echo
    echo "===== COMPTES VERROUILLES / NON VERROUILLES ====="
    sudo awk -F: '($2 ~ /^!/ || $2 ~ /^\*/) {print $1 ":LOCKED"}' /etc/shadow 2>/dev/null
DOC
)"
    fin_controle
}
