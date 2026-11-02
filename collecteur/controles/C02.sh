#!/usr/bin/env bash
# C02 - État et ressources

controle_C02() {
    debut_controle C02 "État et ressources" || return 1
    bloc --id C02.ressources --titre "ETAT ET RESSOURCES" -- "$(cat <<'DOC'
    echo "===== UPTIME / LOAD ====="
    uptime
    echo
    echo "===== CPU ====="
    lscpu | grep -E '^(CPU|Model name|Architecture|Thread|Core|Socket)'
    echo
    echo "===== MEMORY / SWAP ====="
    free -h
    echo
    echo "===== DISK ====="
    df -hT
    echo
    echo "===== INODES ====="
    df -ih
DOC
)"
    fin_controle
}
