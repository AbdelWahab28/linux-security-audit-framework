#!/usr/bin/env bash
# C07 - Ports en écoute

controle_C07() {
    debut_controle C07 "Ports en écoute" || return 1
    bloc --id C07.ports --titre "PORTS TCP/UDP EN ECOUTE" -- "$(cat <<'DOC'
    echo "===== PORTS TCP/UDP EN ECOUTE ====="
    ss -lntup
    echo
    echo "===== PORTS TCP EN ECOUTE ====="
    ss -lntp
    echo
    echo "===== PORTS UDP EN ECOUTE ====="
    ss -lnup
DOC
)"
    fin_controle
}
