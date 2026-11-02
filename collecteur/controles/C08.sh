#!/usr/bin/env bash
# C08 - Pare-feu / filtrage réseau

controle_C08() {
    debut_controle C08 "Pare-feu / filtrage réseau" || return 1
    bloc --id C08.parefeu --titre "ETAT DU FIREWALL" -- "$(cat <<'DOC'
    echo "===== ETAT DU FIREWALL ====="
    sudo ufw status verbose 2>/dev/null || true
    echo
    echo "===== NFTABLES ====="
    sudo nft list ruleset 2>/dev/null || true
    echo
    echo "===== IPTABLES ====="
    sudo iptables -L -n -v 2>/dev/null || true
    echo
    echo "===== FIREWALLD ====="
    sudo firewall-cmd --state 2>/dev/null || true
DOC
)"
    fin_controle
}
