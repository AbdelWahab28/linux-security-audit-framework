#!/usr/bin/env bash
# C05 - Interfaces réseau, IP, routage, DNS et configuration réseau

controle_C05() {
    debut_controle C05 "Réseau" || return 1
    bloc --id C05.reseau --titre "INTERFACES, ROUTAGE, DNS, CONFIGURATION RESEAU" -- "$(cat <<'DOC'
    echo "===== HOST / INTERFACES ====="
    hostname
    ip -br addr
    echo
    echo "===== ROUTING ====="
    ip route
    echo
    echo "===== DNS ====="
    resolvectl status 2>/dev/null || cat /etc/resolv.conf
    echo
    echo "===== NETWORK CONFIGURATION ====="
    ls -la /etc/netplan/ 2>/dev/null
    grep -RhsvE '^[[:space:]]*#|^[[:space:]]*$' /etc/netplan/ 2>/dev/null || true
DOC
)"
    fin_controle
}
