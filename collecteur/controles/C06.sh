#!/usr/bin/env bash
# C06 - Services

controle_C06() {
    debut_controle C06 "Services" || return 1
    bloc --id C06.services --titre "SERVICES ACTIFS ET SERVICES CLES" -- "$(cat <<'DOC'
    echo "===== SERVICES ACTIFS ====="
    systemctl list-units --type=service --state=running --no-legend --no-pager | awk '{print $1}'
    echo
    echo "===== ETAT DES SERVICES CLES ====="
    for svc in nginx postgresql ssh docker containerd rsync smbd nmbd apache2; do
        printf "%-15s : " "$svc"
        systemctl is-active "$svc" 2>/dev/null || true
    done
DOC
)"
    fin_controle
}
