#!/usr/bin/env bash
# C17-01 - systemd / isolation des services

controle_C17_01() {
    debut_controle C17-01 "systemd / isolation des services" || return 1
    [ -s "$REPORT" ] || ajouter_note "Sortie Lynis (C17) absente : les sections Lynis ne peuvent pas être extraites."
    bloc --id C17-01.systemd --titre "C17-01 - SYSTEMD / SERVICES / ISOLATION" -- "$(cat <<'DOC'
    echo "===== C17-01 - SYSTEMD / SERVICES / ISOLATION ====="
    echo "Serveur : $HOST"
    echo "Date/heure : $DATE_AUDIT"
    echo
    echo "===== SECTIONS LYNIS RELATIVES AUX SERVICES ====="
    grep -niE 'boot and services|services|systemd' "$REPORT" 2>/dev/null
    echo
    echo "===== SYSTEMD-ANALYZE SECURITY ====="
    systemd-analyze security --no-pager 2>&1
    echo
    echo "===== SERVICES ACTIFS ====="
    systemctl list-units --type=service --state=running --no-pager 2>&1
    echo
    echo "===== SERVICES ENABLED ====="
    systemctl list-unit-files --type=service --state=enabled --no-pager 2>&1
DOC
)"
    fin_controle
}
