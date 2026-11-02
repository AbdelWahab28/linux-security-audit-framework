#!/usr/bin/env bash
# C13 - Temps et synchronisation

controle_C13() {
    debut_controle C13 "Temps et synchronisation" || return 1
    bloc --id C13.temps --titre "DATE, HEURE, SYNCHRONISATION NTP" -- "$(cat <<'DOC'
    echo "===== DATE / HEURE SYSTEME ====="
    date
    timedatectl
    echo
    echo "===== SYNCHRONISATION NTP ====="
    timedatectl show-timesync --all 2>/dev/null || true
    echo
    echo "===== SERVICES DE SYNCHRONISATION ====="
    systemctl is-active systemd-timesyncd 2>/dev/null || true
    systemctl is-active chrony 2>/dev/null || true
    systemctl is-active ntp 2>/dev/null || true
DOC
)"
    fin_controle
}
