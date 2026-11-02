#!/usr/bin/env bash
# C12 - Logs et journalisation

controle_C12() {
    debut_controle C12 "Logs et journalisation" || return 1
    bloc --id C12.journalisation --titre "SERVICES DE JOURNALISATION, FICHIERS, ROTATION, ERREURS" -- "$(cat <<'DOC'
    echo "===== SERVICES DE JOURNALISATION ====="
    systemctl is-active rsyslog 2>/dev/null || true
    systemctl is-active systemd-journald 2>/dev/null || true
    echo
    echo "===== JOURNAL SYSTEMD ====="
    journalctl --disk-usage 2>/dev/null || true
    echo
    echo "===== FICHIERS DE LOG ====="
    ls -lh /var/log/syslog /var/log/auth.log /var/log/kern.log 2>/dev/null || true
    echo
    echo "===== ROTATION DES LOGS ====="
    ls -la /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null | head -30
    echo
    echo "===== ERREURS RECENTES ====="
    journalctl -p err -b --no-pager -n 30 2>/dev/null || true
DOC
)"
    fin_controle
}
