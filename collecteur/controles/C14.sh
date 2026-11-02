#!/usr/bin/env bash
# C14 - Tâches planifiées (cron, timers systemd)

controle_C14() {
    debut_controle C14 "Tâches planifiées" || return 1
    bloc --id C14.taches --titre "CRON ET TIMERS SYSTEMD" -- "$(cat <<'DOC'
    echo "===== CRON - TACHES PLANIFIEES ====="
    sudo crontab -l 2>/dev/null || true
    echo
    echo "===== CRON SYSTEME ====="
    ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null
    echo
    echo "===== SYSTEMD TIMERS ====="
    systemctl list-timers --all --no-pager
DOC
)"
    fin_controle
}
