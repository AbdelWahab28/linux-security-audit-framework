#!/usr/bin/env bash
# C17-06 - Journalisation / audit / défense

controle_C17_06() {
    debut_controle C17-06 "Journalisation / audit / défense" || return 1
    bloc --id C17-06.journalisation --titre "C17-06 - LOGGING / AUDIT / DEFENSE" -- "$(cat <<'DOC'
    echo "===== C17-06 - LOGGING / AUDIT / DEFENSE ====="
    echo "Serveur : $HOST"
    echo "Date/heure : $DATE_AUDIT"
    echo
    echo "===== SECTIONS LYNIS LOGGING / AUDIT ====="
    grep -niE 'logging and files|accounting|audit' "$REPORT" 2>/dev/null
    echo
    echo "===== FICHIERS SUPPRIMES MAIS ENCORE OUVERTS ====="
    if command -v lsof >/dev/null 2>&1; then
        lsof +L1 2>&1
    else
        echo "lsof : commande absente"
    fi
    echo
    echo "===== SYSTEMD-JOURNald ====="
    systemctl is-active systemd-journald 2>&1
    systemctl is-enabled systemd-journald 2>&1
    echo
    echo "===== JOURNALD - CONFIGURATION EFFECTIVE ====="
    grep -RniE '^[[:space:]]*(ForwardToSyslog|ForwardToKMsg|ForwardToConsole|ForwardToWall|Storage|SystemMaxUse|RuntimeMaxUse)' \
        /etc/systemd/journald.conf /etc/systemd/journald.conf.d 2>/dev/null
    echo
    echo "===== RSYSLOG ====="
    systemctl is-active rsyslog 2>&1
    systemctl is-enabled rsyslog 2>&1
    echo
    echo "===== RSYSLOG - CONFIGURATION ====="
    grep -RniE '^[[:space:]]*[^#].*(omfwd|@@|@[^@[:space:]])' \
        /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null
    echo
    echo "===== RSYSLOG - FICHIERS DE CONFIGURATION ====="
    find /etc/rsyslog.d -maxdepth 1 -type f -print 2>&1
    echo
    echo "===== JOURNAL 24H - ERREURS / ALERTES ====="
    journalctl --since "24 hours ago" --no-pager 2>/dev/null \
        | grep -Ei 'error|failed|warning|critical|alert' \
        | tail -200
DOC
)"
    fin_controle
}
