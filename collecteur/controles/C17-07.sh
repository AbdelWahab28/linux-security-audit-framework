#!/usr/bin/env bash
# C17-07 - Intégrité / protections complémentaires

controle_C17_07() {
    debut_controle C17-07 "Intégrité / protections complémentaires" || return 1
    bloc --id C17-07.integrite --titre "C17-07 - INTEGRITE / ANTIMALWARE / IDS / PERMISSIONS" -- "$(cat <<'DOC'
    echo "===== C17-07 - INTEGRITE / ANTIMALWARE / IDS / PERMISSIONS ====="
    echo "Serveur : $HOST"
    echo "Date/heure : $DATE_AUDIT"
    echo
    echo "===== SECTIONS LYNIS INTEGRITE / MALWARE / DEFENSE ====="
    grep -niE 'file integrity|malware|antivirus|rootkit|intrusion|security frameworks' \
        "$REPORT" 2>/dev/null
    echo
    echo "===== OUTILS INTEGRITE ====="
    for CMD in aide aide.wrapper tripwire samhain ossec-control wazuh-control; do
        echo "--- $CMD ---"
        command -v "$CMD" 2>&1
    done
    echo
    echo "===== PACKAGES INTEGRITE ====="
    dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null \
        | grep -Ei '^(aide|aide-common|tripwire|samhain|ossec|wazuh)'
    echo
    echo "===== ANTIMALWARE / ROOTKIT ====="
    for CMD in clamscan freshclam rkhunter chkrootkit; do
        echo "--- $CMD ---"
        command -v "$CMD" 2>&1
    done
    echo
    echo "===== PACKAGES ANTIMALWARE / ROOTKIT ====="
    dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null \
        | grep -Ei 'clam|rkhunter|chkrootkit'
    echo
    echo "===== IDS / IPS ====="
    for CMD in suricata snort zeek; do
        echo "--- $CMD ---"
        command -v "$CMD" 2>&1
    done
    echo
    echo "===== PACKAGES IDS / IPS ====="
    dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null \
        | grep -Ei '^(suricata|snort|zeek)'
    echo
    echo "===== PERMISSIONS GRUB ====="
    stat /boot/grub/grub.cfg 2>&1
    echo
    echo "===== PERMISSIONS /ETC/CRONTAB ====="
    stat /etc/crontab 2>&1
    echo
    echo "===== PERMISSIONS REPERTOIRES CRON ====="
    find /etc/cron.d /etc/cron.daily /etc/cron.hourly \
         /etc/cron.monthly /etc/cron.weekly \
         -type f -exec stat {} \; 2>&1
DOC
)"
    fin_controle
}
