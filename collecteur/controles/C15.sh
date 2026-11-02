#!/usr/bin/env bash
# C15 - Mécanismes de sécurité et de confinement

controle_C15() {
    debut_controle C15 "Mécanismes de sécurité et de confinement" || return 1
    bloc --id C15.securite --titre "AGENTS / MECANISMES DE SECURITE" -- "$(cat <<'DOC'
    echo "===== AGENTS / MECANISMES DE SECURITE ====="
    echo "--- Services sécurité ---"
    systemctl list-units --type=service --state=running --no-legend --no-pager | \
    grep -Ei 'audit|beat|sophos|wazuh|ossec|falcon|defender|clam|antivirus|edr|agent|security' || true
    echo
    echo "--- Processus sécurité ---"
    ps aux | grep -Ei 'auditbeat|sophos|wazuh|ossec|falcon|defender|clam|antivirus|edr' | grep -v grep || true
    echo
    echo "--- Paquets sécurité ---"
    dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | \
    grep -Ei 'auditbeat|sophos|wazuh|ossec|falcon|clamav|antivirus|security' || true
DOC
)"
    fin_controle
}
