#!/usr/bin/env bash
# C04 - Logiciels installés

controle_C04() {
    debut_controle C04 "Logiciels installés" || return 1
    bloc --id C04.logiciels --titre "PRINCIPAUX LOGICIELS" -- "$(cat <<'DOC'
    echo "===== PRINCIPAUX LOGICIELS ====="
    dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | \
    grep -Ei 'postgres|apache|nginx|docker|containerd|php|python|nodejs|java|openssh|samba|rsync' || true
DOC
)"
    bloc --id C04.services --titre "SERVICES ASSOCIES AUX LOGICIELS DETECTES" -- "$(cat <<'DOC'
    echo "===== SERVICES ASSOCIES AUX LOGICIELS DETECTES ====="
    echo
    echo "--- NGINX ---"
    systemctl status nginx --no-pager 2>&1 | head -n 12
    echo
    echo "--- SSH ---"
    systemctl status ssh --no-pager 2>&1 | head -n 12
    echo
    echo "--- RSYNC ---"
    systemctl status rsync --no-pager 2>&1 | head -n 12
DOC
)"
    fin_controle
}
