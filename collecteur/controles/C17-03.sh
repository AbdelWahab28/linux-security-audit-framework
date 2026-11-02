#!/usr/bin/env bash
# C17-03 - Permissions / répertoires personnels

controle_C17_03() {
    debut_controle C17-03 "Permissions / répertoires personnels" || return 1
    bloc --id C17-03.permissions --titre "C17-03 - PERMISSIONS / HOME / FICHIERS SYSTEME" --delai 900 -- "$(cat <<'DOC'
    echo "===== C17-03 - PERMISSIONS / HOME / FICHIERS SYSTEME ====="
    echo "Serveur : $HOST"
    echo "Date/heure : $DATE_AUDIT"
    echo
    echo "===== PERMISSIONS SUDOERS ====="
    stat /etc/sudoers 2>&1
    echo
    stat /etc/sudoers.d 2>&1
    echo
    find /etc/sudoers.d -maxdepth 1 -type f -exec stat {} \; 2>&1
    echo
    echo "===== PERMISSIONS HOMES ====="
    for u in $LSAF_COMPTES; do
        echo "===== /home/$u ====="
        stat -c '%A %a %U:%G %n' "/home/$u" 2>&1
    done
    echo
    echo "===== FICHIERS SYSTEME ECRIVABLES PAR GROUPE/AUTRES ====="
    find /etc /usr/local -xdev -type f -perm /022 -ls 2>&1
DOC
)"
    fin_controle
}
