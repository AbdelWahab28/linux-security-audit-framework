#!/usr/bin/env bash
# C11 - Permissions

controle_C11() {
    debut_controle C11 "Permissions" || return 1
    bloc --id C11.permissions --titre "FICHIERS ET REPERTOIRES SENSIBLES, SUID/SGID, WORLD-WRITABLE" --delai 900 -- "$(cat <<'DOC'
    echo "===== FICHIERS SENSIBLES ====="
    ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers 2>/dev/null
    echo
    echo "===== REPERTOIRES SENSIBLES ====="
    ls -ld /root /home /tmp /var/tmp 2>/dev/null
    echo
    echo "===== SUID / SGID ====="
    sudo find /usr /bin /sbin /lib /lib64 -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%M %u %g %p\n' 2>/dev/null
    echo
    echo "===== FICHIERS WORLD-WRITABLE ====="
    sudo find /etc /opt /var -xdev -type f -perm -0002 -printf '%M %u %g %p\n' 2>/dev/null
DOC
)"
    fin_controle
}
