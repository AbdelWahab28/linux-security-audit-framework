#!/usr/bin/env bash
# C03 - État des mises à jour

controle_C03() {
    debut_controle C03 "État des mises à jour" || return 1
    bloc --id C03.paquets --titre "PAQUETS POUVANT ETRE MIS A JOUR" -- "$(cat <<'DOC'
apt list --upgradable 2>/dev/null
DOC
)"
    bloc --id C03.policy --titre "VERSIONS CANDIDATES (apt-cache policy)" -- "$(cat <<'DOC'
    echo "===== PAQUETS INTERROGES ====="
    apt-cache policy $LSAF_PAQUETS_POLICY
DOC
)"
    bloc --id C03.noyau --titre "NOYAU ET REDEMARRAGE" -- "$(cat <<'DOC'
    echo "===== KERNEL RUNNING ====="
    uname -r
    echo
    echo "===== INSTALLED KERNEL PACKAGES ====="
    dpkg -l 'linux-image*' 'linux-headers*' 2>/dev/null | grep '^ii'
    echo
    echo "===== REBOOT STATUS ====="
    if [ -f /var/run/reboot-required ]; then
        echo "REBOOT_REQUIRED=YES"
        cat /var/run/reboot-required.pkgs 2>/dev/null
    else
        echo "REBOOT_REQUIRED=NO"
    fi
DOC
)"
    bloc --id C03.sources --titre "SOURCES APT" -- "$(cat <<'DOC'
    echo "===== APT SOURCES CONFIGURATION ====="
    echo "--- /etc/apt/sources.list.d ---"
    find /etc/apt/sources.list.d -maxdepth 1 -type f -print -exec sh -c 'echo "--- $1 ---"; cat "$1"' _ {} \;
    echo
    echo "--- /etc/apt/sources.list ---"
    if [ -f /etc/apt/sources.list ]; then
        cat /etc/apt/sources.list
    else
        echo "FICHIER ABSENT"
    fi
DOC
)"
    fin_controle
}
