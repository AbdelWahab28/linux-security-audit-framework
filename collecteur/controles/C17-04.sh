#!/usr/bin/env bash
# C17-04 - Kernel hardening / sysctl

controle_C17_04() {
    debut_controle C17-04 "Kernel hardening / sysctl" || return 1
    bloc --id C17-04.sysctl --titre "C17-04 - KERNEL HARDENING / SYSCTL" -- "$(cat <<'DOC'
    echo "===== C17-04 - KERNEL HARDENING / SYSCTL ====="
    echo "Serveur : $HOST"
    echo "Date/heure : $DATE_AUDIT"
    echo
    echo "===== SYSCTL - PARAMETRES RESEAU ====="
    sysctl \
        net.ipv4.ip_forward \
        net.ipv4.conf.all.accept_redirects \
        net.ipv4.conf.default.accept_redirects \
        net.ipv4.conf.all.send_redirects \
        net.ipv4.conf.default.send_redirects \
        net.ipv4.conf.all.secure_redirects \
        net.ipv4.conf.default.secure_redirects \
        net.ipv4.conf.all.log_martians \
        net.ipv4.conf.default.log_martians \
        net.ipv4.conf.all.rp_filter \
        net.ipv4.conf.default.rp_filter 2>&1
    echo
    echo "===== LOCALISATION SYSCTL ====="
    command -v sysctl 2>&1
    ls -l /usr/sbin/sysctl /sbin/sysctl 2>&1
    dpkg -S "$(command -v sysctl 2>/dev/null)" 2>&1
    echo
    echo "===== SYSCTL - VERIFICATION VIA /USR/SBIN/SYSCTL ====="
    /usr/sbin/sysctl \
        net.ipv4.ip_forward \
        net.ipv4.conf.all.accept_redirects \
        net.ipv4.conf.default.accept_redirects \
        net.ipv4.conf.all.send_redirects \
        net.ipv4.conf.default.send_redirects \
        net.ipv4.conf.all.secure_redirects \
        net.ipv4.conf.default.secure_redirects \
        net.ipv4.conf.all.log_martians \
        net.ipv4.conf.default.log_martians \
        net.ipv4.conf.all.rp_filter \
        net.ipv4.conf.default.rp_filter 2>&1
    echo
    echo "===== PARAMETRES KERNEL DE SECURITE ====="
    sysctl \
        fs.suid_dumpable \
        fs.protected_symlinks \
        fs.protected_hardlinks \
        kernel.yama.ptrace_scope \
        kernel.kptr_restrict \
        kernel.dmesg_restrict \
        kernel.unprivileged_bpf_disabled \
        kernel.unprivileged_userns_clone 2>&1
    echo
    echo "===== CONFIGURATION SYSCTL PERSISTANTE ====="
    grep -RniE '^[[:space:]]*(net\.ipv4\.|fs\.suid_dumpable|fs\.protected_(symlinks|hardlinks)|kernel\.(yama\.ptrace_scope|kptr_restrict|dmesg_restrict|unprivileged_bpf_disabled|unprivileged_userns_clone))' \
        /etc/sysctl.conf /etc/sysctl.d 2>/dev/null
    echo
    echo "===== CORE DUMPS ====="
    ulimit -c
    echo
    grep -RniE '^[[:space:]]*[^#].*core' \
        /etc/security/limits.conf /etc/security/limits.d 2>/dev/null
    echo
    systemctl status systemd-coredump.socket --no-pager 2>&1
    echo
    systemctl cat systemd-coredump.socket 2>&1
    echo
    sysctl fs.suid_dumpable 2>&1
DOC
)"
    fin_controle
}
