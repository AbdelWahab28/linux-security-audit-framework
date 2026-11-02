#!/usr/bin/env bash
# C09 - SSH

controle_C09() {
    debut_controle C09 "SSH" || return 1
    bloc --id C09.ssh --titre "SSH - SERVICE, VERSION, CONFIGURATION EFFECTIVE" -- "$(cat <<'DOC'
    echo "===== SSH - ETAT DU SERVICE ====="
    systemctl is-active ssh
    echo
    echo "===== SSH - VERSION ====="
    ssh -V 2>&1
    echo
    echo "===== SSH - CONFIGURATION EFFECTIVE ====="
    sudo sshd -T 2>/dev/null | grep -Ei \
    '^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|x11forwarding|allowtcpforwarding|allowagentforwarding|permitemptypasswords|logingracetime|maxauthtries|maxsessions|clientaliveinterval|clientalivecountmax|usedns)\b'
DOC
)"
    fin_controle
}
