#!/usr/bin/env bash
# C17-05 - Réseau / firewall / exposition / TLS

controle_C17_05() {
    debut_controle C17-05 "Réseau / firewall / exposition / TLS" || return 1
    bloc --id C17-05.reseau --titre "C17-05 - RESEAU / FIREWALL / EXPOSITION / TLS" -- "$(cat <<'DOC'
    echo "===== C17-05 - RESEAU / FIREWALL / EXPOSITION / TLS ====="
    echo "Serveur : $HOST"
    echo "Date/heure : $DATE_AUDIT"
    echo
    echo "===== SECTIONS LYNIS RESEAU / FIREWALL / WEB / CRYPTO ====="
    grep -niE 'networking|firewalls|web servers|cryptography|ssh support' \
        "$REPORT" 2>/dev/null
    echo
    echo "===== APACHE - ETAT ====="
    systemctl is-active apache2 2>&1
    systemctl is-enabled apache2 2>&1
    pgrep -a apache2 2>&1
    echo
    echo "===== APACHE - CONFIGURATION ====="
    if command -v apache2ctl >/dev/null 2>&1; then
        apache2ctl -V 2>&1 | grep -E 'SERVER_CONFIG_FILE|SERVER_ROOT'
        apache2ctl -t 2>&1
    else
        echo "apache2ctl : commande absente"
    fi
    echo
    echo "===== CUPS - PERMISSIONS ====="
    stat /etc/cups/cupsd.conf 2>&1
    stat /etc/cups 2>&1
    find /etc/cups -type f -exec stat {} \; 2>&1
    echo
    echo "===== UFW ====="
    ufw status verbose 2>&1
    echo
    echo "===== NFTABLES ====="
    sudo nft list ruleset 2>&1
    echo
    echo "===== IPTABLES FILTER ====="
    sudo iptables -L -n -v 2>&1
    echo
    echo "===== IPTABLES NAT ====="
    sudo iptables -t nat -L -n -v 2>&1
    echo
    echo "===== IPV6 - ADRESSES GLOBALES ====="
    ip -6 addr show scope global 2>&1
    echo
    echo "===== IPV6 - ROUTES ====="
    ip -6 route 2>&1
    echo
    echo "===== ECOUTE IPV6 ====="
    ss -lntup 2>&1 | grep -E '::|:::'
    echo
    echo "===== TLS - PORTS CIBLES ====="
    for PORT in $LSAF_PORTS_TLS; do
        echo
        echo "----- PORT $PORT -----"
        timeout 8 openssl s_client \
            -connect "127.0.0.1:$PORT" \
            -servername "$HOST" \
            </dev/null 2>&1 \
            | grep -Ei 'CONNECTED|Protocol|Cipher|Verify return code|subject=|issuer='
    done
DOC
)"
    bloc --id C17-05.certificats --titre "C17-05 - QUALIFICATION CERTIFICATS TLS" -- "$(cat <<'DOC'
    echo "===== C17-05 - QUALIFICATION CERTIFICATS TLS ====="
    echo "Serveur : $HOST"
    echo "Date/heure : $DATE_AUDIT"
    echo
    for PORT in $LSAF_PORTS_TLS; do
        echo
        echo "============================================================"
        echo " PORT TLS : $PORT"
        echo "============================================================"
        timeout 10 openssl s_client \
            -connect "127.0.0.1:$PORT" \
            -servername "$HOST" \
            -showcerts </dev/null 2>/dev/null \
        | openssl x509 -noout \
            -subject \
            -issuer \
            -dates \
            -serial \
            -fingerprint -sha256 \
            -ext subjectAltName \
            -text 2>&1 \
        | grep -Ei \
            'subject=|issuer=|notBefore=|notAfter=|serial=|sha256 fingerprint|DNS:|IP Address:|Signature Algorithm|Public Key Algorithm|Public-Key'
    done
DOC
)"
    fin_controle
}
