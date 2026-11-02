"""Générateur de sessions SYNTHÉTIQUES (données entièrement fictives).

Utilisé par les tests et par « lsaf demo ». Toutes les valeurs sont inventées :
serveurs SRV-EXEMPLE-xx, adresses des plages réservées à la documentation
(RFC 5737 : 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), comptes génériques
(auditeur, appli), identifiants CVE volontairement invalides (CVE-2099-…).
Le format des sorties reproduit celui des commandes du collecteur.

Profils : « faible » (serveur volontairement mal configuré) et « durci ».
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional

from .controles import CONTROLES_COLLECTES, PAR_ID

BANDEAU = "DONNEES SYNTHETIQUES - SERVEUR FICTIF GENERE PAR « lsaf demo » - AUCUN RESULTAT D'AUDIT REEL"


def _sorties(profil: str, hote: str, ip: str, fuseau: str) -> dict:
    f = profil == "faible"
    h = hote.lower()
    noyau = "5.15.0-105-generic" if f else "6.1.0-21-amd64"
    os_release = ('PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian'
                  if f else 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\nID=debian')
    o = {}
    o["C01.identification"] = f"""==================================================
CONTROLE C01 - IDENTIFICATION DU SYSTEME
Date de collecte : 2026-11-02 10:15:00 UTC
==================================================

### NOM D'HOTE
{h}
{h}

### SYSTEME D'EXPLOITATION
{os_release}

### NOYAU ACTIF
Linux {h} {noyau} #1 SMP x86_64 GNU/Linux

### ARCHITECTURE
x86_64
64

### VIRTUALISATION
kvm
Code retour détection virtualisation : 0

### FIN DU CONTROLE C01"""
    racine = "96%" if f else "41%"
    o["C02.ressources"] = f"""===== UPTIME / LOAD =====
 10:15:00 up 41 days,  2:03,  1 user,  load average: 0.42, 0.37, 0.30

===== CPU =====
Architecture:                       x86_64
CPU(s):                             4
Model name:                         Processeur virtuel fictif
Thread(s) per core:                 1

===== MEMORY / SWAP =====
               total        used        free      shared  buff/cache   available
Mem:           7.8Gi       3.1Gi       1.2Gi        12Mi       3.5Gi       4.4Gi
Swap:          2.0Gi          0B       2.0Gi

===== DISK =====
Filesystem     Type   Size  Used Avail Use% Mounted on
tmpfs          tmpfs  790M  1.2M  789M   1% /run
/dev/vda1      ext4    40G   38G  1.6G  {racine} /

===== INODES =====
Filesystem     Inodes IUsed IFree IUse% Mounted on
/dev/vda1        2.5M  180K  2.4M    7% /"""
    if f:
        o["C03.paquets"] = ("Listing...\nlibexemple1/jammy-updates,jammy-security 1.0-2 amd64 [upgradable from: 1.0-1]\n"
                            "openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.99 amd64 [upgradable from: 3.0.2-0ubuntu1.10]\n"
                            "vim-tiny/jammy-updates 2:8.2.3995-1ubuntu2.99 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.1]")
        o["C03.noyau"] = ("===== KERNEL RUNNING =====\n5.15.0-105-generic\n\n===== INSTALLED KERNEL PACKAGES =====\n"
                          "ii  linux-image-5.15.0-105-generic 5.15.0-105.115 amd64 Signed kernel image generic\n"
                          "ii  linux-image-5.15.0-112-generic 5.15.0-112.122 amd64 Signed kernel image generic\n\n"
                          "===== REBOOT STATUS =====\nREBOOT_REQUIRED=YES\nlinux-image-5.15.0-112-generic")
    else:
        o["C03.paquets"] = "Listing..."
        o["C03.noyau"] = ("===== KERNEL RUNNING =====\n6.1.0-21-amd64\n\n===== INSTALLED KERNEL PACKAGES =====\n"
                          "ii  linux-image-6.1.0-21-amd64 6.1.90-1 amd64 Linux 6.1 for 64-bit PCs (signed)\n\n"
                          "===== REBOOT STATUS =====\nREBOOT_REQUIRED=NO")
    o["C03.policy"] = "===== PAQUETS INTERROGES =====\nopenssh-server:\n  Installed: 1:9.2p1-2\n  Candidate: 1:9.2p1-2"
    o["C03.sources"] = ("===== APT SOURCES CONFIGURATION =====\n--- /etc/apt/sources.list.d ---\n\n--- /etc/apt/sources.list ---\n"
                        "deb http://deb.example.org/debian stable main")
    o["C04.logiciels"] = ("===== PRINCIPAUX LOGICIELS =====\nnginx\t1.22.1-9\nopenssh-server\t1:9.2p1-2\npython3\t3.11.2-1"
                          + ("\ndocker.io\t24.0.7-0ubuntu2\npostgresql-14\t14.11-0ubuntu0.22.04.1" if f else ""))
    o["C04.services"] = ("===== SERVICES ASSOCIES AUX LOGICIELS DETECTES =====\n\n--- NGINX ---\n● nginx.service - A high performance web server\n"
                         "     Active: active (running) since Mon 2026-09-21\n\n--- SSH ---\n● ssh.service - OpenBSD Secure Shell server\n"
                         "     Active: active (running) since Mon 2026-09-21\n\n--- RSYNC ---\nUnit rsync.service could not be found.")
    o["C05.reseau"] = (f"===== HOST / INTERFACES =====\n{h}\nlo               UNKNOWN        127.0.0.1/8 ::1/128\n"
                       f"ens33            UP             {ip}/24 fe80::1/64\n\n===== ROUTING =====\ndefault via 192.0.2.1 dev ens33 proto static\n"
                       f"192.0.2.0/24 dev ens33 proto kernel scope link src {ip}\n\n===== DNS =====\nGlobal\nLink 2 (ens33)\n"
                       + ("Current DNS Server: 8.8.8.8\n       DNS Servers: 8.8.8.8 198.51.100.53" if f else
                          "Current DNS Server: 198.51.100.53\n       DNS Servers: 198.51.100.53")
                       + "\n\n===== NETWORK CONFIGURATION =====\n-rw------- 1 root root 300 Jan 10 01-netcfg.yaml\nnetwork:\n  version: 2")
    actifs = ["cron.service", "dbus.service", "nginx.service", "rsyslog.service", "ssh.service", "systemd-journald.service",
              "systemd-timesyncd.service"] + (["containerd.service", "docker.service", "postgresql.service"] if f
                                              else ["auditd.service", "agent-securite-exemple.service"])
    o["C06.services"] = ("===== SERVICES ACTIFS =====\n" + "\n".join(sorted(actifs)) + "\n\n===== ETAT DES SERVICES CLES =====\n"
                         "nginx           : active\npostgresql      : " + ("active" if f else "inactive") + "\nssh             : active\n"
                         "docker          : " + ("active" if f else "inactive") + "\ncontainerd      : " + ("active" if f else "inactive")
                         + "\nrsync           : inactive\nsmbd            : inactive\nnmbd            : inactive\napache2         : inactive")
    ecoutes = ['tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=812,fd=6))',
               'tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=601,fd=14))']
    ecoutes += (['tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=901,fd=3))',
                 'tcp   LISTEN 0      4096         0.0.0.0:5432      0.0.0.0:*    users:(("docker-proxy",pid=1402,fd=4))',
                 'tcp   LISTEN 0      511          0.0.0.0:443       0.0.0.0:*    users:(("nginx",pid=812,fd=7))']
                if f else [f'tcp   LISTEN 0      128      {ip}:22        0.0.0.0:*    users:(("sshd",pid=901,fd=3))',
                           'tcp   LISTEN 0      511          0.0.0.0:443       0.0.0.0:*    users:(("nginx",pid=812,fd=7))'])
    entete_ss = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess"
    o["C07.ports"] = ("===== PORTS TCP/UDP EN ECOUTE =====\n" + entete_ss + "\n" + "\n".join(ecoutes)
                      + "\n\n===== PORTS TCP EN ECOUTE =====\nState Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n\n"
                        "===== PORTS UDP EN ECOUTE =====\nState Recv-Q Send-Q Local Address:Port Peer Address:PortProcess")
    if f:
        ufw = "Status: inactive"
        nft = "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}"
        ipt = ("Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\n pkts bytes target     prot opt in     out     source               destination\n\n"
               "Chain FORWARD (policy DROP 0 packets, 0 bytes)\n pkts bytes target     prot opt in     out     source               destination\n\n"
               "Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)\n pkts bytes target     prot opt in     out     source               destination")
    else:
        ufw = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)"
        nft = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}"
        ipt = "Chain INPUT (policy DROP 0 packets, 0 bytes)\n pkts bytes target     prot opt in     out     source               destination"
    o["C08.parefeu"] = f"===== ETAT DU FIREWALL =====\n{ufw}\n\n===== NFTABLES =====\n{nft}\n\n===== IPTABLES =====\n{ipt}\n\n===== FIREWALLD ====="
    conf = {"port": "22", "listenaddress": "0.0.0.0:22" if f else f"{ip}:22", "permitrootlogin": "without-password" if f else "no",
            "pubkeyauthentication": "yes", "passwordauthentication": "yes" if f else "no", "kbdinteractiveauthentication": "no",
            "permitemptypasswords": "no", "maxauthtries": "6" if f else "3", "maxsessions": "10", "logingracetime": "120",
            "x11forwarding": "yes" if f else "no", "allowtcpforwarding": "yes" if f else "no", "allowagentforwarding": "yes",
            "clientaliveinterval": "0" if f else "300", "clientalivecountmax": "3", "usedns": "no"}
    o["C09.ssh"] = ("===== SSH - ETAT DU SERVICE =====\nactive\n\n===== SSH - VERSION =====\nOpenSSH_9.2p1 Debian-2, OpenSSL 3.0.13 30 Jan 2024\n\n"
                    "===== SSH - CONFIGURATION EFFECTIVE =====\n" + "\n".join(f"{k} {v}" for k, v in conf.items()))
    o["C10.comptes"] = ("===== COMPTES UTILISATEURS =====\nauditeur:1000:/home/auditeur:/bin/bash\nappli:1001:/home/appli:/bin/bash\n\n"
                        "===== COMPTE ROOT =====\n" + ("root P 2026-01-10 0 99999 7 -1" if f else "root L 2026-01-10 0 99999 7 -1")
                        + "\n\n===== GROUPES PRIVILEGIES =====\nsudo:x:27:auditeur" + (",appli" if f else "") + "\nadm:x:4:syslog,auditeur\n\n"
                        "===== COMPTES AVEC SHELL INTERACTIF =====\nroot:0:/root:/bin/bash\nauditeur:1000:/home/auditeur:/bin/bash\n"
                        "appli:1001:/home/appli:/bin/bash\n\n===== COMPTES VERROUILLES / NON VERROUILLES =====\n"
                        "daemon:LOCKED\nbin:LOCKED\nappli:LOCKED" + ("" if f else "\nroot:LOCKED"))
    o["C11.permissions"] = ("===== FICHIERS SENSIBLES =====\n-rw-r--r-- 1 root root   2100 Jan 10 09:00 /etc/group\n"
                            "-rw-r--r-- 1 root root   3100 Jan 10 09:00 /etc/passwd\n"
                            + ("-rw-r--r-- 1 root shadow 1500 Jan 10 09:00 /etc/shadow\n" if f else "-rw-r----- 1 root shadow 1500 Jan 10 09:00 /etc/shadow\n")
                            + "-r--r----- 1 root root    755 Jan 10 09:00 /etc/sudoers\n\n===== REPERTOIRES SENSIBLES =====\n"
                              "drwxr-xr-x  4 root root 4096 Jan 10 09:00 /home\ndrwx------  5 root root 4096 Jan 10 09:00 /root\n"
                              "drwxrwxrwt 12 root root 4096 Nov  2 10:00 /tmp\ndrwxrwxrwt  6 root root 4096 Nov  2 10:00 /var/tmp\n\n"
                              "===== SUID / SGID =====\n-rwsr-xr-x root root /usr/bin/passwd\n-rwsr-xr-x root root /usr/bin/sudo\n\n"
                              "===== FICHIERS WORLD-WRITABLE =====" + ("\n-rw-rw-rw- root root /etc/appli-exemple.conf" if f else ""))
    o["C12.journalisation"] = ("===== SERVICES DE JOURNALISATION =====\nactive\nactive\n\n===== JOURNAL SYSTEMD =====\n"
                               "Archived and active journals take up 512.0M in the file system.\n\n===== FICHIERS DE LOG =====\n"
                               "-rw-r----- 1 syslog adm 1.2M Nov  2 10:00 /var/log/auth.log\n-rw-r----- 1 syslog adm 5.0M Nov  2 10:00 /var/log/syslog\n\n"
                               "===== ROTATION DES LOGS =====\n-rw-r--r-- 1 root root 591 Jan 10 /etc/logrotate.conf\n\n===== ERREURS RECENTES =====\n"
                               + ("Nov 02 09:00:01 exemple kernel: ligne d'erreur fictive" if f else "-- No entries --"))
    synchro = "no" if f else "yes"
    o["C13.temps"] = (f"===== DATE / HEURE SYSTEME =====\nMon Nov  2 10:15:00 UTC 2026\n               Local time: Mon 2026-11-02 10:15:00 UTC\n"
                      f"                Time zone: {fuseau} (UTC, +0000)\nSystem clock synchronized: {synchro}\n              NTP service: active\n\n"
                      "===== SYNCHRONISATION NTP =====\n" + ("ServerName=ntp.example.org" if f else "ServerName=ntp1.example.org")
                      + "\n\n===== SERVICES DE SYNCHRONISATION =====\nactive\ninactive\ninactive")
    o["C14.taches"] = ("===== CRON - TACHES PLANIFIEES =====\n30 2 * * * /usr/local/bin/sauvegarde-exemple.sh\n\n===== CRON SYSTEME =====\n"
                       "/etc/cron.d:\ntotal 12\ndrwxr-xr-x 2 root root 4096 Jan 10 .\n-rw-r--r-- 1 root root  102 Jan 10 e2scrub_all\n\n"
                       "===== SYSTEMD TIMERS =====\nNEXT LEFT LAST PASSED UNIT ACTIVATES\n2 timers listed.")
    o["C15.securite"] = ("===== AGENTS / MECANISMES DE SECURITE =====\n--- Services sécurité ---\n"
                         + ("" if f else "auditd.service loaded active running Security Auditing Service\n"
                                         "agent-securite-exemple.service loaded active running Agent de sécurité fictif\n")
                         + "\n--- Processus sécurité ---\n\n--- Paquets sécurité ---\n" + ("" if f else "auditd\t1:3.0.9-1"))
    o["C16.identification"] = ("===== DEBSECAN - IDENTIFICATION =====\nServeur : exemple\nDate/heure : Mon Nov  2 10:15:00 UTC 2026\n\n"
                               "===== INSTALLATION =====\nii  debsecan 0.4.20.1 all Debian Security Analyzer\n\n===== VERSION =====\ndebsecan 0.4.20.1")
    if f:
        o["C16.standard"] = "CVE-2099-0001 libexemple1 (remotely exploitable, high urgency)\nCVE-2099-0002 vim-tiny (low urgency)"
        o["C16.detail"] = ("CVE-2099-0001 (remotely exploitable, high urgency)\n  installed: libexemple1 1.0-1\n             (built from libexemple 1.0-1)\n"
                           "CVE-2099-0002 (low urgency)\n  installed: vim-tiny 2:8.2.3995-1ubuntu2.1")
    else:
        o["C16.standard"] = "CVE-2099-0003 libexemple2 (fixed, low urgency)"
        o["C16.detail"] = "CVE-2099-0003 (fixed, low urgency)\n  installed: libexemple2 2.0-1\n  fixed on branch:   libexemple2 2.0-1+deb12u1"
    o["C16.systeme"] = os_release
    o["C17.identification"] = (f"===== C17 - AUDIT LYNIS GLOBAL =====\nServeur : {h}\nDate/heure : 2026-11-02 10:15:00\n\n===== VERSION LYNIS =====\n"
                               "/usr/sbin/lynis\n3.0.9\n\n===== VERIFICATION DES PRIVILEGES SUDO =====\nCode retour sudo : 0\n\n"
                               "===== IDENTITE COURANTE =====\nuid=0(root) gid=0(root) groups=0(root)")
    indice = 58 if f else 79
    o["C17.audit_lynis"] = ("[+] Boot and services\n------------------------------------\n  - Service Manager [ systemd ]\n\n"
                            "[+] Logging and files\n------------------------------------\n\n[+] Networking\n------------------------------------\n\n"
                            "================================================================================\n\n  -[ Lynis 3.0.9 Results ]-\n\n"
                            "  Warnings (1):\n  ----------------------------\n  ! Avertissement fictif sur un paramètre de configuration [EXMP-0001]\n\n"
                            "  Suggestions (2):\n  ----------------------------\n  * Suggestion fictive numéro un [EXMP-0002]\n  * Suggestion fictive numéro deux [EXMP-0003]\n\n"
                            "================================================================================\n\n  Lynis security scan details:\n\n"
                            f"  Hardening index : {indice} [###########         ]\n  Tests performed : 251\n")
    o["C17.sections"] = "1:[+] Boot and services\n4:[+] Logging and files\n7:[+] Networking"
    o["C17.resultats"] = f"12:  Warnings (1):\n16:  Suggestions (2):\n24:  Hardening index : {indice} [###########         ]\n25:  Tests performed : 251"
    unites = ["cron.service                    9.6 UNSAFE    :-(", "ssh.service                     9.6 UNSAFE    :-(",
              "nginx.service                   " + ("9.6 UNSAFE    :-(" if f else "4.4 OK        :-)"),
              "systemd-journald.service        4.4 OK        :-)"] + (["postgresql.service              9.2 UNSAFE    :-("] if f else [])
    o["C17-01.systemd"] = (f"===== C17-01 - SYSTEMD / SERVICES / ISOLATION =====\nServeur : {h}\nDate/heure : 2026-11-02 10:15:00\n\n"
                           "===== SECTIONS LYNIS RELATIVES AUX SERVICES =====\n1:[+] Boot and services\n\n===== SYSTEMD-ANALYZE SECURITY =====\n"
                           "UNIT                                 EXPOSURE PREDICATE HAPPY\n" + "\n".join(unites)
                           + "\n\n===== SERVICES ACTIFS =====\n  UNIT LOAD ACTIVE SUB DESCRIPTION\n"
                           + "\n".join(f"  {s} loaded active running Service fictif" for s in sorted(actifs))
                           + "\n\n===== SERVICES ENABLED =====\nUNIT FILE STATE PRESET\n" + "\n".join(f"{s} enabled enabled" for s in sorted(actifs)))
    o["C17-02.authentification"] = (f"===== C17-02 - AUTHENTIFICATION / MOTS DE PASSE =====\nServeur : {h}\nDate/heure : 2026-11-02 10:15:00\n\n"
                                    "===== POLITIQUE /ETC/LOGIN.DEFS =====\n"
                                    + ("131:PASS_MAX_DAYS\t99999\n132:PASS_MIN_DAYS\t0\n133:PASS_WARN_AGE\t7\n151:UMASK\t\t022" if f else
                                       "131:PASS_MAX_DAYS\t180\n132:PASS_MIN_DAYS\t1\n133:PASS_WARN_AGE\t14\n151:UMASK\t\t027")
                                    + "\n\n===== COMPTE : auditeur =====\nLast password change\t\t\t\t\t: Jan 10, 2026\n"
                                    "Maximum number of days between password change\t\t: " + ("99999" if f else "180")
                                    + "\n\n===== COMPTE : appli =====\nMaximum number of days between password change\t\t: " + ("99999" if f else "180")
                                    + "\n\n===== PAM - PASSWORD STRENGTH =====\n/etc/pam.d/common-password:25:password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt"
                                    + ("\n/etc/pam.d/common-auth:17:auth\t[success=1 default=ignore]\tpam_unix.so nullok" if f else
                                       "\n/etc/pam.d/common-password:24:password\trequisite\tpam_pwquality.so retry=3")
                                    + "\n\n===== PAM - LOCKOUT / FAILED AUTHENTICATION =====\n"
                                    + ("" if f else "/etc/pam.d/common-auth:16:auth\trequired\tpam_faillock.so preauth")
                                    + "\n\n===== COMMAND FAILLOCK =====\n" + ("" if f else "/usr/sbin/faillock")
                                    + "\n\n===== AUTHENTIFICATIONS ECHOUEES - 24H =====\n"
                                    + ("Nov 02 08:00:00 exemple sshd[1000]: Failed password for invalid user test from 203.0.113.50 port 50000 ssh2" if f else ""))
    o["C17-03.permissions"] = (f"===== C17-03 - PERMISSIONS / HOME / FICHIERS SYSTEME =====\nServeur : {h}\nDate/heure : 2026-11-02 10:15:00\n\n"
                               "===== PERMISSIONS SUDOERS =====\n  File: /etc/sudoers\n  Size: 755 Blocks: 8 IO Block: 4096 regular file\n"
                               "Access: (0440/-r--r-----)  Uid: (    0/    root)   Gid: (    0/    root)\n\n  File: /etc/sudoers.d\n"
                               "Access: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\n\n===== PERMISSIONS HOMES =====\n"
                               "===== /home/auditeur =====\n" + ("drwxr-xr-x 755 auditeur:auditeur /home/auditeur" if f else "drwxr-x--- 750 auditeur:auditeur /home/auditeur")
                               + "\n===== /home/appli =====\ndrwx------ 700 appli:appli /home/appli\n\n===== FICHIERS SYSTEME ECRIVABLES PAR GROUPE/AUTRES =====\n"
                               + ("  1234   4 -rw-rw-r--   1 root     root          120 Jan 10 09:00 /etc/appli-exemple/reglages.ini" if f else ""))
    reseau = {"net.ipv4.ip_forward": "1" if f else "0", "net.ipv4.conf.all.accept_redirects": "1" if f else "0",
              "net.ipv4.conf.default.accept_redirects": "1" if f else "0", "net.ipv4.conf.all.send_redirects": "1" if f else "0",
              "net.ipv4.conf.default.send_redirects": "1" if f else "0", "net.ipv4.conf.all.secure_redirects": "1" if f else "0",
              "net.ipv4.conf.default.secure_redirects": "1" if f else "0", "net.ipv4.conf.all.log_martians": "0" if f else "1",
              "net.ipv4.conf.default.log_martians": "0" if f else "1", "net.ipv4.conf.all.rp_filter": "2" if f else "1",
              "net.ipv4.conf.default.rp_filter": "2" if f else "1"}
    securite = {"fs.suid_dumpable": "2" if f else "0", "fs.protected_symlinks": "1", "fs.protected_hardlinks": "1",
                "kernel.yama.ptrace_scope": "1", "kernel.kptr_restrict": "1", "kernel.dmesg_restrict": "0" if f else "1",
                "kernel.unprivileged_bpf_disabled": "2"}
    txt_reseau = "\n".join(f"{k} = {v}" for k, v in reseau.items())
    o["C17-04.sysctl"] = (f"===== C17-04 - KERNEL HARDENING / SYSCTL =====\nServeur : {h}\nDate/heure : 2026-11-02 10:15:00\n\n"
                          f"===== SYSCTL - PARAMETRES RESEAU =====\n{txt_reseau}\n\n===== LOCALISATION SYSCTL =====\n/usr/sbin/sysctl\n\n"
                          f"===== SYSCTL - VERIFICATION VIA /USR/SBIN/SYSCTL =====\n{txt_reseau}\n\n===== PARAMETRES KERNEL DE SECURITE =====\n"
                          + "\n".join(f"{k} = {v}" for k, v in securite.items())
                          + "\nsysctl: cannot stat /proc/sys/kernel/unprivileged_userns_clone: No such file or directory\n\n"
                            "===== CONFIGURATION SYSCTL PERSISTANTE =====\n"
                          + ("" if f else "/etc/sysctl.d/60-exemple.conf:1:net.ipv4.conf.all.accept_redirects = 0")
                          + "\n\n===== CORE DUMPS =====\n0\n\n○ systemd-coredump.socket\n     Active: inactive (dead)\n\n"
                          + f"fs.suid_dumpable = {securite['fs.suid_dumpable']}")
    if f:
        tls = ("----- PORT 443 -----\nCONNECTED(00000003)\nsubject=CN = srv-exemple-01.example.org\nissuer=CN = srv-exemple-01.example.org\n"
               "Verify return code: 18 (self-signed certificate)\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384")
        cert = ("subject=CN = srv-exemple-01.example.org\nissuer=CN = srv-exemple-01.example.org\nnotBefore=Jan  1 00:00:00 2024 GMT\n"
                "notAfter=Jan  1 00:00:00 2025 GMT\nserial=01")
    else:
        tls = ("----- PORT 443 -----\nCONNECTED(00000003)\nsubject=CN = srv-exemple-02.example.org\nissuer=CN = AC interne fictive\n"
               "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nVerify return code: 0 (ok)")
        cert = ("subject=CN = srv-exemple-02.example.org\nissuer=CN = AC interne fictive\nnotBefore=Jan  1 00:00:00 2026 GMT\n"
                "notAfter=Jan  1 00:00:00 2027 GMT\nserial=02")
    o["C17-05.reseau"] = (f"===== C17-05 - RESEAU / FIREWALL / EXPOSITION / TLS =====\nServeur : {h}\nDate/heure : 2026-11-02 10:15:00\n\n"
                          "===== SECTIONS LYNIS RESEAU / FIREWALL / WEB / CRYPTO =====\n7:[+] Networking\n\n===== APACHE - ETAT =====\ninactive\ndisabled\n\n"
                          "===== APACHE - CONFIGURATION =====\napache2ctl : commande absente\n\n===== CUPS - PERMISSIONS =====\n"
                          f"stat: cannot statx '/etc/cups/cupsd.conf': No such file or directory\n\n===== UFW =====\n{ufw}\n\n===== NFTABLES =====\n{nft}\n\n"
                          f"===== IPTABLES FILTER =====\n{ipt}\n\n===== IPTABLES NAT =====\nChain PREROUTING (policy ACCEPT 0 packets, 0 bytes)\n\n"
                          "===== IPV6 - ADRESSES GLOBALES =====\n\n===== IPV6 - ROUTES =====\n\n===== ECOUTE IPV6 =====\n\n"
                          f"===== TLS - PORTS CIBLES =====\n\n{tls}\n\n----- PORT 8443 -----\n\n----- PORT 9443 -----")
    o["C17-05.certificats"] = (f"===== C17-05 - QUALIFICATION CERTIFICATS TLS =====\nServeur : {h}\nDate/heure : 2026-11-02 10:15:00\n\n\n"
                               "============================================================\n PORT TLS : 443\n"
                               f"============================================================\n{cert}")
    o["C17-06.journalisation"] = (f"===== C17-06 - LOGGING / AUDIT / DEFENSE =====\nServeur : {h}\nDate/heure : 2026-11-02 10:15:00\n\n"
                                  "===== SECTIONS LYNIS LOGGING / AUDIT =====\n4:[+] Logging and files\n\n"
                                  "===== FICHIERS SUPPRIMES MAIS ENCORE OUVERTS =====\nCOMMAND PID USER FD TYPE DEVICE SIZE/OFF NLINK NODE NAME\n\n"
                                  "===== SYSTEMD-JOURNald =====\nactive\nstatic\n\n===== JOURNALD - CONFIGURATION EFFECTIVE =====\n"
                                  + ("" if f else "/etc/systemd/journald.conf:15:Storage=persistent")
                                  + "\n\n===== RSYSLOG =====\nactive\nenabled\n\n===== RSYSLOG - CONFIGURATION =====\n"
                                  + ("" if f else '/etc/rsyslog.d/90-transfert.conf:1:*.* action(type="omfwd" target="journaux.example.org" port="6514" protocol="tcp" StreamDriver="gtls")')
                                  + "\n\n===== RSYSLOG - FICHIERS DE CONFIGURATION =====\n/etc/rsyslog.d/50-default.conf\n\n"
                                  "===== JOURNAL 24H - ERREURS / ALERTES =====\nNov 02 08:00:00 exemple systemd[1]: ligne d'alerte fictive")
    trouve = (lambda nom, chemin: f"--- {nom} ---" + ("" if f else f"\n{chemin}"))
    o["C17-07.integrite"] = (f"===== C17-07 - INTEGRITE / ANTIMALWARE / IDS / PERMISSIONS =====\nServeur : {h}\nDate/heure : 2026-11-02 10:15:00\n\n"
                             "===== SECTIONS LYNIS INTEGRITE / MALWARE / DEFENSE =====\n\n===== OUTILS INTEGRITE =====\n"
                             + trouve("aide", "/usr/bin/aide") + "\n--- tripwire ---\n\n===== PACKAGES INTEGRITE =====\n" + ("" if f else "aide 0.18.3-1")
                             + "\n\n===== ANTIMALWARE / ROOTKIT =====\n" + trouve("clamscan", "/usr/bin/clamscan") + "\n--- rkhunter ---\n\n"
                             "===== PACKAGES ANTIMALWARE / ROOTKIT =====\n\n===== IDS / IPS =====\n--- suricata ---\n\n===== PACKAGES IDS / IPS =====\n\n"
                             "===== PERMISSIONS GRUB =====\n  File: /boot/grub/grub.cfg\n"
                             + ("Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" if f else
                                "Access: (0400/-r--------)  Uid: (    0/    root)   Gid: (    0/    root)")
                             + "\n\n===== PERMISSIONS /ETC/CRONTAB =====\n  File: /etc/crontab\n"
                             + ("Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" if f else
                                "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)")
                             + "\n\n===== PERMISSIONS REPERTOIRES CRON =====")
    return o


BLOCS = {
    "C01": ["C01.identification"], "C02": ["C02.ressources"], "C03": ["C03.paquets", "C03.policy", "C03.noyau", "C03.sources"],
    "C04": ["C04.logiciels", "C04.services"], "C05": ["C05.reseau"], "C06": ["C06.services"], "C07": ["C07.ports"],
    "C08": ["C08.parefeu"], "C09": ["C09.ssh"], "C10": ["C10.comptes"], "C11": ["C11.permissions"], "C12": ["C12.journalisation"],
    "C13": ["C13.temps"], "C14": ["C14.taches"], "C15": ["C15.securite"],
    "C16": ["C16.identification", "C16.standard", "C16.detail", "C16.systeme"],
    "C17": ["C17.identification", "C17.audit_lynis", "C17.sections", "C17.resultats"],
    "C17-01": ["C17-01.systemd"], "C17-02": ["C17-02.authentification"], "C17-03": ["C17-03.permissions"],
    "C17-04": ["C17-04.sysctl"], "C17-05": ["C17-05.reseau", "C17-05.certificats"], "C17-06": ["C17-06.journalisation"],
    "C17-07": ["C17-07.integrite"],
}


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def generer_session(parent: Path, hote: str = "SRV-EXEMPLE-01", profil: str = "faible", horodatage: str = "20261102_101500",
                    ip: str = "192.0.2.10", fuseau: str = "Etc/UTC", controles: Optional[list] = None,
                    remplacements: Optional[dict] = None) -> Path:
    """Écrit une session fictive complète et retourne son dossier.

    remplacements : {id_bloc: (statut, code, sortie)} pour simuler des échecs.
    controles     : sous-ensemble de contrôles à produire (les autres sont « non exécutés »).
    """
    sorties = {k: ("ok", 0, v) for k, v in _sorties(profil, hote, ip, fuseau).items()}
    sorties.update(remplacements or {})
    session = f"{hote}_{horodatage}"
    dossier = Path(parent) / session
    preuves = dossier / "preuves"
    preuves.mkdir(parents=True, exist_ok=False)
    d, t = horodatage.split("_")
    iso = f"{d[:4]}-{d[4:6]}-{d[6:]}T{t[:2]}:{t[2:4]}:{t[4:]}+00:00"
    choisis = controles or list(CONTROLES_COLLECTES)
    statuts = {}
    for cid, blocs in BLOCS.items():
        if cid not in choisis:
            continue
        nom = f"{cid}_{hote}_{horodatage}"
        texte = ["#" * 64, f"# {BANDEAU}", f"# controle     : {cid}", f"# intitule     : {PAR_ID[cid].intitule}",
                 f"# session      : {session}", f"# hote         : {hote}", f"# date_collecte: {iso}",
                 "# collecteur   : lsaf-collecte 0.1.0 (synthétique)", "# privileges   : root", "#" * 64, ""]
        descr, executes, degrades = [], 0, 0
        for bid in blocs:
            statut, code, sortie = sorties.get(bid, ("ok", 0, ""))
            texte += [f"===== LSAF-BLOC DEBUT id={bid} =====", f"# titre    : {bid}"]
            if statut in ("ok", "code_non_nul"):
                if sortie:
                    texte += sortie.split("\n")
                executes += 1
            else:
                texte.append("# LSAF : bloc non exécuté - synthétique")
                degrades += 1
            texte += [f"===== LSAF-BLOC FIN id={bid} code={'null' if code is None else code} statut={statut} duree_ms=1 =====", ""]
            descr.append({"id": bid, "titre": bid, "commande": "synthétique", "programmes_absents": None,
                          "code_retour": code, "statut": statut, "duree_ms": 1})
        st = "collecte_impossible" if executes == 0 else ("partiel" if degrades else "termine")
        texte += ["#" * 64, f"# fin du contrôle {cid} - statut d'exécution : {st}", "#" * 64]
        ptxt = preuves / f"{nom}.txt"
        ptxt.write_text("\n".join(texte) + "\n", encoding="utf-8")
        execution = {"schema": "lsaf.execution/1", "controle": cid, "intitule": PAR_ID[cid].intitule, "session": session,
                     "hote": hote, "hote_detecte": True, "version_collecteur": "0.1.0", "execute_en_root": True,
                     "debut": iso, "fin": iso, "statut_execution": st, "fichier_preuve": ptxt.name,
                     "sha256_preuve": _sha(ptxt), "blocs": descr, "annexes": [], "notes": [BANDEAU]}
        (preuves / f"{nom}.json").write_text(json.dumps(execution, indent=2, ensure_ascii=False), encoding="utf-8")
        statuts[cid] = st
    manifeste = {"schema": "lsaf.session/1", "session": session, "hote": hote, "hote_detecte": True,
                 "source_libelle": "synthétique", "alias": False, "version_collecteur": "0.1.0", "debut": iso, "fin": iso,
                 "horodatage": horodatage, "execute_en_root": True,
                 "systeme": {"id": "ubuntu" if profil == "faible" else "debian", "version": "22.04" if profil == "faible" else "12",
                             "nom": "Ubuntu 22.04.4 LTS" if profil == "faible" else "Debian GNU/Linux 12 (bookworm)"},
                 "parametres": {"lynis": True, "debsecan": True, "simulation": False, "ports_tls": "443 8443 9443",
                                "comptes": "auditeur appli", "paquets_policy": "openssh-server"},
                 "controles_demandes": choisis, "controles": {c: statuts.get(c, "non_execute") for c in CONTROLES_COLLECTES},
                 "synthetique": True, "avertissement": BANDEAU}
    (dossier / "session.json").write_text(json.dumps(manifeste, indent=2, ensure_ascii=False), encoding="utf-8")
    return dossier


def generer_demo(parent: Path) -> list[Path]:
    """Trois serveurs fictifs : deux mal configurés (pistes transversales) et un durci."""
    parent = Path(parent)
    return [
        generer_session(parent, "SRV-EXEMPLE-01", "faible", "20261102_101500", "192.0.2.10", "Etc/UTC"),
        generer_session(parent, "SRV-EXEMPLE-02", "durci", "20261102_103000", "192.0.2.20", "Etc/UTC"),
        generer_session(parent, "SRV-EXEMPLE-03", "faible", "20261102_104500", "198.51.100.30", "Europe/Paris",
                        remplacements={"C17.audit_lynis": ("outil_absent", None, "")}),
    ]


INVENTAIRE_DEMO = {
    "SRV-EXEMPLE-01": {"role": "Serveur web fictif", "environnement": "Production", "criticite": "Haute",
                       "domaine": "Hors domaine", "responsable": "Équipe système (fictive)"},
    "SRV-EXEMPLE-02": {"role": "Serveur d'administration fictif", "environnement": "Production", "criticite": "Moyenne",
                       "domaine": "Hors domaine", "responsable": "Équipe système (fictive)"},
    "SRV-EXEMPLE-03": {"role": "Serveur de test fictif", "environnement": "Test", "criticite": "Faible",
                       "domaine": "Hors domaine", "responsable": "Équipe projet (fictive)"},
}

# Qualification fictive utilisée par « lsaf demo » et les tests pour produire
# un rapport complet.
_PRIORITES_DEMO = {"R01": "Haute", "R02": "Haute", "R03": "Moyenne", "R04": "Moyenne", "R05": "Haute", "R06": "Moyenne",
                   "R07": "Moyenne", "R08": "Moyenne", "R09": "Faible", "R10": "Faible", "R11": "Faible"}


def qualifier_demo(chemin_classeur: Path, chemin_sortie: Path) -> Path:
    """Copie le classeur en remplissant ANALYSE avec une qualification FICTIVE de démonstration."""
    import re
    from openpyxl import load_workbook
    wb = load_workbook(chemin_classeur)
    ws = wb["ANALYSE"]
    for r in range(6, ws.max_row + 1):
        commentaire = ws.cell(row=r, column=19).value or ""
        if not str(commentaire).startswith("À QUALIFIER"):
            continue
        m = re.search(r"règle (R\d{2})", commentaire)
        regle = m.group(1) if m else "R00"
        ws.cell(row=r, column=4, value="Référence fictive de démonstration (à remplacer par la référence retenue par l'auditeur)")
        ws.cell(row=r, column=5, value="Autre")
        ws.cell(row=r, column=7, value="Risque fictif rédigé pour la démonstration : en audit réel, l'auditeur décrit ici "
                                       "l'impact au regard du rôle et de l'exposition du serveur.")
        ws.cell(row=r, column=8, value=_PRIORITES_DEMO.get(regle, "Faible"))
        ws.cell(row=r, column=9, value="Recommandation fictive de démonstration.")
        ws.cell(row=r, column=10, value="Action fictive de démonstration.")
        ws.cell(row=r, column=13, value="Non démarrée")
        ws.cell(row=r, column=19, value=f"Qualification FICTIVE de démonstration ({regle}) — données synthétiques.")
    wb.save(chemin_sortie)
    return Path(chemin_sortie)
