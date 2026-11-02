# Contrôles et commandes

Ce document liste les commandes exécutées par le collecteur pour chaque contrôle. Chaque bloc est exécuté séparément ; sa sortie est enregistrée dans le fichier de preuve du contrôle entre les marqueurs `===== LSAF-BLOC DEBUT id=… =====` et `===== LSAF-BLOC FIN id=… code=… statut=… =====`.

Variables disponibles dans les commandes :

| Variable | Contenu |
|---|---|
| `HOST` | nom du serveur, ou libellé donné par `--alias-hote` |
| `DATE_AUDIT` | date et heure de début de la collecte |
| `REPORT` | sortie de Lynis (`preuves/C17_<SERVEUR>_<DATE>_<HEURE>.lynis.txt`), lue par C17-01 à C17-07 |
| `LSAF_COMPTES` | comptes examinés par C17-02 et C17-03 (`--comptes`, par défaut UID ≥ 1000) |
| `LSAF_PORTS_TLS` | ports testés par C17-05 (`--ports-tls`, par défaut `443 8443 9443`) |
| `LSAF_PAQUETS_POLICY` | paquets interrogés par `apt-cache policy` en C03 (`--paquets`) |

Les commandes préfixées par `sudo` nécessitent des droits d'administration : lancez le collecteur avec `sudo`.

## C01 — Identification du système

- **Domaine** : Identification système
- **Élément contrôlé** : OS / kernel / architecture / virtualisation
- **Objet** : OS, noyau, architecture, virtualisation
- **Méthode / outil** (colonnes du registre) : cat /etc/os-release / Commande native
- **Script** : `collecteur/controles/C01.sh`

**Bloc `C01.identification`** — CONTROLE C01 - IDENTIFICATION DU SYSTEME

```bash
  echo "=================================================="
  echo "CONTROLE C01 - IDENTIFICATION DU SYSTEME"
  echo "Date de collecte : $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "=================================================="
  echo
  echo "### NOM D'HOTE"
  hostnamectl --static 2>&1
  hostname 2>&1
  echo
  echo "### SYSTEME D'EXPLOITATION"
  cat /etc/os-release 2>&1
  echo
  echo "### NOYAU ACTIF"
  uname -a 2>&1
  echo
  echo "### ARCHITECTURE"
  uname -m 2>&1
  getconf LONG_BIT 2>&1
  echo
  echo "### VIRTUALISATION"
  systemd-detect-virt 2>&1
  echo "Code retour détection virtualisation : ${PIPESTATUS[0]}"
  echo
  echo "### FIN DU CONTROLE C01"
```

## C02 — État et ressources

- **Domaine** : Configuration système
- **Élément contrôlé** : CPU / RAM / Swap / stockage / charge
- **Objet** : CPU, mémoire, swap, stockage, charge, disponibilité
- **Méthode / outil** (colonnes du registre) : Autre / Commande native
- **Script** : `collecteur/controles/C02.sh`

**Bloc `C02.ressources`** — ETAT ET RESSOURCES

```bash
echo "===== UPTIME / LOAD ====="
uptime
echo
echo "===== CPU ====="
lscpu | grep -E '^(CPU|Model name|Architecture|Thread|Core|Socket)'
echo
echo "===== MEMORY / SWAP ====="
free -h
echo
echo "===== DISK ====="
df -hT
echo
echo "===== INODES ====="
df -ih
```

## C03 — État des mises à jour

- **Domaine** : Versions / mises à jour
- **Élément contrôlé** : Paquets système, noyau, état de redémarrage et sources APT
- **Objet** : Paquets à jour, noyau actif et installé, redémarrage requis, sources APT
- **Méthode / outil** (colonnes du registre) : Autre / Commande native
- **Script** : `collecteur/controles/C03.sh`

**Bloc `C03.paquets`** — PAQUETS POUVANT ETRE MIS A JOUR

```bash
apt list --upgradable 2>/dev/null
```

**Bloc `C03.policy`** — VERSIONS CANDIDATES (apt-cache policy)

```bash
echo "===== PAQUETS INTERROGES ====="
apt-cache policy $LSAF_PAQUETS_POLICY
```

**Bloc `C03.noyau`** — NOYAU ET REDEMARRAGE

```bash
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
```

**Bloc `C03.sources`** — SOURCES APT

```bash
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
```

## C04 — Logiciels installés

- **Domaine** : Applications / logiciels
- **Élément contrôlé** : Principaux logiciels et composants installés
- **Objet** : Principaux logiciels et composants installés, services associés
- **Méthode / outil** (colonnes du registre) : Autre / Commande native
- **Script** : `collecteur/controles/C04.sh`

**Bloc `C04.logiciels`** — PRINCIPAUX LOGICIELS

```bash
echo "===== PRINCIPAUX LOGICIELS ====="
dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | \
grep -Ei 'postgres|apache|nginx|docker|containerd|php|python|nodejs|java|openssh|samba|rsync' || true
```

**Bloc `C04.services`** — SERVICES ASSOCIES AUX LOGICIELS DETECTES

```bash
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
```

## C05 — Réseau

- **Domaine** : Ports / réseau
- **Élément contrôlé** : Interfaces, adressage IP, routage, DNS et interfaces de conteneurisation
- **Objet** : Interfaces, adressage, routage, DNS, réseaux de conteneurs
- **Méthode / outil** (colonnes du registre) : Autre / Commande native
- **Script** : `collecteur/controles/C05.sh`

**Bloc `C05.reseau`** — INTERFACES, ROUTAGE, DNS, CONFIGURATION RESEAU

```bash
echo "===== HOST / INTERFACES ====="
hostname
ip -br addr
echo
echo "===== ROUTING ====="
ip route
echo
echo "===== DNS ====="
resolvectl status 2>/dev/null || cat /etc/resolv.conf
echo
echo "===== NETWORK CONFIGURATION ====="
ls -la /etc/netplan/ 2>/dev/null
grep -RhsvE '^[[:space:]]*#|^[[:space:]]*$' /etc/netplan/ 2>/dev/null || true
```

## C06 — Services

- **Domaine** : Services
- **Élément contrôlé** : Services système actifs
- **Objet** : Services actifs et services clés
- **Méthode / outil** (colonnes du registre) : systemctl / Commande native
- **Script** : `collecteur/controles/C06.sh`

**Bloc `C06.services`** — SERVICES ACTIFS ET SERVICES CLES

```bash
echo "===== SERVICES ACTIFS ====="
systemctl list-units --type=service --state=running --no-legend --no-pager | awk '{print $1}'
echo
echo "===== ETAT DES SERVICES CLES ====="
for svc in nginx postgresql ssh docker containerd rsync smbd nmbd apache2; do
    printf "%-15s : " "$svc"
    systemctl is-active "$svc" 2>/dev/null || true
done
```

## C07 — Ports en écoute

- **Domaine** : Ports / réseau
- **Élément contrôlé** : Ports TCP/UDP et adresses d'écoute
- **Objet** : Ports TCP/UDP et adresses d'écoute (IPv4/IPv6)
- **Méthode / outil** (colonnes du registre) : ss -tulpen / Commande native
- **Script** : `collecteur/controles/C07.sh`

**Bloc `C07.ports`** — PORTS TCP/UDP EN ECOUTE

```bash
echo "===== PORTS TCP/UDP EN ECOUTE ====="
ss -lntup
echo
echo "===== PORTS TCP EN ECOUTE ====="
ss -lntp
echo
echo "===== PORTS UDP EN ECOUTE ====="
ss -lnup
```

## C08 — Pare-feu / filtrage réseau

- **Domaine** : Pare-feu
- **Élément contrôlé** : Pare-feu local / filtrage
- **Objet** : UFW, nftables, iptables, firewalld
- **Méthode / outil** (colonnes du registre) : Autre / Commande native
- **Script** : `collecteur/controles/C08.sh`

**Bloc `C08.parefeu`** — ETAT DU FIREWALL

```bash
echo "===== ETAT DU FIREWALL ====="
sudo ufw status verbose 2>/dev/null || true
echo
echo "===== NFTABLES ====="
sudo nft list ruleset 2>/dev/null || true
echo
echo "===== IPTABLES ====="
sudo iptables -L -n -v 2>/dev/null || true
echo
echo "===== FIREWALLD ====="
sudo firewall-cmd --state 2>/dev/null || true
```

## C09 — SSH

- **Domaine** : SSH / accès distant
- **Élément contrôlé** : Service et configuration effective
- **Objet** : Version et configuration effective (sshd -T)
- **Méthode / outil** (colonnes du registre) : sshd -T / Commande native
- **Script** : `collecteur/controles/C09.sh`

**Bloc `C09.ssh`** — SSH - SERVICE, VERSION, CONFIGURATION EFFECTIVE

```bash
echo "===== SSH - ETAT DU SERVICE ====="
systemctl is-active ssh
echo
echo "===== SSH - VERSION ====="
ssh -V 2>&1
echo
echo "===== SSH - CONFIGURATION EFFECTIVE ====="
sudo sshd -T 2>/dev/null | grep -Ei \
'^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|x11forwarding|allowtcpforwarding|allowagentforwarding|permitemptypasswords|logingracetime|maxauthtries|maxsessions|clientaliveinterval|clientalivecountmax|usedns)\b'
```

## C10 — Utilisateurs, comptes et privilèges

- **Domaine** : Comptes utilisateurs
- **Élément contrôlé** : Comptes, shells et groupes privilégiés
- **Objet** : Comptes, shells, groupes privilégiés (sudo, adm)
- **Méthode / outil** (colonnes du registre) : Autre / Commande native
- **Script** : `collecteur/controles/C10.sh`

**Bloc `C10.comptes`** — COMPTES, GROUPES PRIVILEGIES, VERROUILLAGE

```bash
echo "===== COMPTES UTILISATEURS ====="
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd
echo
echo "===== COMPTE ROOT ====="
sudo passwd -S root
echo
echo "===== GROUPES PRIVILEGIES ====="
getent group sudo
getent group adm
echo
echo "===== COMPTES AVEC SHELL INTERACTIF ====="
awk -F: '$7 !~ /(nologin|false)/ {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd
echo
echo "===== COMPTES VERROUILLES / NON VERROUILLES ====="
sudo awk -F: '($2 ~ /^!/ || $2 ~ /^\*/) {print $1 ":LOCKED"}' /etc/shadow 2>/dev/null
```

## C11 — Permissions

- **Domaine** : Privilèges
- **Élément contrôlé** : Fichiers et répertoires sensibles
- **Objet** : Permissions des fichiers et répertoires sensibles, SUID/SGID, fichiers inscriptibles
- **Méthode / outil** (colonnes du registre) : Autre / Commande native
- **Script** : `collecteur/controles/C11.sh`

**Bloc `C11.permissions`** — FICHIERS ET REPERTOIRES SENSIBLES, SUID/SGID, WORLD-WRITABLE

```bash
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
```

## C12 — Logs et journalisation

- **Domaine** : Journalisation
- **Élément contrôlé** : Journalisation système et rotation
- **Objet** : journald, rsyslog, fichiers de journaux, rotation, erreurs
- **Méthode / outil** (colonnes du registre) : journalctl / Commande native
- **Script** : `collecteur/controles/C12.sh`

**Bloc `C12.journalisation`** — SERVICES DE JOURNALISATION, FICHIERS, ROTATION, ERREURS

```bash
echo "===== SERVICES DE JOURNALISATION ====="
systemctl is-active rsyslog 2>/dev/null || true
systemctl is-active systemd-journald 2>/dev/null || true
echo
echo "===== JOURNAL SYSTEMD ====="
journalctl --disk-usage 2>/dev/null || true
echo
echo "===== FICHIERS DE LOG ====="
ls -lh /var/log/syslog /var/log/auth.log /var/log/kern.log 2>/dev/null || true
echo
echo "===== ROTATION DES LOGS ====="
ls -la /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null | head -30
echo
echo "===== ERREURS RECENTES ====="
journalctl -p err -b --no-pager -n 30 2>/dev/null || true
```

## C13 — Temps et synchronisation

- **Domaine** : Synchronisation horaire
- **Élément contrôlé** : Synchronisation horaire
- **Objet** : Service NTP, source, fuseau horaire
- **Méthode / outil** (colonnes du registre) : Autre / Commande native
- **Script** : `collecteur/controles/C13.sh`

**Bloc `C13.temps`** — DATE, HEURE, SYNCHRONISATION NTP

```bash
echo "===== DATE / HEURE SYSTEME ====="
date
timedatectl
echo
echo "===== SYNCHRONISATION NTP ====="
timedatectl show-timesync --all 2>/dev/null || true
echo
echo "===== SERVICES DE SYNCHRONISATION ====="
systemctl is-active systemd-timesyncd 2>/dev/null || true
systemctl is-active chrony 2>/dev/null || true
systemctl is-active ntp 2>/dev/null || true
```

## C14 — Tâches planifiées

- **Domaine** : Processus
- **Élément contrôlé** : Tâches planifiées
- **Objet** : cron et timers systemd
- **Méthode / outil** (colonnes du registre) : systemctl / Commande native
- **Script** : `collecteur/controles/C14.sh`

**Bloc `C14.taches`** — CRON ET TIMERS SYSTEMD

```bash
echo "===== CRON - TACHES PLANIFIEES ====="
sudo crontab -l 2>/dev/null || true
echo
echo "===== CRON SYSTEME ====="
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null
echo
echo "===== SYSTEMD TIMERS ====="
systemctl list-timers --all --no-pager
```

## C15 — Mécanismes de sécurité et de confinement

- **Domaine** : Antivirus / EDR
- **Élément contrôlé** : Mécanismes / agents de sécurité
- **Objet** : Services, processus et paquets de sécurité
- **Méthode / outil** (colonnes du registre) : systemctl / Commande native
- **Script** : `collecteur/controles/C15.sh`

**Bloc `C15.securite`** — AGENTS / MECANISMES DE SECURITE

```bash
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
```

## C16 — Debsecan

- **Domaine** : Vulnérabilités
- **Élément contrôlé** : Analyse des vulnérabilités avec Debsecan
- **Objet** : Debsecan : CVE, paquets, versions installées
- **Méthode / outil** (colonnes du registre) : Debsecan / Debsecan
- **Script** : `collecteur/controles/C16.sh`

**Bloc `C16.identification`** — DEBSECAN - IDENTIFICATION

```bash
echo "===== DEBSECAN - IDENTIFICATION ====="
echo "Serveur : $(hostname)"
echo "Date/heure : $(date)"
echo
echo "===== INSTALLATION ====="
dpkg -l | grep debsecan || true
echo
echo "===== VERSION ====="
debsecan --version 2>&1 || true
```

**Bloc `C16.standard`** — DEBSECAN - RAPPORT STANDARD (requiert `debsecan`)

```bash
sudo debsecan
```

**Bloc `C16.detail`** — DEBSECAN - RAPPORT DETAILLE (requiert `debsecan`)

```bash
sudo debsecan --format detail
```

**Bloc `C16.systeme`** — SYSTEME (os-release)

```bash
cat /etc/os-release
```

## C17 — Durcissement - résultat global Lynis

- **Domaine** : Vulnérabilités
- **Élément contrôlé** : Version, nombre de tests, Hardening Index, fonctions de sécurité détectées
- **Objet** : Version, nombre de tests, indice de durcissement, avertissements et suggestions
- **Méthode / outil** (colonnes du registre) : Lynis / Lynis
- **Script** : `collecteur/controles/C17.sh`

**Bloc `C17.identification`** — C17 - AUDIT LYNIS GLOBAL

```bash
echo "===== C17 - AUDIT LYNIS GLOBAL ====="
echo "Serveur : $HOST"
echo "Date/heure : $DATE_AUDIT"
echo
echo "===== VERSION LYNIS ====="
command -v lynis
lynis show version
echo
echo "===== VERIFICATION DES PRIVILEGES SUDO ====="
sudo -v
echo "Code retour sudo : $?"
echo
echo "===== IDENTITE COURANTE ====="
id
echo
echo "===== HOSTNAME ====="
hostnamectl 2>&1
echo
echo "===== SYSTEME ====="
cat /etc/os-release
uname -a
```

**Bloc `C17.audit_lynis`** — LANCEMENT AUDIT LYNIS (requiert `lynis`)

```bash
sudo lynis audit system --no-colors 2>&1 | tee "$REPORT"
```

**Bloc `C17.sections`** — SECTIONS LYNIS

```bash
grep -nE '^\[[+!-]\]' "$REPORT" 2>/dev/null
```

**Bloc `C17.resultats`** — RESULTATS GLOBAUX LYNIS

```bash
grep -niE 'hardening index|suggestions|warnings|tests performed' "$REPORT" 2>/dev/null
```

## C17-01 — systemd / isolation des services

- **Domaine** : Services
- **Élément contrôlé** : Niveau d'exposition et protections systemd des services critiques
- **Objet** : Niveau d'exposition systemd-analyze security
- **Méthode / outil** (colonnes du registre) : Lynis / Lynis
- **Script** : `collecteur/controles/C17-01.sh`

**Bloc `C17-01.systemd`** — C17-01 - SYSTEMD / SERVICES / ISOLATION

```bash
echo "===== C17-01 - SYSTEMD / SERVICES / ISOLATION ====="
echo "Serveur : $HOST"
echo "Date/heure : $DATE_AUDIT"
echo
echo "===== SECTIONS LYNIS RELATIVES AUX SERVICES ====="
grep -niE 'boot and services|services|systemd' "$REPORT" 2>/dev/null
echo
echo "===== SYSTEMD-ANALYZE SECURITY ====="
systemd-analyze security --no-pager 2>&1
echo
echo "===== SERVICES ACTIFS ====="
systemctl list-units --type=service --state=running --no-pager 2>&1
echo
echo "===== SERVICES ENABLED ====="
systemctl list-unit-files --type=service --state=enabled --no-pager 2>&1
```

## C17-02 — Authentification / mots de passe

- **Domaine** : Authentification
- **Élément contrôlé** : login.defs, vieillissement, PAM, échecs d'authentification
- **Objet** : login.defs, vieillissement des comptes, modules PAM, verrouillage, échecs d'authentification
- **Méthode / outil** (colonnes du registre) : Lynis / Lynis
- **Script** : `collecteur/controles/C17-02.sh`

**Bloc `C17-02.authentification`** — C17-02 - AUTHENTIFICATION / MOTS DE PASSE

```bash
echo "===== C17-02 - AUTHENTIFICATION / MOTS DE PASSE ====="
echo "Serveur : $HOST"
echo "Date/heure : $DATE_AUDIT"
echo
echo "===== POLITIQUE /ETC/LOGIN.DEFS ====="
grep -nE '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK)' \
    /etc/login.defs 2>/dev/null
echo
for u in $LSAF_COMPTES; do
    echo "===== COMPTE : $u ====="
    chage -l "$u" 2>&1
    echo
done
echo "===== PAM - PASSWORD STRENGTH ====="
grep -RniE 'pam_(pwquality|cracklib|unix|passwdqc)' \
    /etc/pam.d 2>/dev/null
echo
echo "===== PAM - LOCKOUT / FAILED AUTHENTICATION ====="
grep -RniE 'faillock|pam_tally|tally2' /etc/pam.d 2>/dev/null
echo
echo "===== COMMAND FAILLOCK ====="
command -v faillock 2>&1
echo
echo "===== AUTHENTIFICATIONS ECHOUEES - 24H ====="
journalctl --since "24 hours ago" --no-pager 2>/dev/null \
    | grep -Ei 'failed|failure|invalid|authentication' \
    | tail -200
```

## C17-03 — Permissions / répertoires personnels

- **Domaine** : Privilèges
- **Élément contrôlé** : Sudoers, répertoires utilisateurs, fichiers sensibles
- **Objet** : sudoers, répertoires home, fichiers système inscriptibles
- **Méthode / outil** (colonnes du registre) : Lynis / Lynis
- **Script** : `collecteur/controles/C17-03.sh`

**Bloc `C17-03.permissions`** — C17-03 - PERMISSIONS / HOME / FICHIERS SYSTEME

```bash
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
```

## C17-04 — Kernel hardening / sysctl

- **Domaine** : Autres
- **Élément contrôlé** : Paramètres réseau et sécurité du kernel, core dumps
- **Objet** : Paramètres réseau et de sécurité du noyau, core dumps
- **Méthode / outil** (colonnes du registre) : Lynis / Lynis
- **Script** : `collecteur/controles/C17-04.sh`

**Bloc `C17-04.sysctl`** — C17-04 - KERNEL HARDENING / SYSCTL

```bash
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
```

## C17-05 — Réseau / firewall / exposition / TLS

- **Domaine** : Pare-feu
- **Élément contrôlé** : Firewall, IPv6, TLS, services exposés
- **Objet** : Filtrage effectif, IPv6, services exposés, protocoles et certificats TLS
- **Méthode / outil** (colonnes du registre) : Lynis / Lynis
- **Script** : `collecteur/controles/C17-05.sh`

**Bloc `C17-05.reseau`** — C17-05 - RESEAU / FIREWALL / EXPOSITION / TLS

```bash
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
```

**Bloc `C17-05.certificats`** — C17-05 - QUALIFICATION CERTIFICATS TLS

```bash
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
```

## C17-06 — Journalisation / audit / défense

- **Domaine** : Journalisation
- **Élément contrôlé** : Journald, RSyslog, auditd, logs distants, fichiers supprimés ouverts
- **Objet** : journald, rsyslog, auditd, centralisation, fichiers supprimés ouverts
- **Méthode / outil** (colonnes du registre) : Lynis / Lynis
- **Script** : `collecteur/controles/C17-06.sh`

**Bloc `C17-06.journalisation`** — C17-06 - LOGGING / AUDIT / DEFENSE

```bash
echo "===== C17-06 - LOGGING / AUDIT / DEFENSE ====="
echo "Serveur : $HOST"
echo "Date/heure : $DATE_AUDIT"
echo
echo "===== SECTIONS LYNIS LOGGING / AUDIT ====="
grep -niE 'logging and files|accounting|audit' "$REPORT" 2>/dev/null
echo
echo "===== FICHIERS SUPPRIMES MAIS ENCORE OUVERTS ====="
if command -v lsof >/dev/null 2>&1; then
    lsof +L1 2>&1
else
    echo "lsof : commande absente"
fi
echo
echo "===== SYSTEMD-JOURNald ====="
systemctl is-active systemd-journald 2>&1
systemctl is-enabled systemd-journald 2>&1
echo
echo "===== JOURNALD - CONFIGURATION EFFECTIVE ====="
grep -RniE '^[[:space:]]*(ForwardToSyslog|ForwardToKMsg|ForwardToConsole|ForwardToWall|Storage|SystemMaxUse|RuntimeMaxUse)' \
    /etc/systemd/journald.conf /etc/systemd/journald.conf.d 2>/dev/null
echo
echo "===== RSYSLOG ====="
systemctl is-active rsyslog 2>&1
systemctl is-enabled rsyslog 2>&1
echo
echo "===== RSYSLOG - CONFIGURATION ====="
grep -RniE '^[[:space:]]*[^#].*(omfwd|@@|@[^@[:space:]])' \
    /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null
echo
echo "===== RSYSLOG - FICHIERS DE CONFIGURATION ====="
find /etc/rsyslog.d -maxdepth 1 -type f -print 2>&1
echo
echo "===== JOURNAL 24H - ERREURS / ALERTES ====="
journalctl --since "24 hours ago" --no-pager 2>/dev/null \
    | grep -Ei 'error|failed|warning|critical|alert' \
    | tail -200
```

## C17-07 — Intégrité / protections complémentaires

- **Domaine** : Autres
- **Élément contrôlé** : AppArmor, intégrité fichiers, antimalware, mécanismes de défense
- **Objet** : Outils d'intégrité, antimalware, IDS, permissions signalées
- **Méthode / outil** (colonnes du registre) : Lynis / Lynis
- **Script** : `collecteur/controles/C17-07.sh`

**Bloc `C17-07.integrite`** — C17-07 - INTEGRITE / ANTIMALWARE / IDS / PERMISSIONS

```bash
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
```

## C18 — Analyse croisée et qualification SSI

- **Domaine** : Autres
- **Élément contrôlé** : Analyse croisée
- **Objet** : Croisement des contrôles et des serveurs, qualification, criticité, recommandations
- **Méthode / outil** (colonnes du registre) : Autre / Autre

Aucune commande : l'analyse croisée est réalisée sur le poste de l'auditeur (`lsaf classeur`). Voir [regles-c18.md](regles-c18.md).

