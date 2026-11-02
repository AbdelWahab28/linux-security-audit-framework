#!/usr/bin/env bash
# C01 - Identification du système (OS / Kernel)

controle_C01() {
    debut_controle C01 "Identification du système (OS / Kernel)" || return 1
    bloc --id C01.identification --titre "CONTROLE C01 - IDENTIFICATION DU SYSTEME" -- "$(cat <<'DOC'
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
DOC
)"
    fin_controle
}
