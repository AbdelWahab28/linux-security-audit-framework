"""Catalogue des contrôles C01 à C18.

Intitulés, domaines, éléments contrôlés, méthodes et outils utilisés dans le
classeur (CONTROLES_ET_PREUVES, listes du DASHBOARD) et dans le rapport.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Controle:
    id: str
    intitule: str               # intitulé de la méthodologie
    domaine: str                # « Domaine de contrôle » (liste du classeur)
    element: str                # « Élément contrôlé » (classeur)
    objet: str                  # « Éléments examinés » (rapport, section 3.2 / 3.3)
    methode: str                # « Méthode de contrôle » (liste du classeur)
    outil: str                  # « Outil utilisé » (liste du classeur)
    blocs_cles: tuple = ()      # blocs dont la sortie est indispensable


CONTROLES = [
    Controle("C01", "Identification du système", "Identification système",
             "OS / kernel / architecture / virtualisation", "OS, noyau, architecture, virtualisation",
             "cat /etc/os-release", "Commande native", ("C01.identification",)),
    Controle("C02", "État et ressources", "Configuration système",
             "CPU / RAM / Swap / stockage / charge", "CPU, mémoire, swap, stockage, charge, disponibilité",
             "Autre", "Commande native", ("C02.ressources",)),
    Controle("C03", "État des mises à jour", "Versions / mises à jour",
             "Paquets système, noyau, état de redémarrage et sources APT",
             "Paquets à jour, noyau actif et installé, redémarrage requis, sources APT",
             "Autre", "Commande native", ("C03.paquets", "C03.noyau")),
    Controle("C04", "Logiciels installés", "Applications / logiciels",
             "Principaux logiciels et composants installés", "Principaux logiciels et composants installés, services associés",
             "Autre", "Commande native", ("C04.logiciels",)),
    Controle("C05", "Réseau", "Ports / réseau",
             "Interfaces, adressage IP, routage, DNS et interfaces de conteneurisation",
             "Interfaces, adressage, routage, DNS, réseaux de conteneurs",
             "Autre", "Commande native", ("C05.reseau",)),
    Controle("C06", "Services", "Services", "Services système actifs", "Services actifs et services clés",
             "systemctl", "Commande native", ("C06.services",)),
    Controle("C07", "Ports en écoute", "Ports / réseau", "Ports TCP/UDP et adresses d'écoute",
             "Ports TCP/UDP et adresses d'écoute (IPv4/IPv6)", "ss -tulpen", "Commande native", ("C07.ports",)),
    Controle("C08", "Pare-feu / filtrage réseau", "Pare-feu", "Pare-feu local / filtrage",
             "UFW, nftables, iptables, firewalld", "Autre", "Commande native", ("C08.parefeu",)),
    Controle("C09", "SSH", "SSH / accès distant", "Service et configuration effective",
             "Version et configuration effective (sshd -T)", "sshd -T", "Commande native", ("C09.ssh",)),
    Controle("C10", "Utilisateurs, comptes et privilèges", "Comptes utilisateurs", "Comptes, shells et groupes privilégiés",
             "Comptes, shells, groupes privilégiés (sudo, adm)", "Autre", "Commande native", ("C10.comptes",)),
    Controle("C11", "Permissions", "Privilèges", "Fichiers et répertoires sensibles",
             "Permissions des fichiers et répertoires sensibles, SUID/SGID, fichiers inscriptibles",
             "Autre", "Commande native", ("C11.permissions",)),
    Controle("C12", "Logs et journalisation", "Journalisation", "Journalisation système et rotation",
             "journald, rsyslog, fichiers de journaux, rotation, erreurs", "journalctl", "Commande native",
             ("C12.journalisation",)),
    Controle("C13", "Temps et synchronisation", "Synchronisation horaire", "Synchronisation horaire",
             "Service NTP, source, fuseau horaire", "Autre", "Commande native", ("C13.temps",)),
    Controle("C14", "Tâches planifiées", "Processus", "Tâches planifiées", "cron et timers systemd",
             "systemctl", "Commande native", ("C14.taches",)),
    Controle("C15", "Mécanismes de sécurité et de confinement", "Antivirus / EDR", "Mécanismes / agents de sécurité",
             "Services, processus et paquets de sécurité", "systemctl", "Commande native", ("C15.securite",)),
    Controle("C16", "Debsecan", "Vulnérabilités", "Analyse des vulnérabilités avec Debsecan",
             "Debsecan : CVE, paquets, versions installées", "Debsecan", "Debsecan", ("C16.standard", "C16.detail")),
    Controle("C17", "Durcissement - résultat global Lynis", "Vulnérabilités",
             "Version, nombre de tests, Hardening Index, fonctions de sécurité détectées",
             "Version, nombre de tests, indice de durcissement, avertissements et suggestions", "Lynis", "Lynis",
             ("C17.audit_lynis",)),
    Controle("C17-01", "systemd / isolation des services", "Services",
             "Niveau d'exposition et protections systemd des services critiques",
             "Niveau d'exposition systemd-analyze security", "Lynis", "Lynis", ("C17-01.systemd",)),
    Controle("C17-02", "Authentification / mots de passe", "Authentification",
             "login.defs, vieillissement, PAM, échecs d'authentification",
             "login.defs, vieillissement des comptes, modules PAM, verrouillage, échecs d'authentification",
             "Lynis", "Lynis", ("C17-02.authentification",)),
    Controle("C17-03", "Permissions / répertoires personnels", "Privilèges",
             "Sudoers, répertoires utilisateurs, fichiers sensibles",
             "sudoers, répertoires home, fichiers système inscriptibles", "Lynis", "Lynis", ("C17-03.permissions",)),
    Controle("C17-04", "Kernel hardening / sysctl", "Autres", "Paramètres réseau et sécurité du kernel, core dumps",
             "Paramètres réseau et de sécurité du noyau, core dumps", "Lynis", "Lynis", ("C17-04.sysctl",)),
    Controle("C17-05", "Réseau / firewall / exposition / TLS", "Pare-feu", "Firewall, IPv6, TLS, services exposés",
             "Filtrage effectif, IPv6, services exposés, protocoles et certificats TLS", "Lynis", "Lynis",
             ("C17-05.reseau",)),
    Controle("C17-06", "Journalisation / audit / défense", "Journalisation",
             "Journald, RSyslog, auditd, logs distants, fichiers supprimés ouverts",
             "journald, rsyslog, auditd, centralisation, fichiers supprimés ouverts", "Lynis", "Lynis",
             ("C17-06.journalisation",)),
    Controle("C17-07", "Intégrité / protections complémentaires", "Autres",
             "AppArmor, intégrité fichiers, antimalware, mécanismes de défense",
             "Outils d'intégrité, antimalware, IDS, permissions signalées", "Lynis", "Lynis",
             ("C17-07.integrite",)),
    Controle("C18", "Analyse croisée et qualification SSI", "Autres", "Analyse croisée",
             "Croisement des contrôles et des serveurs, qualification, criticité, recommandations",
             "Autre", "Autre"),
]

PAR_ID = {c.id: c for c in CONTROLES}
CONTROLES_COLLECTES = [c.id for c in CONTROLES if c.id != "C18"]

# Listes de référence (feuille DASHBOARD, colonnes AA à AD)
DOMAINES = ["Identification système", "Versions / mises à jour", "Comptes utilisateurs", "Authentification",
            "Privilèges", "Services", "Processus", "Ports / réseau", "Pare-feu", "SSH / accès distant",
            "Journalisation", "Synchronisation horaire", "Antivirus / EDR", "Applications / logiciels",
            "Vulnérabilités", "Chiffrement", "Sauvegarde", "Contrôle d'accès", "Configuration système", "Autres"]
METHODES = ["cat /etc/os-release", "uname -a", "sshd -T", "systemctl", "ss -tulpen", "journalctl", "Lynis",
            "Debsecan", "PowerShell", "HardeningKitty", "Microsoft Security Baseline", "Autre"]
OUTILS = ["Commande native", "Lynis", "Debsecan", "OpenSCAP", "PowerShell", "HardeningKitty",
          "Microsoft Security Compliance Toolkit", "Nmap", "Autre"]
TYPES_REFERENCE = ["CIS Benchmark", "Microsoft Security Baseline", "Politique interne", "Recommandation éditeur",
                   "CVE", "Documentation officielle", "Autre", "ISO/IEC 27002:2022", "CIS Controls v8"]
CRITICITES = ["Critique", "Haute", "Moyenne", "Faible"]
STATUTS_REMEDIATION = ["Non démarrée", "En cours", "Terminée", "Acceptée", "Non applicable"]
ETATS = ["Conforme", "Partiellement conforme", "Non conforme", "Non vérifié"]


def cle_tri(controle_id: str) -> tuple:
    base, _, sous = controle_id.partition("-")
    return int(base[1:]), int(sous) if sous else 0
