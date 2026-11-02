"""Extraction C10 à C16."""

from __future__ import annotations

import re

from . import Extraction
from .outils import cle_valeur, lignes, section


def _passwd(texte: str) -> list[dict]:
    r = []
    for l in lignes(texte):
        p = l.strip().split(":")
        if len(p) == 4 and p[1].isdigit():
            r.append({"compte": p[0], "uid": int(p[1]), "home": p[2], "shell": p[3]})
    return r


def extraire_c10(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C10.comptes")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    v["comptes_uid_1000"] = _passwd(section(s, "COMPTES UTILISATEURS"))
    root = lignes(section(s, "COMPTE ROOT"))
    p = root[0].split() if root else []
    v["root_statut"] = p[1] if len(p) >= 2 and p[0] == "root" else None
    groupes = {}
    for l in lignes(section(s, "GROUPES PRIVILEGIES")):
        q = l.strip().split(":")
        if len(q) == 4:
            groupes[q[0]] = [m for m in q[3].split(",") if m]
    v["groupes_privilegies"] = groupes
    v["comptes_shell_interactif"] = _passwd(section(s, "SHELL INTERACTIF"))
    v["comptes_verrouilles"] = [l.split(":")[0] for l in lignes(section(s, "VERROUILLES")) if l.endswith(":LOCKED")]
    if v["root_statut"] is None:
        ex.a_verifier.append("Statut du compte root non obtenu (sudo passwd -S root).")
    if not v["comptes_verrouilles"]:
        ex.a_verifier.append("Aucune ligne lue dans /etc/shadow : vérifier les droits sudo.")
    ex.resume = (f"{len(v['comptes_uid_1000'])} compte(s) UID >= 1000 ; root : {v['root_statut'] or '?'} ; "
                 + " ; ".join(f"groupe {g} : {', '.join(m) or 'aucun membre'}" for g, m in groupes.items())
                 + f" ; {len(v['comptes_shell_interactif'])} compte(s) avec shell interactif ; "
                 f"{len(v['comptes_verrouilles'])} compte(s) verrouillé(s)")
    return ex


def _ls_l(texte: str) -> list[dict]:
    r = []
    for l in lignes(texte):
        p = l.split()
        if len(p) >= 9 and re.match(r"^[-dlcbps][rwxsStT-]{9}", p[0]):
            r.append({"droits": p[0], "proprietaire": p[2], "groupe": p[3], "chemin": p[-1]})
    return r


def _find_printf(texte: str) -> list[dict]:
    r = []
    for l in lignes(texte):
        p = l.split(None, 3)
        if len(p) == 4 and re.match(r"^[-dlcbps][rwxsStT-]{9}$", p[0]):
            r.append({"droits": p[0], "proprietaire": p[1], "groupe": p[2], "chemin": p[3]})
    return r


def extraire_c11(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C11.permissions")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    v["fichiers_sensibles"] = _ls_l(section(s, "FICHIERS SENSIBLES"))
    v["repertoires_sensibles"] = _ls_l(section(s, "REPERTOIRES SENSIBLES"))
    v["suid_sgid"] = _find_printf(section(s, "SUID / SGID"))
    v["fichiers_world_writable"] = _find_printf(section(s, "WORLD-WRITABLE"))
    if not v["fichiers_sensibles"]:
        ex.complet = False
    ex.resume = (" ; ".join(f"{f['chemin']} {f['droits']} {f['proprietaire']}:{f['groupe']}" for f in v["fichiers_sensibles"])
                 + " ; " + " ; ".join(f"{f['chemin']} {f['droits']}" for f in v["repertoires_sensibles"])
                 + f" ; {len(v['suid_sgid'])} fichier(s) SUID/SGID ; {len(v['fichiers_world_writable'])} fichier(s) "
                   "modifiable(s) par tous dans /etc, /opt, /var")
    return ex


def extraire_c12(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C12.journalisation")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    etats = lignes(section(s, "SERVICES DE JOURNALISATION"))
    v["rsyslog"] = etats[0].strip() if len(etats) >= 1 else None
    v["journald"] = etats[1].strip() if len(etats) >= 2 else None
    usage = lignes(section(s, "JOURNAL SYSTEMD"))
    m = re.search(r"take up (\S+)", " ".join(usage))
    v["taille_journal"] = m.group(1) if m else None
    v["fichiers_journaux"] = [l.split()[-1] for l in lignes(section(s, "FICHIERS DE LOG")) if l.split()[-1].startswith("/var/log")]
    v["logrotate_present"] = "logrotate.conf" in section(s, "ROTATION")
    erreurs = [l for l in lignes(section(s, "ERREURS RECENTES")) if not l.startswith("--")]
    v["nb_erreurs_recentes"] = len(erreurs)
    ex.resume = (f"rsyslog : {v['rsyslog'] or '?'} ; journald : {v['journald'] or '?'} ; journal : {v['taille_journal'] or '?'} ; "
                 f"fichiers : {', '.join(v['fichiers_journaux']) or 'aucun'} ; logrotate : {'présent' if v['logrotate_present'] else 'non trouvé'} ; "
                 f"{v['nb_erreurs_recentes']} ligne(s) d'erreur depuis le démarrage (30 au plus)")
    return ex


def extraire_c13(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C13.temps")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    txt = section(s, "DATE / HEURE")
    for cle, motif in (("fuseau", r"Time zone:\s*(\S+)"), ("horloge_synchronisee", r"System clock synchronized:\s*(\w+)"),
                       ("service_ntp", r"NTP service:\s*(\w+)")):
        m = re.search(motif, txt)
        v[cle] = m.group(1) if m else None
    ts = cle_valeur(section(s, "SYNCHRONISATION NTP"))
    v["serveur_ntp"] = ts.get("ServerName")
    v["serveurs_ntp_configures"] = (ts.get("SystemNTPServers") or ts.get("LinkNTPServers") or "").split()
    services = lignes(section(s, "SERVICES DE SYNCHRONISATION"))
    noms = ["systemd-timesyncd", "chrony", "ntp"]
    v["services"] = {n: (services[i].strip() if i < len(services) else None) for i, n in enumerate(noms)}
    if v["horloge_synchronisee"] is None:
        ex.a_verifier.append("État de synchronisation non lu dans la sortie de timedatectl.")
    ex.resume = (f"fuseau {v['fuseau'] or '?'} ; horloge synchronisée : {v['horloge_synchronisee'] or '?'} ; "
                 f"service NTP : {v['service_ntp'] or '?'} ; serveur : {v['serveur_ntp'] or '?'} ; "
                 + ", ".join(f"{n} {e or '?'}" for n, e in v["services"].items()))
    return ex


def extraire_c14(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C14.taches")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    v["crontab_root"] = [l for l in lignes(section(s, "CRON - TACHES")) if not l.strip().startswith("#")]
    v["cron_systeme"] = [l.split()[-1] for l in lignes(section(s, "CRON SYSTEME"))
                         if re.match(r"^[-d]", l) and l.split()[-1] not in (".", "..")]
    m = re.search(r"(\d+) timers? listed", section(s, "SYSTEMD TIMERS"))
    v["nb_timers"] = int(m.group(1)) if m else None
    ex.resume = (f"{len(v['crontab_root'])} entrée(s) dans la crontab root ; {len(v['cron_systeme'])} élément(s) "
                 f"dans les répertoires cron ; {v['nb_timers'] if v['nb_timers'] is not None else '?'} timer(s) systemd")
    return ex


def extraire_c15(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C15.securite")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    v["services_securite"] = [l.replace("●", " ").split()[0] for l in lignes(section(s, "Services sécurité"))
                              if l.replace("●", " ").split()[0].endswith(".service")]
    v["processus_securite"] = len(lignes(section(s, "Processus sécurité")))
    v["paquets_securite"] = [l.split("\t")[0].strip() for l in lignes(section(s, "Paquets sécurité"))]
    v["agent_audit_actif"] = any("audit" in x.lower() for x in v["services_securite"])
    ex.resume = (f"services : {', '.join(v['services_securite']) or 'aucun correspondant'} ; "
                 f"processus : {v['processus_securite']} ; paquets : {', '.join(v['paquets_securite']) or 'aucun correspondant'}")
    return ex


def extraire_c16(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    v = ex.valeurs
    osr = cle_valeur(preuve.sortie("C16.systeme"))
    v["os_id"] = osr.get("ID")
    ident = preuve.sortie("C16.identification")
    m = re.search(r"===== VERSION =====\s*\n\s*(.+)", ident)
    v["version_debsecan"] = m.group(1).strip() if m else None
    if not (preuve.execute("C16.standard") or preuve.execute("C16.detail")):
        ex.complet = False
        b = preuve.bloc("C16.standard")
        if b and b.statut == "outil_absent":
            ex.limites.append("Debsecan n'est pas installé sur le serveur : C16 non réalisable.")
        return ex
    std = preuve.sortie("C16.standard")
    det = preuve.sortie("C16.detail")
    # Comptages : lignes, CVE uniques (grep '^CVE-' | sort -u), CVE par paquet
    v["lignes_rapport_standard"] = len(std.splitlines()) if std else 0
    v["cve_uniques_standard"] = len({l.split()[0] for l in std.splitlines() if l.startswith("CVE-")})
    v["lignes_rapport_detail"] = len(det.splitlines()) if det else 0
    v["cve_uniques_detail"] = len({l.split()[0] for l in det.splitlines() if l.startswith("CVE-")})
    par_paquet: dict = {}
    entrees = []
    cve = None
    for l in det.splitlines():
        if l.startswith("CVE-"):
            cve = l.split()[0].strip("()")
            continue
        m = re.match(r"^\s+installed:\s+(\S+)\s*(\S*)", l)
        if m:
            par_paquet[m.group(1)] = par_paquet.get(m.group(1), 0) + 1
            entrees.append({"cve": cve, "paquet": m.group(1), "version_installee": m.group(2) or None})
    v["cve_par_paquet"] = sorted(par_paquet.items(), key=lambda kv: (-kv[1], kv[0]))[:30]
    v["entrees"] = entrees
    v["paquets_concernes"] = sorted(par_paquet)
    if v["os_id"] and v["os_id"] != "debian":
        ex.a_verifier.append(f"Système « {v['os_id']} » : Debsecan est conçu pour Debian et compare les paquets aux "
                             "données de sécurité Debian ; les résultats sont à qualifier avant toute conclusion.")
    ex.resume = (f"Debsecan {v['version_debsecan'] or '?'} ; {v['cve_uniques_standard']} CVE unique(s) (rapport standard), "
                 f"{v['cve_uniques_detail']} (rapport détaillé) ; {len(par_paquet)} paquet(s) concerné(s) ; principaux : "
                 + ", ".join(f"{p} ({n})" for p, n in v["cve_par_paquet"][:10]))
    return ex
