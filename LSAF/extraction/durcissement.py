"""Extraction C17 (Lynis) et C17-01 à C17-07."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from . import Extraction
from .outils import lignes, lire_stat_access, section
from .reseau import etat_filtrage


# ---------------------------------------------------------------------------
# C17 - Lynis
# ---------------------------------------------------------------------------
def lire_sortie_lynis(texte: str) -> dict:
    r = {"avertissements": [], "suggestions": [], "sections": []}
    mode = None
    for l in texte.splitlines():
        s = l.strip()
        m = re.match(r"^\[\+\]\s*(.+)$", s)
        if m:
            r["sections"].append(m.group(1).strip())
        m = re.match(r"^Hardening index\s*:\s*(\d+)", s)
        if m:
            r["indice_durcissement"] = int(m.group(1))
        m = re.match(r"^Tests performed\s*:\s*(\d+)", s)
        if m:
            r["tests_realises"] = int(m.group(1))
        m = re.match(r"^Lynis (\d+\.\d+\.\d+)", s)
        if m and "version" not in r:
            r["version"] = m.group(1)
        if re.match(r"^Warnings \(\d+\):", s):
            mode = "avertissements"
            continue
        if re.match(r"^Suggestions \(\d+\):", s):
            mode = "suggestions"
            continue
        if re.match(r"^(Great, no warnings|No warnings)", s):
            mode = None
        if mode and s[:1] in ("!", "*"):
            m = re.match(r"^[!*]\s*(.+?)\s*\[([A-Z0-9-]+)\]\s*$", s)
            if m:
                r[mode].append({"test": m.group(2), "texte": m.group(1)})
        elif mode and s.startswith("=") and len(s) > 20:
            mode = None
    return r


def extraire_c17(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    v = ex.valeurs
    ident = preuve.bloc("C17.identification")
    if ident and ident.execute:
        s = ident.sections()
        ver = lignes(section(s, "VERSION LYNIS"))
        v["chemin_lynis"] = ver[0].strip() if ver else None
        v["version_lynis"] = ver[1].strip() if len(ver) > 1 else None
        m = re.search(r"Code retour sudo : (\d+)", ident.sortie)
        v["code_retour_sudo"] = int(m.group(1)) if m else None
    audit = preuve.bloc("C17.audit_lynis")
    if not audit or not audit.execute or not audit.sortie.strip():
        ex.complet = False
        if audit and audit.statut == "outil_absent":
            ex.limites.append("Lynis n'est pas installé sur le serveur : C17 et les sections Lynis des sous-contrôles ne sont pas réalisables.")
        return ex
    lu = lire_sortie_lynis(audit.sortie)
    v.update({k: lu[k] for k in lu if k != "version"})
    v["version_lynis"] = v.get("version_lynis") or lu.get("version")
    v["nb_avertissements"] = len(lu["avertissements"])
    v["nb_suggestions"] = len(lu["suggestions"])
    v["resultats_globaux"] = lignes(preuve.sortie("C17.resultats"))
    if "indice_durcissement" not in v:
        ex.a_verifier.append("Indice de durcissement non trouvé dans la sortie de Lynis.")
    ex.resume = (f"Lynis {v.get('version_lynis') or '?'} ; {v.get('tests_realises', '?')} tests ; indice de durcissement "
                 f"{v.get('indice_durcissement', '?')} ; {v['nb_avertissements']} avertissement(s) ; {v['nb_suggestions']} suggestion(s)")
    ex.limites.append("L'indice de durcissement Lynis est un indicateur global, pas un pourcentage de sécurité.")
    return ex


# ---------------------------------------------------------------------------
# C17-01
# ---------------------------------------------------------------------------
RE_SYSTEMD = re.compile(r"^(?P<unite>\S+\.service)\s+(?P<exposition>\d+(?:\.\d+)?)\s+(?P<predicat>[A-Z]+)")


def extraire_c17_01(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C17-01.systemd")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    unites = []
    for l in lignes(section(s, "SYSTEMD-ANALYZE SECURITY")):
        m = RE_SYSTEMD.match(l.strip())
        if m:
            unites.append({"unite": m.group("unite"), "exposition": float(m.group("exposition")), "predicat": m.group("predicat")})
    v["unites"] = unites
    comptes: dict = {}
    for u in unites:
        comptes[u["predicat"]] = comptes.get(u["predicat"], 0) + 1
    v["repartition"] = comptes
    actifs = []
    for l in lignes(section(s, "SERVICES ACTIFS")):
        jetons = l.replace("●", " ").split()
        if jetons and jetons[0].endswith(".service"):
            actifs.append(jetons[0])
    v["services_actifs"] = actifs
    v["services_actives_au_demarrage"] = [l.split()[0] for l in lignes(section(s, "SERVICES ENABLED")) if l.split()[0].endswith(".service")]
    v["lignes_lynis"] = lignes(section(s, "SECTIONS LYNIS RELATIVES AUX SERVICES"))
    if not unites:
        ex.complet = False
        ex.a_verifier.append("Tableau systemd-analyze security non lu.")
    unsafe = sorted([u for u in unites if u["predicat"] == "UNSAFE"], key=lambda u: -u["exposition"])
    ex.resume = ("répartition : " + ", ".join(f"{k} {n}" for k, n in sorted(comptes.items()))
                 + " ; UNSAFE : " + (", ".join(f"{u['unite']} {u['exposition']}" for u in unsafe[:20]) or "aucune"))
    return ex


# ---------------------------------------------------------------------------
# C17-02
# ---------------------------------------------------------------------------
def _lignes_actives(texte: str) -> list[str]:
    """Lignes « fichier:n:contenu » dont le contenu n'est pas un commentaire."""
    r = []
    for l in lignes(texte):
        m = re.match(r"^([^:]+):(\d+):(.*)$", l)
        contenu = m.group(3) if m else l
        if contenu.strip() and not contenu.strip().startswith("#"):
            r.append(l.strip())
    return r


def extraire_c17_02(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C17-02.authentification")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    ld = {}
    for l in lignes(section(s, "POLITIQUE /ETC/LOGIN.DEFS")):
        contenu = l.split(":", 1)[1] if re.match(r"^\d+:", l) else l
        p = contenu.split()
        if len(p) >= 2:
            ld[p[0]] = p[1]
    v["login_defs"] = ld
    comptes = {}
    for titre, contenu in s.items():
        m = re.match(r"^COMPTE : (\S+)$", titre)
        if m:
            infos = {k.strip(): val.strip() for k, _, val in (l.partition(":") for l in lignes(contenu)) if val}
            comptes[m.group(1)] = infos
    v["vieillissement_comptes"] = comptes
    pam = _lignes_actives(section(s, "PAM - PASSWORD STRENGTH"))
    v["pam_robustesse"] = pam
    v["modules_robustesse"] = sorted({x for l in pam for x in re.findall(r"pam_(pwquality|cracklib|passwdqc)", l)})
    v["option_nullok"] = any("pam_unix" in l and "nullok" in l for l in pam)
    verrou = _lignes_actives(section(s, "PAM - LOCKOUT"))
    v["pam_verrouillage"] = verrou
    v["module_verrouillage_configure"] = any(re.search(r"pam_(faillock|tally2?)\.so", l) for l in verrou)
    fl = lignes(section(s, "COMMAND FAILLOCK"))
    v["commande_faillock"] = fl[0].strip() if fl else None
    v["nb_lignes_echecs_24h"] = len(lignes(section(s, "AUTHENTIFICATIONS ECHOUEES")))
    if not ld:
        ex.a_verifier.append("Paramètres de /etc/login.defs non lus.")
    ex.resume = (" ; ".join(f"{k} {val}" for k, val in ld.items())
                 + " ; " + " ; ".join(f"{c} : max {i.get('Maximum number of days between password change', '?')} j"
                                      for c, i in comptes.items())
                 + f" ; robustesse PAM : {', '.join(v['modules_robustesse']) or 'aucun module pwquality/cracklib/passwdqc'}"
                 + f" ; nullok : {'oui' if v['option_nullok'] else 'non'} ; verrouillage : "
                 + ("configuré" if v["module_verrouillage_configure"] else "aucune ligne faillock/tally active")
                 + f" ; {v['nb_lignes_echecs_24h']} ligne(s) d'échec sur 24 h")
    return ex


# ---------------------------------------------------------------------------
# C17-03
# ---------------------------------------------------------------------------
def extraire_c17_03(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C17-03.permissions")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    v["sudoers"] = lire_stat_access(section(s, "PERMISSIONS SUDOERS"))
    homes = []
    for titre, contenu in s.items():
        if titre.startswith("/home/"):
            for l in lignes(contenu):
                p = l.split()
                if len(p) >= 4 and re.match(r"^\d{3,4}$", p[1]):
                    homes.append({"chemin": p[3], "droits": p[1], "symbolique": p[0], "proprietaire": p[2]})
                elif "No such file" in l or "cannot stat" in l:
                    homes.append({"chemin": titre, "droits": None, "symbolique": None, "proprietaire": None})
    v["repertoires_personnels"] = homes
    ecrivables = []
    for l in lignes(section(s, "FICHIERS SYSTEME ECRIVABLES")):
        p = l.split()
        if len(p) >= 11 and re.match(r"^[-dl][rwxsStT-]{9}$", p[2]):
            ecrivables.append({"droits": p[2], "proprietaire": p[4], "groupe": p[5], "chemin": " ".join(p[10:])})
    v["fichiers_ecrivables_groupe_autres"] = ecrivables
    ex.resume = (" ; ".join(f"{x['fichier']} {x['droits']} {x['proprietaire']}:{x['groupe']}" for x in v["sudoers"])
                 + " ; " + " ; ".join(f"{h['chemin']} {h['droits'] or 'absent'}" for h in homes)
                 + f" ; {len(ecrivables)} fichier(s) de /etc et /usr/local modifiable(s) par le groupe ou les autres")
    return ex


# ---------------------------------------------------------------------------
# C17-04
# ---------------------------------------------------------------------------
def _sysctl(texte: str) -> dict:
    r = {}
    for l in lignes(texte):
        m = re.match(r"^([a-z0-9_.]+)\s*=\s*(.*)$", l.strip())
        if m:
            r[m.group(1)] = m.group(2).strip()
        m = re.search(r"cannot stat /proc/sys/(\S+):", l)
        if m:
            r[m.group(1).replace("/", ".")] = "inexistant"
    return r


def extraire_c17_04(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C17-04.sysctl")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    v["sysctl_reseau"] = _sysctl(section(s, "SYSCTL - PARAMETRES RESEAU"))
    v["sysctl_reseau_usr_sbin"] = _sysctl(section(s, "SYSCTL - VERIFICATION VIA /USR/SBIN/SYSCTL"))
    v["sysctl_securite"] = _sysctl(section(s, "PARAMETRES KERNEL DE SECURITE"))
    v["configuration_persistante"] = _lignes_actives(section(s, "CONFIGURATION SYSCTL PERSISTANTE"))
    core = lignes(section(s, "CORE DUMPS"))
    v["ulimit_core"] = core[0].strip() if core else None
    m = re.search(r"Active:\s*(\S+)", section(s, "CORE DUMPS"))
    v["socket_coredump"] = m.group(1) if m else None
    tout = {**v["sysctl_reseau"], **v["sysctl_securite"]}
    if not tout:
        ex.complet = False
        ex.a_verifier.append("Aucun paramètre sysctl lu.")
    ex.resume = " ; ".join(f"{k} = {val}" for k, val in tout.items()) + f" ; ulimit -c {v['ulimit_core'] or '?'}"
    return ex


# ---------------------------------------------------------------------------
# C17-05
# ---------------------------------------------------------------------------
def _date_openssl(texte: str):
    texte = re.sub(r"\s+", " ", texte.strip())
    for f in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(texte, f).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def extraire_c17_05(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C17-05.reseau")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    v["filtrage"] = etat_filtrage(section(s, "UFW"), section(s, "NFTABLES"), section(s, "IPTABLES FILTER"), "")
    v["ipv6_adresses_globales"] = re.findall(r"inet6 (\S+) scope global", section(s, "IPV6 - ADRESSES GLOBALES"))
    v["ipv6_ecoutes"] = lignes(section(s, "ECOUTE IPV6"))
    v["apache"] = lignes(section(s, "APACHE - ETAT"))[:2]
    tls = {}
    for titre, contenu in s.items():
        m = re.match(r"^PORT (\d+)$", titre)
        if m:
            t = {"port": int(m.group(1)), "connecte": "CONNECTED" in contenu}
            mp = re.search(r"New, (\S+), Cipher is (\S+)", contenu) or re.search(r"Protocol\s*:\s*(\S+)", contenu)
            if mp:
                t["protocole"] = mp.group(1)
            mc = re.search(r"Cipher is (\S+)", contenu) or re.search(r"Cipher\s*:\s*(\S+)", contenu)
            if mc:
                t["chiffrement"] = mc.group(1)
            mv = re.search(r"Verify return code: (\d+) \(([^)]*)\)", contenu)
            if mv:
                t["code_verification"] = f"{mv.group(1)} ({mv.group(2)})"
            tls[t["port"]] = t
    # Certificats (second bloc)
    ref = None
    if (contexte or {}).get("date_collecte"):
        try:
            ref = datetime.fromisoformat(contexte["date_collecte"])
        except ValueError:
            ref = None
    port = None
    for l in preuve.sortie("C17-05.certificats").splitlines():
        m = re.match(r"^\s*PORT TLS : (\d+)", l)
        if m:
            port = int(m.group(1))
            tls.setdefault(port, {"port": port})
            tls[port]["certificat"] = {}
            continue
        if port is None:
            continue
        c = tls[port]["certificat"]
        for cle in ("subject", "issuer", "notBefore", "notAfter", "serial"):
            if l.strip().lower().startswith(cle.lower() + "="):
                c[cle] = l.split("=", 1)[1].strip()
    for t in tls.values():
        c = t.get("certificat") or {}
        if c.get("notAfter") and ref:
            fin = _date_openssl(c["notAfter"])
            if fin:
                c["expire_a_la_collecte"] = fin < ref
        if c.get("subject") and c.get("issuer"):
            c["emetteur_egal_sujet"] = c["subject"] == c["issuer"]
    v["tls"] = [tls[p] for p in sorted(tls)]
    morceaux = [f"filtrage : {v['filtrage']['synthese']}", f"{len(v['ipv6_adresses_globales'])} adresse(s) IPv6 globale(s)"]
    for t in v["tls"]:
        c = t.get("certificat") or {}
        morceaux.append(f"port {t['port']} : " + (f"{t.get('protocole', '?')} {t.get('chiffrement', '')}".strip() if t.get("connecte") else "pas de connexion TLS")
                        + (f", notAfter {c['notAfter']}" if c.get("notAfter") else ""))
    ex.resume = " ; ".join(morceaux)
    return ex


# ---------------------------------------------------------------------------
# C17-06
# ---------------------------------------------------------------------------
def extraire_c17_06(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C17-06.journalisation")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    j = lignes(section(s, "SYSTEMD-JOURNald"))
    v["journald"] = j[0].strip() if j else None
    v["journald_configuration"] = _lignes_actives(section(s, "JOURNALD - CONFIGURATION EFFECTIVE"))
    r = lignes(section(s, "RSYSLOG"))
    v["rsyslog"] = r[0].strip() if r else None
    regles = _lignes_actives(section(s, "RSYSLOG - CONFIGURATION"))
    v["regles_transfert"] = regles
    v["transfert_configure"] = bool(regles)
    v["transfert_udp_ou_tcp_sans_tls"] = [x for x in regles if not re.search(r"StreamDriver|gtls|ossl", x, re.I)]
    v["fichiers_rsyslog_d"] = lignes(section(s, "RSYSLOG - FICHIERS DE CONFIGURATION"))
    supp = [l for l in lignes(section(s, "FICHIERS SUPPRIMES")) if not l.startswith("COMMAND") and "commande absente" not in l]
    v["nb_fichiers_supprimes_ouverts"] = len(supp)
    v["lignes_lynis"] = lignes(section(s, "SECTIONS LYNIS LOGGING / AUDIT"))
    v["mention_auditd_lynis"] = [l for l in v["lignes_lynis"] if "audit" in l.lower()]
    v["nb_alertes_24h"] = len(lignes(section(s, "JOURNAL 24H")))
    ex.resume = (f"journald : {v['journald'] or '?'} ; rsyslog : {v['rsyslog'] or '?'} ; règles de transfert : "
                 + ("; ".join(regles[:5]) if regles else "aucune trouvée")
                 + f" ; {v['nb_fichiers_supprimes_ouverts']} fichier(s) supprimé(s) encore ouvert(s) ; "
                 f"{v['nb_alertes_24h']} ligne(s) d'erreur/alerte sur 24 h")
    return ex


# ---------------------------------------------------------------------------
# C17-07
# ---------------------------------------------------------------------------
OUTILS_INTEGRITE = ("aide", "aide.wrapper", "tripwire", "samhain", "ossec-control", "wazuh-control")
OUTILS_ANTIMALWARE = ("clamscan", "freshclam", "rkhunter", "chkrootkit")
OUTILS_IDS = ("suricata", "snort", "zeek")


def extraire_c17_07(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C17-07.integrite")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs

    def trouves(noms):
        return [n for n in noms if any(x.strip().startswith("/") for x in lignes(s.get(n, "")))]

    v["outils_integrite"] = trouves(OUTILS_INTEGRITE)
    v["outils_antimalware"] = trouves(OUTILS_ANTIMALWARE)
    v["outils_ids"] = trouves(OUTILS_IDS)
    v["paquets_integrite"] = lignes(section(s, "PACKAGES INTEGRITE"))
    v["paquets_antimalware"] = lignes(section(s, "PACKAGES ANTIMALWARE / ROOTKIT"))
    v["paquets_ids"] = lignes(section(s, "PACKAGES IDS / IPS"))
    v["grub"] = lire_stat_access(section(s, "PERMISSIONS GRUB"))
    v["crontab"] = lire_stat_access(section(s, "PERMISSIONS /ETC/CRONTAB"))
    v["fichiers_cron"] = lire_stat_access(section(s, "PERMISSIONS REPERTOIRES CRON"))
    v["lignes_lynis"] = lignes(section(s, "SECTIONS LYNIS INTEGRITE / MALWARE / DEFENSE"))
    ex.resume = (f"intégrité : {', '.join(v['outils_integrite']) or 'aucun outil listé trouvé'} ; antimalware : "
                 f"{', '.join(v['outils_antimalware']) or 'aucun outil listé trouvé'} ; IDS : {', '.join(v['outils_ids']) or 'aucun outil listé trouvé'} ; "
                 + " ; ".join(f"{x['fichier']} {x['droits']}" for x in v["grub"] + v["crontab"]))
    ex.limites.append("Seuls les outils listés par le contrôle sont recherchés.")
    return ex

