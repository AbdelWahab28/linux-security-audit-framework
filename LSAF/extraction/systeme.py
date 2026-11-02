"""Extraction C01 à C04."""

from __future__ import annotations

import re

from . import Extraction
from .outils import cle_valeur, cle_version, lignes, section

FS_PSEUDO = {"tmpfs", "devtmpfs", "squashfs", "overlay", "efivarfs"}


def extraire_c01(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C01.identification")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    osr = cle_valeur(section(s, "SYSTEME D'EXPLOITATION"))
    v = ex.valeurs
    v["os"] = osr.get("PRETTY_NAME")
    v["os_id"] = osr.get("ID")
    v["os_version"] = osr.get("VERSION_ID")
    v["os_nom_code"] = osr.get("VERSION_CODENAME")
    noms = [l.strip() for l in lignes(section(s, "NOM D'HOTE")) if not re.search(r"(Failed|System has not|Can't)", l)]
    v["nom_hote"] = noms[0] if noms else None
    uname = (lignes(section(s, "NOYAU ACTIF")) or [""])[0]
    v["uname"] = uname
    v["noyau"] = uname.split()[2] if len(uname.split()) > 2 else None
    arch = lignes(section(s, "ARCHITECTURE"))
    v["architecture"] = arch[0].strip() if arch else None
    v["bits"] = arch[1].strip() if len(arch) > 1 else None
    virt = [l for l in lignes(section(s, "VIRTUALISATION")) if not l.startswith("Code retour")]
    v["virtualisation"] = virt[0].strip() if virt else None
    if not v["os"]:
        ex.complet = False
        ex.a_verifier.append("Système d'exploitation non identifié dans /etc/os-release.")
    ex.resume = " ; ".join(x for x in (
        v["os"], f"noyau {v['noyau']}" if v["noyau"] else None,
        f"{v['architecture']} ({v['bits']} bits)" if v["architecture"] else None,
        f"virtualisation : {v['virtualisation']}" if v["virtualisation"] else None) if x)
    return ex


def lire_df(texte: str) -> list[dict]:
    rows, avec_type = [], True
    for l in texte.splitlines():
        p = l.split()
        if not p:
            continue
        if p[0] == "Filesystem":
            avec_type = "Type" in p
            continue
        n = 7 if avec_type else 6
        if len(p) < n:
            continue
        if avec_type:
            fs, typ, taille, util, dispo, pct = p[:6]
            point = " ".join(p[6:])
        else:
            fs, taille, util, dispo, pct = p[:5]
            typ, point = None, " ".join(p[5:])
        if (typ in FS_PSEUDO) or (typ is None and fs in FS_PSEUDO):
            continue
        m = re.match(r"^(\d+)%$", pct)
        rows.append({"fs": fs, "type": typ, "taille": taille, "utilise": util, "disponible": dispo,
                     "pourcentage": int(m.group(1)) if m else None, "montage": point})
    return rows


def extraire_c02(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C02.ressources")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    up = section(s, "UPTIME").strip()
    v["uptime"] = up
    m = re.search(r"load average[s]?:\s*(.+)$", up)
    v["charge"] = m.group(1).strip() if m else None
    v["cpu"] = {k.strip(): val.strip() for k, _, val in (l.partition(":") for l in lignes(section(s, "CPU"))) if val}
    for l in lignes(section(s, "MEMORY")):
        p = l.split()
        if p[0] == "Mem:" and len(p) >= 3:
            v["memoire_totale"], v["memoire_utilisee"] = p[1], p[2]
            v["memoire_disponible"] = p[6] if len(p) >= 7 else None
        if p[0] == "Swap:" and len(p) >= 3:
            v["swap_total"], v["swap_utilise"] = p[1], p[2]
    v["disques"] = lire_df(section(s, "DISK"))
    v["inodes"] = lire_df(section(s, "INODES"))
    if not v["disques"]:
        ex.complet = False
    morceaux = []
    if v.get("cpu", {}).get("CPU(s)"):
        morceaux.append(f"{v['cpu']['CPU(s)']} CPU")
    if v.get("memoire_totale"):
        morceaux.append(f"RAM {v['memoire_totale']} dont {v.get('memoire_disponible') or '?'} disponibles")
    if v.get("swap_total"):
        morceaux.append(f"swap {v['swap_total']} dont {v.get('swap_utilise')} utilisés")
    for d in v["disques"]:
        morceaux.append(f"{d['montage']} {d['taille']} dont {d['utilise']} utilisés ({d['pourcentage']} %)")
    if v.get("charge"):
        morceaux.append(f"charge {v['charge']}")
    ex.resume = " ; ".join(morceaux)
    return ex


RE_APT = re.compile(r"^(?P<paquet>[^/\s]+)/(?P<suites>\S+)\s+(?P<candidat>\S+)\s+\S+(?:\s+\[upgradable from: (?P<installe>[^\]]+)\])?")


def extraire_c03(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    v = ex.valeurs
    if preuve.execute("C03.paquets"):
        paquets = []
        for l in preuve.sortie("C03.paquets").splitlines():
            m = RE_APT.match(l.strip())
            if m:
                suites = m.group("suites").split(",")
                paquets.append({"paquet": m.group("paquet"), "suites": suites, "version_candidate": m.group("candidat"),
                                "version_installee": m.group("installe"),
                                "suite_securite": any(x.endswith("-security") for x in suites)})
        v["paquets_a_mettre_a_jour"] = paquets
        v["nb_paquets_a_mettre_a_jour"] = len(paquets)
        v["nb_depuis_suite_securite"] = sum(1 for p in paquets if p["suite_securite"])
    else:
        ex.complet = False
    if preuve.execute("C03.noyau"):
        s = preuve.bloc("C03.noyau").sections()
        actif = (lignes(section(s, "KERNEL RUNNING")) or [None])[0]
        v["noyau_actif"] = actif
        images = []
        for l in lignes(section(s, "INSTALLED KERNEL PACKAGES")):
            p = l.split()
            if len(p) >= 2:
                m = re.match(r"^linux-image-(\d\S*)$", p[1])
                if m:
                    images.append(m.group(1))
        v["noyaux_installes"] = sorted(set(images), key=cle_version)
        if actif and images:
            plus_recent = max(images, key=cle_version)
            v["noyau_installe_le_plus_recent"] = plus_recent
            v["noyau_plus_recent_non_actif"] = cle_version(plus_recent) > cle_version(actif)
        reboot = section(s, "REBOOT STATUS")
        v["redemarrage_requis"] = True if "REBOOT_REQUIRED=YES" in reboot else (False if "REBOOT_REQUIRED=NO" in reboot else None)
        v["paquets_redemarrage"] = [l.strip() for l in lignes(reboot)[1:]]
    if preuve.execute("C03.sources"):
        v["sources_apt"] = [l.strip() for l in lignes(preuve.sortie("C03.sources"))
                            if l.strip().startswith(("deb ", "deb-src ", "URIs:", "Suites:", "Types:"))]
    if preuve.execute("C03.policy"):
        pol = {}
        courant = None
        for l in preuve.sortie("C03.policy").splitlines():
            m = re.match(r"^(\S+):$", l.strip())
            if m and not l.startswith(" "):
                courant = m.group(1)
                pol[courant] = {}
                continue
            m = re.match(r"^\s*(Installed|Candidate):\s*(\S+)", l)
            if m and courant:
                pol[courant]["installe" if m.group(1) == "Installed" else "candidat"] = m.group(2)
        v["versions_policy"] = pol
    morceaux = []
    if "nb_paquets_a_mettre_a_jour" in v:
        morceaux.append(f"{v['nb_paquets_a_mettre_a_jour']} paquet(s) pouvant être mis à jour "
                        f"(dont {v['nb_depuis_suite_securite']} depuis une suite « -security »)")
    if v.get("noyau_actif"):
        morceaux.append(f"noyau actif {v['noyau_actif']}")
    if v.get("noyau_installe_le_plus_recent"):
        morceaux.append(f"noyau installé le plus récent {v['noyau_installe_le_plus_recent']}")
    if v.get("redemarrage_requis") is not None:
        morceaux.append("redémarrage requis : " + ("oui" if v["redemarrage_requis"] else "non"))
    ex.resume = " ; ".join(morceaux)
    ex.limites.append("La liste des mises à jour dépend de la dernière actualisation de l'index APT du serveur "
                      "(le collecteur n'exécute pas « apt update »).")
    return ex


def extraire_c04(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    v = ex.valeurs
    if preuve.execute("C04.logiciels"):
        v["logiciels"] = [{"paquet": a.strip(), "version": b.strip()}
                          for a, _, b in (l.partition("\t") for l in preuve.sortie("C04.logiciels").splitlines()) if b]
    else:
        ex.complet = False
    if preuve.execute("C04.services"):
        etats = {}
        for titre, contenu in preuve.bloc("C04.services").sections().items():
            if titre in ("NGINX", "SSH", "RSYNC"):
                m = re.search(r"Active:\s*(\S+(?: \([^)]*\))?)", contenu)
                etats[titre.lower()] = m.group(1) if m else ("introuvable" if "could not be found" in contenu or "not-found" in contenu else "indéterminé")
        v["etat_services"] = etats
    ex.resume = " ; ".join(f"{l['paquet']} {l['version']}" for l in v.get("logiciels", [])[:25])
    if v.get("etat_services"):
        ex.resume += (" ; " if ex.resume else "") + ", ".join(f"{k} : {e}" for k, e in v["etat_services"].items())
    return ex
