"""Extraction C05 à C09."""

from __future__ import annotations

import re

from . import Extraction
from .outils import classer_adresse, lignes, section


def extraire_c05(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C05.reseau")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    interfaces = []
    for l in lignes(section(s, "HOST / INTERFACES")):
        p = l.split()
        if len(p) >= 2 and p[1] in ("UP", "DOWN", "UNKNOWN", "LOWERLAYERDOWN", "DORMANT"):
            interfaces.append({"nom": p[0], "etat": p[1], "adresses": p[2:]})
    v["interfaces"] = interfaces
    v["adresses_ipv4"] = [a.split("/")[0] for i in interfaces if i["nom"] != "lo" for a in i["adresses"]
                          if re.match(r"^\d+\.\d+\.\d+\.\d+/", a)]
    routes = lignes(section(s, "ROUTING"))
    v["routes"] = routes
    defaut = [r for r in routes if r.startswith("default")]
    m = re.search(r"via (\S+)", defaut[0]) if defaut else None
    v["passerelle"] = m.group(1) if m else None
    dns_txt = section(s, "DNS")
    serveurs = []
    for m in re.finditer(r"(?:Current DNS Server|DNS Servers):\s*(.+)", dns_txt):
        serveurs += m.group(1).split()
    serveurs += re.findall(r"^\s*nameserver\s+(\S+)", dns_txt, flags=re.M)
    vus = []
    for x in serveurs:
        if x not in vus:
            vus.append(x)
    v["serveurs_dns"] = vus
    v["netplan"] = lignes(section(s, "NETWORK CONFIGURATION"))
    if not interfaces:
        ex.complet = False
    ex.resume = " ; ".join(x for x in (
        "; ".join(f"{i['nom']} {i['etat']} {' '.join(a for a in i['adresses'] if not a.startswith('fe80'))}".strip()
                  for i in interfaces if i["nom"] != "lo"),
        f"passerelle {v['passerelle']}" if v["passerelle"] else None,
        f"DNS : {', '.join(vus)}" if vus else None) if x)
    return ex


def extraire_c06(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C06.services")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    actifs = [l.strip() for l in lignes(section(s, "SERVICES ACTIFS")) if l.strip().endswith(".service")]
    cles = {}
    for l in lignes(section(s, "ETAT DES SERVICES CLES")):
        m = re.match(r"^\s*(\S+)\s*:\s*(\S*)", l)
        if m:
            cles[m.group(1)] = m.group(2) or "inconnu"
    ex.valeurs = {"services_actifs": actifs, "services_cles": cles}
    if not actifs:
        ex.a_verifier.append("Aucun service actif listé : vérifier l'exécution de systemctl.")
    ex.resume = f"{len(actifs)} service(s) actif(s) ; services clés : " + ", ".join(f"{k} {e}" for k, e in cles.items())
    return ex


RE_SS = re.compile(r"^(?P<proto>tcp|udp|sctp)\s+(?P<etat>\S+)\s+\d+\s+\d+\s+(?P<locale>\S+)\s+(?P<pair>\S+)\s*(?P<processus>.*)$")


def lire_ss(texte: str) -> list[dict]:
    lignes_ss = []
    for l in texte.splitlines():
        m = RE_SS.match(l.strip())
        if not m:
            continue
        hote, _, port = m.group("locale").rpartition(":")
        procs = sorted({p for p, _ in re.findall(r'\("([^"]+)",pid=(\d+)', m.group("processus"))})
        lignes_ss.append({"proto": m.group("proto"), "adresse": hote, "port": port,
                          "exposition": classer_adresse(hote), "processus": procs})
    return lignes_ss


def extraire_c07(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C07.ports")
    if not b or not b.execute:
        ex.complet = False
        return ex
    ecoutes = lire_ss(section(b.sections(), "PORTS TCP/UDP EN ECOUTE"))
    ex.valeurs["ecoutes"] = ecoutes
    hors_boucle = [e for e in ecoutes if e["exposition"] in ("toutes interfaces", "adresse spécifique")]
    ex.valeurs["ecoutes_hors_boucle_locale"] = hors_boucle
    if not ecoutes:
        ex.complet = "command not found" not in b.sortie
        ex.a_verifier.append("Aucun port en écoute lu dans la sortie de ss.")
    if ecoutes and not any(e["processus"] for e in ecoutes):
        ex.a_verifier.append("Processus non affichés par ss (droits insuffisants ?) : rattachement port / service impossible.")
    ex.resume = f"{len(ecoutes)} écoute(s), dont {len(hors_boucle)} hors boucle locale : " + ", ".join(
        sorted({f"{e['proto']}/{e['port']} {'/'.join(e['processus']) or '?'} ({e['adresse']})" for e in hors_boucle}))
    return ex


def lire_iptables(texte: str) -> dict:
    chaines, courante = {}, None
    for l in texte.splitlines():
        m = re.match(r"^Chain (\S+) \((?:policy (\S+)[^)]*|\d+ references)\)", l)
        if m:
            courante = m.group(1)
            chaines[courante] = {"politique": m.group(2), "regles": []}
            continue
        if courante is None or not l.strip() or l.strip().startswith("pkts"):
            continue
        p = l.split()
        if len(p) >= 3:
            chaines[courante]["regles"].append(p[2])
    return chaines


def lire_nft_entree(texte: str) -> list[dict]:
    chaines, courante, prof = [], None, 0
    for l in texte.splitlines():
        s = l.strip()
        m = re.match(r"^chain (\S+) \{", s)
        if m:
            courante, prof = {"nom": m.group(1), "entree": False, "politique": None, "regles_drop": 0}, 1
            continue
        if courante is None:
            continue
        if "hook input" in s:
            courante["entree"] = True
            pm = re.search(r"policy (\w+)", s)
            courante["politique"] = pm.group(1) if pm else None
        elif re.search(r"\b(drop|reject)\b", s):
            courante["regles_drop"] += 1
        prof += s.count("{") - s.count("}")
        if prof <= 0:
            chaines.append(courante)
            courante = None
    return [c for c in chaines if c["entree"]]


def etat_filtrage(ufw: str, nft: str, iptables: str, firewalld: str) -> dict:
    """Synthèse factuelle du filtrage entrant local à partir des sorties de C08 / C17-05."""
    r = {"ufw": None, "firewalld": None, "iptables_input_politique": None, "iptables_input_regles": None,
         "nft_chaines_entree": lire_nft_entree(nft)}
    m = re.search(r"Status:\s*(\w+)", ufw or "")
    r["ufw"] = m.group(1) if m else ("aucune sortie" if not (ufw or "").strip() else "indéterminé")
    fw = (firewalld or "").strip().splitlines()
    r["firewalld"] = fw[0] if fw else "aucune sortie"
    ch = lire_iptables(iptables or "")
    if "INPUT" in ch:
        r["iptables_input_politique"] = ch["INPUT"]["politique"]
        r["iptables_input_regles"] = len(ch["INPUT"]["regles"])
        cibles = set(ch["INPUT"]["regles"])
    else:
        cibles = set()
    lu = any([(ufw or "").strip(), (nft or "").strip(), (iptables or "").strip(), (firewalld or "").strip()])
    restrictif = (r["ufw"] == "active" or r["firewalld"] == "running"
                  or (r["iptables_input_politique"] or "").upper() in ("DROP", "REJECT")
                  or bool(cibles & {"DROP", "REJECT"})
                  or any((c["politique"] or "").lower() == "drop" or c["regles_drop"] for c in r["nft_chaines_entree"]))
    autres = cibles - {"ACCEPT", "DROP", "REJECT", "LOG", "RETURN"}
    if not lu:
        r["synthese"] = "indéterminé (aucune sortie)"
    elif restrictif:
        r["synthese"] = "filtrage restrictif identifié"
    elif autres:
        r["synthese"] = "indéterminé (règles renvoyant vers d'autres chaînes)"
    elif (r["iptables_input_politique"] or "").upper() == "ACCEPT" or "INPUT" not in ch:
        r["synthese"] = "aucun filtrage restrictif identifié"
    else:
        r["synthese"] = "indéterminé"
    return r


def extraire_c08(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C08.parefeu")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    f = etat_filtrage(section(s, "ETAT DU FIREWALL"), section(s, "NFTABLES"), section(s, "IPTABLES"), section(s, "FIREWALLD"))
    ex.valeurs = f
    if f["synthese"].startswith("indéterminé"):
        ex.a_verifier.append(f"Filtrage local {f['synthese']} : vérifier les droits sudo et les règles.")
    ex.resume = (f"UFW : {f['ufw']} ; iptables INPUT : politique {f['iptables_input_politique'] or '?'}, "
                 f"{f['iptables_input_regles'] if f['iptables_input_regles'] is not None else '?'} règle(s) ; "
                 f"nftables : {len(f['nft_chaines_entree'])} chaîne(s) d'entrée ; firewalld : {f['firewalld']} ; "
                 f"synthèse : {f['synthese']}")
    return ex


def extraire_c09(preuve, contexte=None) -> Extraction:
    ex = Extraction()
    b = preuve.bloc("C09.ssh")
    if not b or not b.execute:
        ex.complet = False
        return ex
    s = b.sections()
    v = ex.valeurs
    etat = lignes(section(s, "ETAT DU SERVICE"))
    v["service_ssh"] = etat[0].strip() if etat else None
    version = lignes(section(s, "VERSION"))
    v["version"] = version[0].strip() if version else None
    config = {}
    for l in lignes(section(s, "CONFIGURATION EFFECTIVE")):
        p = l.strip().split(None, 1)
        if len(p) == 2 and re.match(r"^[a-z]+$", p[0]):
            config[p[0]] = f"{config[p[0]]},{p[1]}" if p[0] in config else p[1]
    v["configuration"] = config
    if not config:
        ex.complet = False
        ex.a_verifier.append("Configuration effective (sshd -T) non obtenue : droits sudo insuffisants ou serveur SSH absent.")
    ex.resume = f"service {v['service_ssh'] or '?'} ; {v['version'] or 'version ?'} ; " + ", ".join(
        f"{k} {val}" for k, val in config.items())
    return ex
