"""C18 - analyse croisée des contrôles C01 à C17.

Les règles lisent les valeurs extraites des preuves, croisent les contrôles pour
chaque serveur, puis regroupent un même croisement observé sur plusieurs serveurs
en une seule piste. Une piste est factuelle : la criticité, la référence, le
risque et la recommandation sont renseignés par l'auditeur dans la feuille ANALYSE.

Pour chaque serveur, une règle est « déclenchée », « non déclenchée » ou « non
concluante » (données manquantes), avec les faits utilisés et leur preuve.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import statuts as S

DECLENCHEE = "déclenchée"
NON_DECLENCHEE = "non déclenchée"
NON_CONCLUANTE = "non concluante"


@dataclass
class Fait:
    controle: str
    texte: str
    preuve: Optional[str] = None


@dataclass
class Evaluation:
    regle: str
    hote: str
    resultat: str
    faits: list = field(default_factory=list)
    detail: str = ""


@dataclass(frozen=True)
class Regle:
    id: str
    titre: str
    axe: str
    controles: tuple
    domaine: str
    fonction: Callable


REGLES: list = []


def regle(id_regle, titre, axe, controles, domaine):
    def deco(fn):
        REGLES.append(Regle(id_regle, titre, axe, controles, domaine, fn))
        return fn
    return deco


class Hote:
    """Accès en lecture aux résultats d'un serveur."""

    def __init__(self, libelle: str, resultats: dict):
        self.libelle = libelle
        self.resultats = resultats

    def v(self, cid: str) -> dict:
        r = self.resultats.get(cid)
        return r.valeurs if r and r.statut in S.AVEC_PREUVE else {}

    def ok(self, cid: str) -> bool:
        r = self.resultats.get(cid)
        return bool(r and r.statut in S.AVEC_PREUVE)

    def preuve(self, cid: str) -> Optional[str]:
        r = self.resultats.get(cid)
        return r.fichier_preuve if r else None

    def fait(self, cid: str, texte: str) -> Fait:
        return Fait(cid, texte, self.preuve(cid))


def _nom_base_unite(unite: str) -> str:
    return unite.removesuffix(".service").split("@")[0].lower()


def _correspond(unite: str, processus: str) -> bool:
    """Rapprochement unité systemd / processus par le nom."""
    a, b = _nom_base_unite(unite), processus.lower()
    if len(a) < 3 or len(b) < 3:
        return a == b
    return a == b or a.startswith(b) or b.startswith(a)


# ---------------------------------------------------------------------------
# Règles de croisement
# ---------------------------------------------------------------------------
@regle("R01", "Services en écoute hors boucle locale sans filtrage restrictif identifié",
       "Exposition réseau", ("C06", "C07", "C08", "C17-05"), "Ports / réseau")
def r01(h: Hote):
    if not h.ok("C07"):
        return NON_CONCLUANTE, [], "C07 sans preuve exploitable"
    filtrage = h.v("C08") or {}
    source = "C08"
    if not filtrage.get("synthese") or filtrage["synthese"].startswith("indéterminé"):
        filtrage, source = (h.v("C17-05").get("filtrage") or {}), "C17-05"
    synthese = filtrage.get("synthese")
    if not synthese or synthese.startswith("indéterminé"):
        return NON_CONCLUANTE, [], f"filtrage local indéterminé ({synthese})"
    exposes = h.v("C07").get("ecoutes_hors_boucle_locale", [])
    if not exposes or synthese != "aucun filtrage restrictif identifié":
        return NON_DECLENCHEE, [], f"{len(exposes)} écoute(s) hors boucle locale ; filtrage : {synthese}"
    faits = [h.fait("C07", "écoutes hors boucle locale : " + ", ".join(sorted(
                 {f"{e['proto']}/{e['port']} {'/'.join(e['processus']) or '?'} ({e['adresse']})" for e in exposes}))),
             h.fait(source, f"UFW : {filtrage.get('ufw')} ; iptables INPUT : politique {filtrage.get('iptables_input_politique')}, "
                            f"{filtrage.get('iptables_input_regles')} règle(s) ; nftables : {len(filtrage.get('nft_chaines_entree') or [])} "
                            f"chaîne(s) d'entrée ; synthèse : {synthese}")]
    cles = h.v("C06").get("services_cles") or {}
    actifs = [k for k, e in cles.items() if e == "active"]
    if actifs:
        faits.append(h.fait("C06", "services clés actifs : " + ", ".join(actifs)))
    return DECLENCHEE, faits, ""


@regle("R02", "Paquets potentiellement concernés par des CVE (Debsecan) pour lesquels une mise à jour est disponible",
       "Vulnérabilités et correctifs", ("C03", "C04", "C16"), "Vulnérabilités")
def r02(h: Hote):
    if not (h.ok("C03") and h.ok("C16")):
        return NON_CONCLUANTE, [], "C03 ou C16 sans preuve exploitable"
    concernes = set(h.v("C16").get("paquets_concernes", []))
    maj = {p["paquet"].split(":")[0]: p for p in h.v("C03").get("paquets_a_mettre_a_jour", [])}
    communs = sorted(concernes & set(maj))
    if not communs:
        return NON_DECLENCHEE, [], "aucun paquet commun entre Debsecan et la liste des mises à jour"
    cve = {}
    for e in h.v("C16").get("entrees", []):
        if e["paquet"] in communs:
            cve.setdefault(e["paquet"], set()).add(e["cve"])
    faits = [h.fait("C16", "paquets identifiés comme potentiellement concernés : " + "; ".join(
                 f"{p} ({', '.join(sorted(cve.get(p, []))[:5])}{'…' if len(cve.get(p, [])) > 5 else ''})" for p in communs[:20])),
             h.fait("C03", "mise à jour disponible : " + "; ".join(
                 f"{p} {maj[p]['version_installee'] or '?'} → {maj[p]['version_candidate']}" for p in communs[:20]))]
    os_id = h.v("C16").get("os_id")
    if os_id and os_id != "debian":
        faits.append(h.fait("C16", f"système « {os_id} » : Debsecan compare les paquets aux données Debian, résultats à qualifier"))
    return DECLENCHEE, faits, ""


@regle("R03", "Mises à jour en attente ou non actives (redémarrage requis, noyau plus récent non actif)",
       "Mises à jour", ("C03",), "Versions / mises à jour")
def r03(h: Hote):
    if not h.ok("C03"):
        return NON_CONCLUANTE, [], "C03 sans preuve exploitable"
    v = h.v("C03")
    faits = []
    if v.get("nb_paquets_a_mettre_a_jour"):
        faits.append(h.fait("C03", f"{v['nb_paquets_a_mettre_a_jour']} paquet(s) pouvant être mis à jour, dont "
                                   f"{v.get('nb_depuis_suite_securite', 0)} depuis une suite « -security »"))
    if v.get("redemarrage_requis"):
        faits.append(h.fait("C03", "redémarrage requis" + (f" ({', '.join(v.get('paquets_redemarrage', [])[:10])})"
                                                          if v.get("paquets_redemarrage") else "")))
    if v.get("noyau_plus_recent_non_actif"):
        faits.append(h.fait("C03", f"noyau actif {v.get('noyau_actif')}, noyau installé le plus récent {v.get('noyau_installe_le_plus_recent')}"))
    return (DECLENCHEE, faits, "") if faits else (NON_DECLENCHEE, [], "aucune mise à jour en attente lue")


@regle("R04", "Services exposés au réseau classés « UNSAFE » par systemd-analyze security",
       "Exposition réseau et confinement des services", ("C06", "C07", "C17-01"), "Services")
def r04(h: Hote):
    if not (h.ok("C17-01") and h.ok("C07")):
        return NON_CONCLUANTE, [], "C17-01 ou C07 sans preuve exploitable"
    exposes = h.v("C07").get("ecoutes_hors_boucle_locale", [])
    if exposes and not any(e["processus"] for e in exposes):
        return NON_CONCLUANTE, [], "processus des ports non affichés par ss"
    unsafe = [u for u in h.v("C17-01").get("unites", []) if u["predicat"] == "UNSAFE"]
    rapproches = []
    for u in unsafe:
        for e in exposes:
            procs = [p for p in e["processus"] if _correspond(u["unite"], p)]
            if procs:
                rapproches.append(f"{u['unite']} ({u['exposition']} UNSAFE) ↔ {e['proto']}/{e['port']} {'/'.join(procs)} ({e['adresse']})")
                break
    if not rapproches:
        return NON_DECLENCHEE, [], f"{len(unsafe)} unité(s) UNSAFE, aucune rapprochée d'un port exposé"
    return DECLENCHEE, [h.fait("C17-01", "; ".join(rapproches)),
                        h.fait("C17-01", "un score élevé indique un faible confinement, pas une vulnérabilité : "
                                         "à qualifier selon le rôle, les privilèges et l'exposition du service")], ""


@regle("R05", "Accès SSH et politique d'authentification : éléments à qualifier",
       "Authentification et accès SSH", ("C07", "C09", "C10", "C17-02"), "SSH / accès distant")
def r05(h: Hote):
    if not (h.ok("C09") or h.ok("C17-02")):
        return NON_CONCLUANTE, [], "C09 et C17-02 sans preuve exploitable"
    conf = h.v("C09").get("configuration") or {}
    c17 = h.v("C17-02")
    faits = []
    if conf.get("permitrootlogin") and conf["permitrootlogin"] != "no":
        faits.append(h.fait("C09", f"permitrootlogin {conf['permitrootlogin']}"))
    if conf.get("passwordauthentication") == "yes":
        faits.append(h.fait("C09", "passwordauthentication yes"))
    if h.ok("C17-02") and not c17.get("module_verrouillage_configure"):
        faits.append(h.fait("C17-02", "aucune ligne pam_faillock / pam_tally active dans /etc/pam.d"))
    if (c17.get("login_defs") or {}).get("PASS_MAX_DAYS") == "99999":
        faits.append(h.fait("C17-02", "PASS_MAX_DAYS 99999 dans /etc/login.defs"))
    if not faits:
        return NON_DECLENCHEE, [], "aucun des éléments de la section 14 relevé"
    if conf:
        autres = ", ".join(f"{k} {conf[k]}" for k in ("maxauthtries", "x11forwarding", "allowtcpforwarding", "permitemptypasswords") if k in conf)
        if autres:
            faits.append(h.fait("C09", autres))
    ssh_expose = [e for e in h.v("C07").get("ecoutes_hors_boucle_locale", []) if "sshd" in e["processus"]]
    if ssh_expose:
        faits.append(h.fait("C07", "sshd en écoute sur " + ", ".join(sorted({f"{e['adresse']}:{e['port']}" for e in ssh_expose}))))
    if c17.get("nb_lignes_echecs_24h"):
        faits.append(h.fait("C17-02", f"{c17['nb_lignes_echecs_24h']} ligne(s) d'échec d'authentification sur 24 h"))
    sudo = (h.v("C10").get("groupes_privilegies") or {}).get("sudo")
    if sudo:
        faits.append(h.fait("C10", "membres du groupe sudo : " + ", ".join(sudo)))
    return DECLENCHEE, faits, ""


@regle("R06", "Fichiers modifiables par d'autres comptes que leur propriétaire",
       "Permissions sensibles", ("C11", "C17-03"), "Privilèges")
def r06(h: Hote):
    if not (h.ok("C11") or h.ok("C17-03")):
        return NON_CONCLUANTE, [], "C11 et C17-03 sans preuve exploitable"
    ww = h.v("C11").get("fichiers_world_writable", [])
    go = h.v("C17-03").get("fichiers_ecrivables_groupe_autres", [])
    if not ww and not go:
        return NON_DECLENCHEE, [], "aucun fichier listé"
    faits = []
    if ww:
        faits.append(h.fait("C11", f"{len(ww)} fichier(s) modifiable(s) par tous : " +
                            ", ".join(f"{f['chemin']} {f['droits']} {f['proprietaire']}:{f['groupe']}" for f in ww[:10])))
    if go:
        faits.append(h.fait("C17-03", f"{len(go)} fichier(s) de /etc ou /usr/local modifiable(s) par le groupe ou les autres : " +
                            ", ".join(f"{f['chemin']} {f['droits']} {f['proprietaire']}:{f['groupe']}" for f in go[:10])))
    faits.append(Fait("C18", "à qualifier : qui peut modifier ces fichiers, quel service les utilise et avec quels privilèges"))
    return DECLENCHEE, faits, ""


@regle("R07", "Centralisation des journaux et audit système non démontrés",
       "Journalisation et détection", ("C12", "C15", "C17-06"), "Journalisation")
def r07(h: Hote):
    if not h.ok("C17-06"):
        return NON_CONCLUANTE, [], "C17-06 sans preuve exploitable"
    j = h.v("C17-06")
    faits = []
    if not j.get("transfert_configure"):
        faits.append(h.fait("C17-06", "aucune règle de transfert (omfwd, @@, @) trouvée dans la configuration rsyslog"))
    if h.ok("C15") and not h.v("C15").get("agent_audit_actif"):
        faits.append(h.fait("C15", "aucun service actif correspondant à « audit » dans la liste des services de sécurité"))
    if not faits:
        return NON_DECLENCHEE, [], "transfert configuré et agent d'audit actif"
    faits.append(h.fait("C12", f"rsyslog : {h.v('C12').get('rsyslog') or '?'} ; journald : {h.v('C12').get('journald') or '?'}"))
    faits.append(Fait("C18", "absence d'auditd ≠ absence d'audit : vérifier les autres mécanismes de collecte"))
    return DECLENCHEE, faits, ""


@regle("R08", "Protection antimalware et contrôle d'intégrité non démontrés",
       "Protection antimalware et intégrité", ("C15", "C17-07"), "Antivirus / EDR")
def r08(h: Hote):
    if not (h.ok("C15") and h.ok("C17-07")):
        return NON_CONCLUANTE, [], "C15 ou C17-07 sans preuve exploitable"
    c15, c07 = h.v("C15"), h.v("C17-07")
    if c15.get("services_securite") or c07.get("outils_integrite") or c07.get("outils_antimalware") or c07.get("outils_ids"):
        return NON_DECLENCHEE, [], "au moins un mécanisme trouvé"
    return DECLENCHEE, [h.fait("C15", "aucun service de sécurité correspondant aux motifs recherchés"),
                        h.fait("C17-07", "aucun outil d'intégrité, antimalware ou IDS parmi ceux recherchés"),
                        Fait("C18", "absence d'un outil FIM ≠ absence de toute surveillance d'intégrité")], ""


@regle("R09", "Certificats TLS expirés à la date de collecte ou dont l'émetteur est le sujet",
       "Chiffrement TLS", ("C17-05",), "Chiffrement")
def r09(h: Hote):
    if not h.ok("C17-05"):
        return NON_CONCLUANTE, [], "C17-05 sans preuve exploitable"
    faits = []
    for t in h.v("C17-05").get("tls", []):
        c = t.get("certificat") or {}
        if c.get("expire_a_la_collecte"):
            faits.append(h.fait("C17-05", f"port {t['port']} : certificat expiré (notAfter {c.get('notAfter')})"))
        if c.get("emetteur_egal_sujet"):
            faits.append(h.fait("C17-05", f"port {t['port']} : émetteur identique au sujet ({c.get('subject')})"))
    return (DECLENCHEE, faits, "") if faits else (NON_DECLENCHEE, [], "aucun certificat concerné")


@regle("R10", "Horloge non synchronisée ou aucun service de synchronisation actif",
       "Synchronisation horaire", ("C13",), "Synchronisation horaire")
def r10(h: Hote):
    if not h.ok("C13"):
        return NON_CONCLUANTE, [], "C13 sans preuve exploitable"
    v = h.v("C13")
    if v.get("horloge_synchronisee") is None:
        return NON_CONCLUANTE, [], "état de synchronisation non lu"
    actifs = [n for n, e in (v.get("services") or {}).items() if e == "active"]
    faits = []
    if v.get("horloge_synchronisee") != "yes":
        faits.append(h.fait("C13", f"System clock synchronized: {v.get('horloge_synchronisee')}"))
    if not actifs:
        faits.append(h.fait("C13", "aucun des services systemd-timesyncd, chrony, ntp n'est actif"))
    return (DECLENCHEE, faits, "") if faits else (NON_DECLENCHEE, [], f"synchronisée ; service(s) actif(s) : {', '.join(actifs)}")


@regle("R11", "Avertissements Lynis à vérifier sur la configuration réelle",
       "Résultats Lynis", ("C17",), "Autres")
def r11(h: Hote):
    if not h.ok("C17"):
        return NON_CONCLUANTE, [], "C17 sans preuve exploitable"
    av = h.v("C17").get("avertissements", [])
    if not av:
        return NON_DECLENCHEE, [], "aucun avertissement"
    return DECLENCHEE, [h.fait("C17", "; ".join(f"[{a['test']}] {a['texte']}" for a in av[:15])),
                        Fait("C18", "un avertissement Lynis n'est pas automatiquement une vulnérabilité")], ""


# ---------------------------------------------------------------------------
# Comparaison entre serveurs
# ---------------------------------------------------------------------------
def elements_comparables(h: Hote) -> dict:
    """Éléments à comparer entre serveurs : {thème: {valeur}}."""
    e: dict = {}
    e["Paquet pouvant être mis à jour (C03)"] = {p["paquet"] for p in h.v("C03").get("paquets_a_mettre_a_jour", [])}
    e["CVE Debsecan (C16)"] = {x["cve"] for x in h.v("C16").get("entrees", []) if x.get("cve")}
    e["Port en écoute hors boucle locale (C07)"] = {f"{x['proto']}/{x['port']} {'/'.join(x['processus']) or '?'}"
                                                    for x in h.v("C07").get("ecoutes_hors_boucle_locale", [])}
    e["Paramètre SSH effectif (C09)"] = {f"{k} {v}" for k, v in (h.v("C09").get("configuration") or {}).items()}
    e["Unité systemd UNSAFE (C17-01)"] = {u["unite"] for u in h.v("C17-01").get("unites", []) if u["predicat"] == "UNSAFE"}
    e["Paramètre sysctl (C17-04)"] = {f"{k} = {v}" for k, v in {**h.v("C17-04").get("sysctl_reseau", {}),
                                                              **h.v("C17-04").get("sysctl_securite", {})}.items()}
    e["Politique de mots de passe (C17-02)"] = {f"{k} {v}" for k, v in (h.v("C17-02").get("login_defs") or {}).items()}
    f = h.v("C08")
    if f.get("synthese"):
        e["Filtrage local (C08)"] = {f["synthese"]}
    e["Avertissement Lynis (C17)"] = {f"[{a['test']}] {a['texte']}" for a in h.v("C17").get("avertissements", [])}
    e["Service de sécurité (C15)"] = set(h.v("C15").get("services_securite", []))
    if h.v("C13").get("fuseau"):
        e["Fuseau horaire (C13)"] = {h.v("C13")["fuseau"]}
    return e


def comparer_serveurs(hotes: list) -> list[dict]:
    index: dict = {}
    for h in hotes:
        for theme, valeurs in elements_comparables(h).items():
            for val in valeurs:
                index.setdefault((theme, val), []).append(h.libelle)
    lignes = [{"theme": t, "valeur": v, "serveurs": sorted(s), "nb_serveurs": len(s)} for (t, v), s in index.items()]
    lignes.sort(key=lambda x: (x["theme"], -x["nb_serveurs"], x["valeur"]))
    return lignes


def evaluer(hotes: list) -> tuple[list, list]:
    """Retourne (évaluations par règle et serveur, pistes regroupées)."""
    evaluations = []
    for h in hotes:
        for r in REGLES:
            try:
                resultat, faits, detail = r.fonction(h)
            except Exception as exc:  # une règle en erreur est signalée, jamais ignorée
                resultat, faits, detail = NON_CONCLUANTE, [], f"erreur de la règle : {exc.__class__.__name__} : {exc}"
            evaluations.append(Evaluation(r.id, h.libelle, resultat, faits, detail))
    pistes = []
    for r in REGLES:
        declenchees = [e for e in evaluations if e.regle == r.id and e.resultat == DECLENCHEE]
        if declenchees:
            pistes.append({"regle": r.id, "titre": r.titre, "axe": r.axe,
                           "domaine": r.domaine, "controles": list(r.controles),
                           "hotes": [e.hote for e in declenchees],
                           "faits": {e.hote: [f.__dict__ for f in e.faits] for e in declenchees}})
    pistes.sort(key=lambda p: -len(p["hotes"]))
    return evaluations, pistes
