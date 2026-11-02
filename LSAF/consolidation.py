"""Consolidation d'une ou plusieurs sessions (une session = un serveur).

Produit les données consolidées utilisées par le classeur et le rapport ; toutes
les valeurs proviennent des fichiers de session.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from . import statuts as S
from .analyse import analyser_session
from .c18 import REGLES, Hote, comparer_serveurs, evaluer
from .controles import CONTROLES_COLLECTES, PAR_ID, cle_tri
from .session import charger_session


class ErreurConsolidation(Exception):
    pass


def _lignes_controles(id_srv: str, libelle: str, resultats: dict) -> list[dict]:
    """Une ligne par contrôle, comme la feuille CONTROLES_ET_PREUVES (C16 sur deux lignes)."""
    lignes = []
    for cid in sorted(CONTROLES_COLLECTES, key=cle_tri):
        r = resultats[cid]
        d = PAR_ID[cid]
        base = {
            "id_serveur": id_srv, "serveur": libelle, "controle": cid, "domaine": d.domaine, "element": d.element,
            "valeur_observee": r.resume or None, "statut": r.statut, "libelle_statut": S.LIBELLES[r.statut],
            "statut_execution": r.statut_execution, "date_collecte": r.date_collecte, "methode": d.methode,
            "outil": d.outil, "preuve": " ; ".join(x for x in [r.fichier_preuve] + [a.get("fichier") for a in r.annexes] if x) or None,
            "fichier_json": r.fichier_json, "sha256": r.sha256_preuve, "integrite": r.integrite,
            "a_verifier": r.a_verifier, "limites": r.limites, "erreurs": [e for e in r.erreurs if not e.startswith("Traceback")],
        }
        lignes.append(base)
        if cid == "C16":
            q = dict(base)
            q["element"] = "Qualification des correctifs disponibles"
            par_paquet = r.valeurs.get("cve_par_paquet") or []
            q["valeur_observee"] = ("CVE par paquet (rapport détaillé) : " + ", ".join(f"{p} ({n})" for p, n in par_paquet[:15])
                                    if par_paquet else None)
            lignes.append(q)
    return lignes


def consolider(chemins: list, inventaire: Optional[dict] = None, campagne: Optional[str] = None,
               ecrire_resultats: bool = True) -> dict:
    inventaire = inventaire or {}
    sessions = [charger_session(Path(p)) for p in chemins]
    if not sessions:
        raise ErreurConsolidation("aucune session trouvée")
    libelles = [s.hote for s in sessions]
    doublons = sorted({x for x in libelles if libelles.count(x) > 1})
    if doublons:
        raise ErreurConsolidation(
            f"plusieurs sessions pour le même serveur : {', '.join(doublons)}. Consolidez une seule session par serveur.")
    sessions.sort(key=lambda s: s.hote.lower())
    ids = {s.hote: f"SRV-LINUX-{n:02d}" for n, s in enumerate(sessions, 1)}

    serveurs, controles, limites = [], [], []
    hotes = []
    for s in sessions:
        res = {r.controle: r for r in analyser_session(s, ecrire=ecrire_resultats)}
        hotes.append(Hote(s.hote, res))
        c01, c05 = res["C01"].valeurs, res["C05"].valeurs
        inv = inventaire.get(s.hote, {})
        outils = ["Commandes natives"]
        if res["C17"].statut in S.AVEC_PREUVE:
            outils.append("Lynis")
        if res["C16"].statut in S.AVEC_PREUVE:
            outils.append("Debsecan")
        if res["C17-01"].statut in S.AVEC_PREUVE:
            outils.append("systemd-analyze")
        if res["C09"].statut in S.AVEC_PREUVE:
            outils.append("sshd -T")
        serveurs.append({
            "id": ids[s.hote], "libelle": s.hote, "session": s.id, "chemin_session": str(s.chemin),
            "date_collecte": s.date_collecte, "execute_en_root": s.manifeste.get("execute_en_root"),
            "os": "Linux", "version_os": c01.get("os") or (s.manifeste.get("systeme") or {}).get("nom"),
            "os_id": c01.get("os_id"), "noyau": c01.get("noyau"), "virtualisation": c01.get("virtualisation"),
            "adresse_ip": ", ".join(c05.get("adresses_ipv4", [])) or None,
            "inventaire": inv, "outils_utilises": ", ".join(outils),
            "nb_controles_avec_preuve": sum(1 for r in res.values() if r.statut in S.AVEC_PREUVE),
            "nb_controles_attendus": len(CONTROLES_COLLECTES),
            "statuts": {k: sum(1 for r in res.values() if r.statut == k) for k in S.TOUS},
            "lynis": {"version": res["C17"].valeurs.get("version_lynis"), "tests": res["C17"].valeurs.get("tests_realises"),
                      "indice": res["C17"].valeurs.get("indice_durcissement"),
                      "avertissements": res["C17"].valeurs.get("nb_avertissements"),
                      "suggestions": res["C17"].valeurs.get("nb_suggestions")},
            "resumes": {cid: res[cid].resume for cid in ("C01", "C02", "C05", "C07", "C08", "C09")},
            "anomalies": [a.en_dict() for a in s.anomalies if a.niveau != "info"],
            "synthetique": bool(s.manifeste.get("synthetique")),
        })
        controles += _lignes_controles(ids[s.hote], s.hote, res)
        for a in s.anomalies:
            if a.niveau == "erreur":
                limites.append({"serveur": s.hote, "controle": a.controle, "texte": f"[{a.code}] {a.message}"})
        for r in res.values():
            for lim in r.limites:
                limites.append({"serveur": s.hote, "controle": r.controle, "texte": lim})

    evaluations, pistes = evaluer(hotes)
    for p in pistes:
        p["ids_serveurs"] = [ids[h] for h in p["hotes"]]
    transversal = comparer_serveurs(hotes)
    for t in transversal:
        t["ids_serveurs"] = [ids[h] for h in t["serveurs"]]

    statuts = [c["statut"] for c in controles if not (c["controle"] == "C16" and c["element"].startswith("Qualification"))]
    donnees = {
        "schema": "lsaf.consolide/1",
        "version_lsaf": __version__,
        "date_generation": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "campagne": campagne,
        "synthetique": any(x["synthetique"] for x in serveurs),
        "serveurs": serveurs,
        "controles": controles,
        "c18": {
            "regles": [{"id": r.id, "titre": r.titre, "axe": r.axe,
                        "controles": list(r.controles), "domaine": r.domaine} for r in REGLES],
            "evaluations": [{"regle": e.regle, "serveur": e.hote, "id_serveur": ids[e.hote], "resultat": e.resultat,
                             "detail": e.detail, "faits": [f.__dict__ for f in e.faits]} for e in evaluations],
            "pistes": pistes,
            "transversal": transversal,
        },
        "limites": limites,
        "indicateurs": {
            "serveurs": len(serveurs),
            "controles_attendus": len(statuts),
            "controles_avec_preuve": sum(1 for x in statuts if x in S.AVEC_PREUVE),
            "statuts": {k: statuts.count(k) for k in S.TOUS},
            "pistes_c18": len(pistes),
            "pistes_transversales": sum(1 for p in pistes if len(p["hotes"]) > 1),
        },
    }
    return donnees


def ecrire_consolide(donnees: dict, chemin: Path) -> Path:
    """Écrit les données consolidées (fichier local, droits 0600 : il contient des données d'audit)."""
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    chemin.write_text(json.dumps(donnees, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    try:
        chemin.chmod(0o600)
    except OSError:
        pass
    return chemin
