"""Analyse d'une session : preuves -> un résultat structuré JSON par contrôle.

Fichiers écrits dans <session>/resultats/ :
    Cxx.json            résultat structuré du contrôle (schéma lsaf.resultat/1)
    session.json        synthèse de la session (statuts, anomalies)
"""

from __future__ import annotations

import json
import logging
import re
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import __version__
from . import statuts as S
from .controles import CONTROLES_COLLECTES, PAR_ID, cle_tri
from .extraction import EXTRACTEURS, Extraction
from .session import Session

journal = logging.getLogger("lsaf.analyse")

# Messages indiquant qu'une commande n'a pas pu produire son résultat
MOTIFS_ERREUR = re.compile(r"command not found|Permission denied|sudo: |a password is required|"
                           r"Failed to connect to bus|System has not been booted|Operation not permitted")


@dataclass
class Resultat:
    controle: str
    intitule: str
    session: str
    hote: str
    date_collecte: Optional[str]
    statut: str
    statut_execution: Optional[str]
    fichier_preuve: Optional[str]
    fichier_json: Optional[str]
    sha256_preuve: Optional[str]
    integrite: str
    resume: str = ""
    valeurs: dict = field(default_factory=dict)
    a_verifier: list = field(default_factory=list)
    limites: list = field(default_factory=list)
    erreurs: list = field(default_factory=list)
    blocs: list = field(default_factory=list)
    annexes: list = field(default_factory=list)

    def en_dict(self) -> dict:
        d = asdict(self)
        d["schema"] = "lsaf.resultat/1"
        d["libelle_statut"] = S.LIBELLES[self.statut]
        return d


def analyser_controle(session: Session, cid: str, contexte: dict) -> Resultat:
    definition = PAR_ID[cid]
    pc = session.controles.get(cid)
    execution = pc.execution if pc else None
    preuve = pc.preuve if pc else None
    statut_exec = (execution or {}).get("statut_execution") or (session.manifeste.get("controles") or {}).get(cid)
    r = Resultat(
        controle=cid, intitule=definition.intitule, session=session.id, hote=session.hote,
        date_collecte=(execution or {}).get("debut") or session.date_collecte, statut=S.NON_EXECUTE,
        statut_execution=statut_exec, fichier_preuve=pc.chemin_txt.name if pc and pc.chemin_txt else None,
        fichier_json=pc.chemin_json.name if pc and pc.chemin_json else None,
        sha256_preuve=(execution or {}).get("sha256_preuve"), integrite=pc.integrite if pc else "absente",
    )
    if execution:
        r.blocs = [{k: b.get(k) for k in ("id", "titre", "statut", "code_retour", "programmes_absents")}
                   for b in execution.get("blocs", [])]
        r.limites += execution.get("notes", [])
        r.annexes = execution.get("annexes", [])
    degrades = False
    for b in r.blocs:
        if b["statut"] in S.DEGRADES:
            degrades = True
            extra = f" ({b['programmes_absents']})" if b.get("programmes_absents") else ""
            r.limites.append(f"Bloc {b['id']} non exécuté : {S.DEGRADES[b['statut']]}{extra}.")
    if r.integrite == "modifiee":
        r.erreurs.append("La preuve a été modifiée après la collecte (empreinte SHA-256 différente) : elle n'est pas fiable.")
    if r.integrite == "non_verifiable":
        r.a_verifier.append("Intégrité de la preuve non vérifiable (empreinte ou fichier JSON manquant).")

    erreur_analyse = False
    ex = Extraction(complet=False)
    if preuve is not None:
        try:
            ex = EXTRACTEURS[cid](preuve, contexte)
        except Exception as exc:  # une erreur d'analyse n'est jamais masquée
            erreur_analyse = True
            journal.error("erreur d'extraction %s : %s", cid, exc)
            r.erreurs.append(f"Erreur d'extraction : {exc.__class__.__name__} : {exc}")
            r.erreurs.append(traceback.format_exc(limit=2))
        r.valeurs, r.resume = ex.valeurs, ex.resume
        r.a_verifier += ex.a_verifier
        r.limites += ex.limites
    if preuve is not None:
        for b in preuve.blocs.values():
            if not b.execute:
                continue
            messages = sorted({l.strip()[:160] for l in b.sortie.splitlines() if MOTIFS_ERREUR.search(l)})
            if messages:
                r.a_verifier.append(f"Message(s) d'erreur dans la sortie du bloc {b.id} : " + " | ".join(messages[:3]))
    cles_ok = bool(preuve) and any(
        (preuve.bloc(b) and preuve.bloc(b).execute) for b in definition.blocs_cles)
    r.statut = S.determiner_statut(
        statut_execution=statut_exec, preuve_presente=preuve is not None,
        tronquee=bool(preuve and preuve.tronque), erreur_analyse=erreur_analyse,
        blocs_cles_executes=cles_ok, integrite=r.integrite, extraction_complete=ex.complet,
        blocs_degrades=degrades, elements_a_verifier=bool(r.a_verifier))
    if r.statut == S.COLLECTE_IMPOSSIBLE:
        r.a_verifier.append("Collecte impossible : relancer le contrôle ou justifier l'absence de preuve.")
    contexte[cid] = r.valeurs
    return r


def analyser_session(session: Session, ecrire: bool = True) -> list[Resultat]:
    contexte: dict = {"date_collecte": session.date_collecte, "hote": session.hote}
    resultats = [analyser_controle(session, cid, contexte) for cid in sorted(CONTROLES_COLLECTES, key=cle_tri)]
    if ecrire:
        d = session.dossier_resultats
        d.mkdir(parents=True, exist_ok=True)
        try:
            d.chmod(0o700)
        except OSError:
            pass
        date = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for r in resultats:
            contenu = r.en_dict()
            contenu["date_analyse"] = date
            contenu["version_lsaf"] = __version__
            (d / f"{r.controle}.json").write_text(json.dumps(contenu, indent=2, ensure_ascii=False), encoding="utf-8")
        synthese = {"schema": "lsaf.synthese-session/1", "session": session.id, "hote": session.hote,
                    "date_analyse": date, "version_lsaf": __version__,
                    "anomalies": [a.en_dict() for a in session.anomalies],
                    "statuts": {r.controle: r.statut for r in resultats}}
        (d / "session.json").write_text(json.dumps(synthese, indent=2, ensure_ascii=False), encoding="utf-8")
    return resultats
