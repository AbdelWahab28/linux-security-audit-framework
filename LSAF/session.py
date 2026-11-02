"""Découverte et validation des sessions de collecte.

Une session (un serveur, une exécution du collecteur) contient :

    session.json                         manifeste écrit par le collecteur
    SHA256SUMS                           empreintes de tous les fichiers
    preuves/Cxx_<HOTE>_<DATE>_<HEURE>.txt    preuves lisibles
    preuves/Cxx_<HOTE>_<DATE>_<HEURE>.json   description de l'exécution
    preuves/C17_<HOTE>_<DATE>_<HEURE>.lynis.txt  sortie brute de Lynis (fichier REPORT)
    resultats/                           résultats structurés (lsaf analyser)

La validation ne « répare » jamais une session : les problèmes sont signalés.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .controles import CONTROLES_COLLECTES
from .preuves import RE_NOM_PREUVE, FichierPreuve, lire_json, lire_preuve, sha256_fichier
from .schemas import valider as valider_schema


@dataclass
class Anomalie:
    niveau: str          # erreur | alerte | info
    code: str
    message: str
    controle: Optional[str] = None

    def en_dict(self) -> dict:
        d = {"niveau": self.niveau, "code": self.code, "message": self.message}
        if self.controle:
            d["controle"] = self.controle
        return d


@dataclass
class PreuveControle:
    controle: str
    execution: Optional[dict] = None
    chemin_json: Optional[Path] = None
    chemin_txt: Optional[Path] = None
    integrite: str = "absente"     # verifiee | modifiee | absente | non_verifiable
    _lu: Optional[FichierPreuve] = None

    @property
    def preuve(self) -> Optional[FichierPreuve]:
        if self._lu is None and self.chemin_txt and self.chemin_txt.exists():
            self._lu = lire_preuve(self.chemin_txt)
        return self._lu


@dataclass
class Session:
    chemin: Path
    manifeste: dict
    id: str
    hote: str
    controles: dict = field(default_factory=dict)   # id contrôle -> PreuveControle
    anomalies: list = field(default_factory=list)

    @property
    def dossier_preuves(self) -> Path:
        return self.chemin / "preuves"

    @property
    def dossier_resultats(self) -> Path:
        return self.chemin / "resultats"

    @property
    def date_collecte(self) -> Optional[str]:
        return self.manifeste.get("debut")

    def erreurs(self) -> list:
        return [a for a in self.anomalies if a.niveau == "erreur"]


def trouver_sessions(chemins: list) -> list[Path]:
    """Dossiers de session trouvés dans les chemins donnés (sessions ou dossiers parents)."""
    trouves: list[Path] = []
    for p in map(Path, chemins):
        if (p / "session.json").exists() or (p / "preuves").is_dir():
            trouves.append(p)
        elif p.is_dir():
            for enfant in sorted(p.iterdir()):
                if enfant.is_dir() and ((enfant / "session.json").exists() or (enfant / "preuves").is_dir()):
                    trouves.append(enfant)
    vus, uniques = set(), []
    for t in trouves:
        r = t.resolve()
        if r not in vus:
            vus.add(r)
            uniques.append(t)
    return uniques


def charger_session(chemin: Path) -> Session:
    chemin = Path(chemin)
    anomalies: list = []
    manifeste, err = lire_json(chemin / "session.json")
    if manifeste is None:
        anomalies.append(Anomalie("erreur", "MANIFESTE_INVALIDE", f"manifeste de session inutilisable : {err}"))
        manifeste = {}
    else:
        for e in valider_schema(manifeste, "session")[:5]:
            anomalies.append(Anomalie("alerte", "MANIFESTE_SCHEMA", f"session.json : {e}"))
    id_session = manifeste.get("session") or chemin.name
    hote = manifeste.get("hote") or "HOTE-INCONNU"
    if manifeste and not manifeste.get("hote_detecte", True) and not manifeste.get("alias"):
        anomalies.append(Anomalie("alerte", "HOTE_NON_DETECTE",
                                  "le nom d'hôte n'a pas pu être détecté : un libellé générique est utilisé"))
    if (manifeste.get("parametres") or {}).get("simulation"):
        anomalies.append(Anomalie("erreur", "SIMULATION", "session produite avec --simulation : elle ne contient aucune preuve"))

    session = Session(chemin=chemin, manifeste=manifeste, id=id_session, hote=hote, anomalies=anomalies)
    dossier = chemin / "preuves"
    if not dossier.is_dir():
        anomalies.append(Anomalie("erreur", "DOSSIER_PREUVES_ABSENT", "le dossier « preuves » est absent"))
        return session

    horodatage = manifeste.get("horodatage")
    for f in sorted(dossier.iterdir()):
        m = RE_NOM_PREUVE.match(f.name)
        if not m:
            anomalies.append(Anomalie("alerte", "FICHIER_INATTENDU", f"fichier hors convention de nommage : {f.name}"))
            continue
        cid, ext = m.group("controle"), m.group("extension")
        if m.group("hote") != hote:
            anomalies.append(Anomalie("erreur", "HOTE_DIFFERENT",
                                      f"{f.name} appartient à l'hôte « {m.group('hote')} », la session est celle de « {hote} »", cid))
            continue
        if horodatage and f"{m.group('date')}_{m.group('heure')}" != horodatage:
            anomalies.append(Anomalie("erreur", "SESSION_DIFFERENTE",
                                      f"{f.name} ne porte pas l'horodatage de la session ({horodatage})", cid))
            continue
        if ext == ".lynis.txt":
            continue
        pc = session.controles.setdefault(cid, PreuveControle(cid))
        if ext == ".txt":
            pc.chemin_txt = f
        else:
            pc.chemin_json = f

    for cid, pc in session.controles.items():
        if pc.chemin_txt is None:
            anomalies.append(Anomalie("erreur", "PREUVE_ABSENTE", f"{cid} : fichier JSON présent sans preuve TXT", cid))
        if pc.chemin_json is None:
            anomalies.append(Anomalie("erreur", "JSON_ABSENT", f"{cid} : preuve TXT sans fichier d'exécution JSON", cid))
            pc.integrite = "non_verifiable"
            continue
        execution, err = lire_json(pc.chemin_json)
        if execution is None:
            anomalies.append(Anomalie("erreur", "JSON_INVALIDE", f"{cid} : {err}", cid))
            pc.integrite = "non_verifiable"
            continue
        pc.execution = execution
        for e in valider_schema(execution, "execution")[:5]:
            anomalies.append(Anomalie("alerte", "JSON_SCHEMA", f"{cid} : {e}", cid))
        for cle, attendu in (("controle", cid), ("session", id_session), ("hote", hote)):
            if execution.get(cle) != attendu:
                anomalies.append(Anomalie("erreur", "JSON_INCOHERENT",
                                          f"{cid} : champ « {cle} » = {execution.get(cle)!r}, attendu {attendu!r}", cid))
        if pc.chemin_txt is not None:
            enregistre = execution.get("sha256_preuve")
            if not enregistre or enregistre == "indisponible":
                pc.integrite = "non_verifiable"
                anomalies.append(Anomalie("alerte", "EMPREINTE_ABSENTE", f"{cid} : aucune empreinte enregistrée", cid))
            elif sha256_fichier(pc.chemin_txt) != enregistre:
                pc.integrite = "modifiee"
                anomalies.append(Anomalie("erreur", "PREUVE_MODIFIEE",
                                          f"{cid} : la preuve a été modifiée après la collecte (empreinte SHA-256 différente)", cid))
            else:
                pc.integrite = "verifiee"
            if pc.preuve and pc.preuve.tronque:
                anomalies.append(Anomalie("erreur", "PREUVE_TRONQUEE", f"{cid} : preuve tronquée (collecte interrompue)", cid))
        for annexe in execution.get("annexes") or []:
            pa = dossier / annexe.get("fichier", "")
            if not pa.exists():
                anomalies.append(Anomalie("alerte", "ANNEXE_ABSENTE", f"{cid} : fichier annexe absent : {annexe.get('fichier')}", cid))
            elif annexe.get("sha256") and sha256_fichier(pa) != annexe["sha256"]:
                anomalies.append(Anomalie("erreur", "ANNEXE_MODIFIEE", f"{cid} : fichier annexe modifié : {annexe.get('fichier')}", cid))

    declares = manifeste.get("controles") or {}
    for cid in CONTROLES_COLLECTES:
        statut = declares.get(cid)
        present = cid in session.controles and session.controles[cid].chemin_txt is not None
        if statut and statut not in ("non_execute",) and not present:
            anomalies.append(Anomalie("erreur", "PREUVE_MANQUANTE",
                                      f"{cid} : le manifeste indique « {statut} » mais aucune preuve n'a été trouvée", cid))
        elif not present:
            anomalies.append(Anomalie("info", "NON_EXECUTE", f"{cid} : non exécuté dans cette session", cid))
    return session
