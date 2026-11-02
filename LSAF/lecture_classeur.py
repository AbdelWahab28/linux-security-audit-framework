"""Lecture du classeur d'audit qualifié par l'auditeur.

Le rapport Word est construit à partir du classeur (source de vérité), après
qualification des pistes de la feuille ANALYSE. Ce module relit les valeurs
saisies (et non les résultats des formules) et recalcule les indicateurs en
Python, avec exactement les mêmes règles que les formules du DASHBOARD :
  - un finding = une ligne de ANALYSE dont la colonne C est renseignée ;
  - les serveurs d'un finding = colonne A, séparés par « ; » ;
  - un finding transversal concerne au moins 2 serveurs ;
  - un contrôle « avec preuve » = colonne Preuve non vide.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from openpyxl import load_workbook

from .classeur import MENTION_A_QUALIFIER, PREMIERE
from .controles import CRITICITES


class ErreurClasseur(Exception):
    pass


@dataclass
class Serveur:
    id: str
    nom: str
    ip: str = ""
    os: str = ""
    version_os: str = ""
    role: str = ""
    environnement: str = ""
    criticite: str = ""
    domaine: str = ""
    responsable: str = ""
    date_audit: str = ""
    statut_audit: str = ""
    outils: str = ""
    commentaire: str = ""


@dataclass
class LigneControle:
    id: str
    id_serveur: str
    domaine: str
    element: str
    valeur: str
    etat_initial: str
    date: str
    methode: str
    outil: str
    preuve: str
    controle_lsaf: str = ""
    statut_lsaf: str = ""


@dataclass
class Finding:
    ligne: int
    ids_serveurs: list
    domaine: str
    element: str          # « F01 – intitulé »
    reference: str
    type_reference: str
    constat: str
    risque: str
    priorite: str
    recommandation: str
    action: str
    responsable: str
    echeance: str
    statut: str
    commentaire: str

    @property
    def code(self) -> str:
        return self.element.split("–")[0].split("-")[0].strip() if self.element else f"L{self.ligne}"

    @property
    def intitule(self) -> str:
        if "–" in self.element:
            return self.element.split("–", 1)[1].strip()
        return self.element

    @property
    def nb_serveurs(self) -> int:
        return len(self.ids_serveurs)

    @property
    def a_qualifier(self) -> bool:
        return self.commentaire.strip().upper().startswith(MENTION_A_QUALIFIER.upper())


@dataclass
class Classeur:
    chemin: Path
    serveurs: list = field(default_factory=list)
    controles: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def serveur(self, id_srv: str) -> Optional[Serveur]:
        return next((s for s in self.serveurs if s.id == id_srv), None)

    def nom(self, id_srv: str) -> str:
        s = self.serveur(id_srv)
        return s.nom if s else id_srv

    # ---------------------------------------------------------------- indicateurs (mêmes règles que le DASHBOARD)
    def indicateurs(self) -> dict:
        par_crit = {c: sum(1 for f in self.findings if f.priorite == c) for c in CRITICITES}
        trans = {c: sum(1 for f in self.findings if f.priorite == c and f.nb_serveurs >= 2) for c in CRITICITES}
        par_serveur = {}
        for s in self.serveurs:
            par_serveur[s.id] = {c: sum(1 for f in self.findings if s.id in f.ids_serveurs and f.priorite == c) for c in CRITICITES}
        nb_srv_max = max([len(self.serveurs)] + [f.nb_serveurs for f in self.findings] + [1])
        par_nb = {n: {c: sum(1 for f in self.findings if f.nb_serveurs == n and f.priorite == c) for c in CRITICITES}
                  for n in range(1, nb_srv_max + 1)}
        domaines = {}
        for f in self.findings:
            domaines.setdefault(f.domaine or "Non renseigné", {c: 0 for c in CRITICITES})
            if f.priorite in CRITICITES:
                domaines[f.domaine or "Non renseigné"][f.priorite] += 1
        etats = {}
        for c in self.controles:
            etats[c.etat_initial or "Non renseigné"] = etats.get(c.etat_initial or "Non renseigné", 0) + 1
        return {
            "serveurs": len(self.serveurs),
            "serveurs_audites": sum(1 for s in self.serveurs if any(c.id_serveur == s.id for c in self.controles)),
            "controles": len(self.controles),
            "controles_avec_preuve": sum(1 for c in self.controles if c.preuve.strip()),
            "findings": len(self.findings),
            "par_criticite": par_crit,
            "non_qualifies": sum(1 for f in self.findings if f.priorite not in CRITICITES),
            "transversaux": sum(1 for f in self.findings if f.nb_serveurs >= 2),
            "transversaux_par_criticite": trans,
            "par_serveur": par_serveur,
            "par_nb_serveurs": par_nb,
            "par_domaine": domaines,
            "etats_initiaux": etats,
        }

    # ---------------------------------------------------------------- contrôle de qualification
    def problemes_qualification(self) -> list[str]:
        """Liste des éléments qui empêchent de produire un rapport définitif."""
        pb = []
        ids = {s.id for s in self.serveurs}
        codes = {}
        for f in self.findings:
            ref = f"ANALYSE ligne {f.ligne} ({f.code})"
            if f.a_qualifier:
                pb.append(f"{ref} : piste encore marquée « {MENTION_A_QUALIFIER} » (colonne S).")
            if f.priorite not in CRITICITES:
                pb.append(f"{ref} : niveau de priorité (colonne H) absent ou hors liste.")
            if not f.risque.strip():
                pb.append(f"{ref} : risque / impact (colonne G) non renseigné.")
            if not (f.recommandation.strip() or f.action.strip()):
                pb.append(f"{ref} : recommandation ou action (colonnes I, J) non renseignée.")
            if not f.ids_serveurs:
                pb.append(f"{ref} : aucun ID serveur (colonne A).")
            for i in f.ids_serveurs:
                if i not in ids:
                    pb.append(f"{ref} : ID serveur « {i} » absent de INVENTAIRE_AUDIT.")
            codes.setdefault(f.code, []).append(f.ligne)
        for code, lignes in codes.items():
            if len(lignes) > 1:
                pb.append(f"Identifiant {code} utilisé sur plusieurs lignes de ANALYSE : {', '.join(map(str, lignes))}.")
        return pb


def _txt(v) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%d/%m/%Y %H:%M") if (v.hour or v.minute) else v.strftime("%d/%m/%Y")
    if isinstance(v, date):
        return v.strftime("%d/%m/%Y")
    if isinstance(v, str) and v.startswith("="):
        return ""   # formule non calculée : ignorée (les indicateurs sont recalculés)
    return str(v).strip()


def lire_classeur(chemin: Path) -> Classeur:
    chemin = Path(chemin)
    if not chemin.is_file():
        raise ErreurClasseur(f"classeur introuvable : {chemin}")
    try:
        wb = load_workbook(chemin, data_only=False)
    except Exception as e:  # fichier corrompu, mauvais format…
        raise ErreurClasseur(f"impossible d'ouvrir le classeur {chemin.name} : {e}") from e
    manquantes = [f for f in ("INVENTAIRE_AUDIT", "CONTROLES_ET_PREUVES", "ANALYSE") if f not in wb.sheetnames]
    if manquantes:
        raise ErreurClasseur(f"feuilles absentes du classeur : {', '.join(manquantes)}")
    c = Classeur(chemin)

    ws = wb["INVENTAIRE_AUDIT"]
    for r in range(PREMIERE, ws.max_row + 1):
        v = [_txt(ws.cell(row=r, column=k).value) for k in range(1, 24)]
        if not v[0]:
            continue
        c.serveurs.append(Serveur(id=v[0], nom=v[1] or v[0], ip=v[2], os=v[3], version_os=v[4], role=v[5], environnement=v[6],
                                  criticite=v[7], domaine=v[8], responsable=v[9], date_audit=v[11], statut_audit=v[12],
                                  outils=v[13], commentaire=v[22]))

    ws = wb["CONTROLES_ET_PREUVES"]
    for r in range(PREMIERE, ws.max_row + 1):
        v = [_txt(ws.cell(row=r, column=k).value) for k in range(1, 19)]
        if not v[1]:
            continue
        c.controles.append(LigneControle(id=v[0], id_serveur=v[1], domaine=v[5], element=v[6], valeur=v[7], etat_initial=v[8],
                                         date=v[9], methode=v[10], outil=v[11], preuve=v[12], controle_lsaf=v[13],
                                         statut_lsaf=v[14]))

    ws = wb["ANALYSE"]
    for r in range(PREMIERE, ws.max_row + 1):
        v = [_txt(ws.cell(row=r, column=k).value) for k in range(1, 20)]
        if not v[2]:
            continue
        ids = [x.strip() for x in v[0].split(";") if x.strip()]
        c.findings.append(Finding(ligne=r, ids_serveurs=ids, domaine=v[1], element=v[2], reference=v[3], type_reference=v[4],
                                  constat=v[5], risque=v[6], priorite=v[7], recommandation=v[8], action=v[9],
                                  responsable=v[10], echeance=v[11], statut=v[12], commentaire=v[18]))
    if not c.serveurs:
        raise ErreurClasseur("aucun serveur dans INVENTAIRE_AUDIT")
    return c


def trier_findings(findings: list) -> list:
    """Ordre du rapport : Critique → Haute → Moyenne → Faible, puis nombre de serveurs décroissant, puis identifiant."""
    rang = {c: i for i, c in enumerate(CRITICITES)}
    return sorted(findings, key=lambda f: (rang.get(f.priorite, 9), -f.nb_serveurs, f.code))
