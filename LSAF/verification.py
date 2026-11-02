"""Vérification des livrables : cohérence Excel ↔ Word ↔ données consolidées.

Contrôles réalisés :
  - le classeur s'ouvre, contient les feuilles attendues et ses formules ne
    produisent pas d'erreur évidente (références vers des feuilles absentes) ;
  - les indicateurs du rapport (tuiles de la synthèse, tableau « Répartition par
    criticité ») sont identiques à ceux recalculés depuis le classeur ;
  - chaque finding du classeur a sa fiche dans le rapport, et inversement ;
  - chaque serveur du classeur apparaît dans le tableau « Serveurs audités » ;
  - le rapport définitif ne contient aucune piste « À QUALIFIER » ;
  - si consolide.json est fourni : mêmes serveurs et même nombre de lignes de
    contrôle que dans le classeur.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .controles import CRITICITES
from .lecture_classeur import lire_classeur

FEUILLES = ["INVENTAIRE_AUDIT", "CONTROLES_ET_PREUVES", "ANALYSE", "DASHBOARD", "C18_CROISEMENTS", "C18_TRANSVERSAL",
            "LIMITES_COLLECTE"]


@dataclass
class Bilan:
    erreurs: list = field(default_factory=list)
    alertes: list = field(default_factory=list)
    verifications: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.erreurs

    def verifier(self, condition: bool, message_ok: str, message_ko: str, bloquant: bool = True):
        if condition:
            self.verifications.append(message_ok)
        elif bloquant:
            self.erreurs.append(message_ko)
        else:
            self.alertes.append(message_ko)


def verifier_classeur(chemin: Path, bilan: Optional[Bilan] = None) -> Bilan:
    from openpyxl import load_workbook
    bilan = bilan or Bilan()
    wb = load_workbook(chemin)
    manquantes = [f for f in FEUILLES if f not in wb.sheetnames]
    bilan.verifier(not manquantes, "classeur : toutes les feuilles attendues sont présentes",
                   f"classeur : feuille(s) absente(s) : {', '.join(manquantes)}", bloquant=False)
    noms = set(wb.sheetnames)
    references_cassees = set()
    for ws in wb:
        for ligne in ws.iter_rows():
            for cel in ligne:
                if isinstance(cel.value, str) and cel.value.startswith("="):
                    for feuille in re.findall(r"([A-Z_]{4,})!", cel.value):
                        if feuille not in noms:
                            references_cassees.add(feuille)
                    if "#REF!" in cel.value:
                        references_cassees.add("#REF!")
    bilan.verifier(not references_cassees, "classeur : aucune formule ne pointe vers une feuille absente",
                   f"classeur : formules vers des feuilles absentes : {', '.join(sorted(references_cassees))}")
    return bilan


def _textes_docx(chemin: Path):
    from docx import Document
    doc = Document(str(chemin))
    titres3 = [p.text.strip() for p in doc.paragraphs if p.style.name == "Heading 3"]
    tableaux = [[[c.text.strip() for c in r.cells] for r in t.rows] for t in doc.tables]
    texte = "\n".join(p.text for p in doc.paragraphs)
    return titres3, tableaux, texte


def verifier_coherence(chemin_classeur: Path, chemin_rapport: Path, consolide: Optional[dict] = None,
                       brouillon: bool = False) -> Bilan:
    bilan = verifier_classeur(chemin_classeur)
    c = lire_classeur(chemin_classeur)
    ind = c.indicateurs()
    titres3, tableaux, texte = _textes_docx(chemin_rapport)

    # 1. Tuiles de la synthèse exécutive
    tuiles = next((t for t in tableaux if len(t) == 1 and len(t[0]) == 5 and t[0][0].upper().endswith("CONSTATS")), None)
    if tuiles is None:
        bilan.erreurs.append("rapport : tuiles de la synthèse exécutive introuvables")
    else:
        lues = [int(x.split("\n")[0]) for x in tuiles[0]]
        attendues = [ind["findings"]] + [ind["par_criticite"][k] for k in CRITICITES]
        bilan.verifier(lues == attendues, f"synthèse : nombres de constats identiques au classeur ({attendues})",
                       f"synthèse : tuiles {lues} différentes du classeur {attendues}")

    # 2. Tableau « Répartition par criticité »
    rep = next((t for t in tableaux if t and t[0][:2] == ["Criticité", "Constats"]), None)
    if rep is None:
        bilan.erreurs.append("rapport : tableau « Répartition par criticité » introuvable")
    else:
        lues = {ligne[0]: int(ligne[1]) for ligne in rep[1:]}
        for k in CRITICITES:
            bilan.verifier(lues.get(k) == ind["par_criticite"][k], f"répartition : {k} = {ind['par_criticite'][k]}",
                           f"répartition : {k} = {lues.get(k)} dans le rapport, {ind['par_criticite'][k]} dans le classeur")
        bilan.verifier(lues.get("Total") == ind["findings"], f"répartition : total = {ind['findings']}",
                       f"répartition : total {lues.get('Total')} ≠ {ind['findings']}")

    # 3. Une fiche par finding
    codes_classeur = {f.code for f in c.findings}
    codes_rapport = {t.split("–")[0].strip() for t in titres3 if re.match(r"^F\d+", t)}
    bilan.verifier(codes_classeur == codes_rapport, f"fiches : {len(codes_classeur)} finding(s), tous présents dans le rapport",
                   f"fiches : différence classeur/rapport — absents du rapport : {sorted(codes_classeur - codes_rapport)}, "
                   f"absents du classeur : {sorted(codes_rapport - codes_classeur)}")

    # 4. Serveurs
    perimetre = next((t for t in tableaux if t and t[0][:3] == ["ID", "Serveur", "Adresse IP"]), None)
    if perimetre is None:
        bilan.erreurs.append("rapport : tableau « Serveurs audités » introuvable")
    else:
        ids = {ligne[0] for ligne in perimetre[1:]}
        bilan.verifier(ids == {s.id for s in c.serveurs}, f"périmètre : {len(ids)} serveur(s) identiques au classeur",
                       f"périmètre : serveurs différents (rapport {sorted(ids)}, classeur {sorted(s.id for s in c.serveurs)})")

    # 5. Pistes non qualifiées
    if not brouillon:
        bilan.verifier("À QUALIFIER" not in texte and "Pistes non qualifiées" not in texte,
                       "rapport définitif : aucune piste « À QUALIFIER »",
                       "rapport définitif : des pistes « À QUALIFIER » subsistent")
        bilan.verifier("VERSION DE TRAVAIL" not in texte, "rapport définitif : pas de mention « version de travail »",
                       "rapport définitif : mention « VERSION DE TRAVAIL » présente")

    # 6. Données consolidées
    if consolide:
        ids_cons = {s["id"] for s in consolide.get("serveurs", [])}
        bilan.verifier(ids_cons == {s.id for s in c.serveurs}, "consolidé : mêmes serveurs que le classeur",
                       "consolidé : serveurs différents de ceux du classeur", bloquant=False)
        bilan.verifier(len(consolide.get("controles", [])) == len(c.controles),
                       f"consolidé : {len(c.controles)} lignes de contrôle, identiques au classeur",
                       f"consolidé : {len(consolide.get('controles', []))} lignes de contrôle, classeur : {len(c.controles)} "
                       "(lignes ajoutées ou supprimées à la main ?)", bloquant=False)

    # 7. Champs manquants (alertes, non bloquantes)
    sans_resp = [f.code for f in c.findings if not f.responsable]
    if sans_resp:
        bilan.alertes.append(f"{len(sans_resp)} finding(s) sans responsable (N.R. dans le plan) : {', '.join(sans_resp)}")
    sans_ech = [f.code for f in c.findings if not f.echeance]
    if sans_ech:
        bilan.alertes.append(f"{len(sans_ech)} finding(s) sans échéance (N.R. dans le plan) : {', '.join(sans_ech)}")
    sans_ref = [f.code for f in c.findings if not f.reference]
    if sans_ref:
        bilan.alertes.append(f"{len(sans_ref)} finding(s) sans référence : {', '.join(sans_ref)}")
    non_evalues = ind["etats_initiaux"].get("Non renseigné", 0)
    if non_evalues:
        bilan.alertes.append(f"{non_evalues} contrôle(s) sans état initial renseigné (colonne I de CONTROLES_ET_PREUVES)")
    return bilan
