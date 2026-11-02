"""Génération du classeur Excel (registre d'audit).

Feuilles : INVENTAIRE_AUDIT, CONTROLES_ET_PREUVES, ANALYSE, DASHBOARD,
C18_CROISEMENTS, C18_TRANSVERSAL et LIMITES_COLLECTE.

Les colonnes d'appréciation (état initial, référence, risque, priorité,
recommandation, action, responsable, échéance) sont laissées à l'auditeur ; les
pistes C18 sont écrites dans ANALYSE avec la mention « À QUALIFIER ».
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from openpyxl import Workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.series import DataPoint
from openpyxl.formatting.rule import CellIsRule, FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter as L
from openpyxl.worksheet.datavalidation import DataValidation

from . import statuts as S
from .controles import CRITICITES, DOMAINES, ETATS, METHODES, OUTILS, STATUTS_REMEDIATION, TYPES_REFERENCE

POLICE = "Arial"
BLEU = "1F3864"
FIN = Side(style="thin", color="BFBFBF")
BORD = Border(left=FIN, right=FIN, top=FIN, bottom=FIN)
HAUT = Alignment(wrap_text=True, vertical="top")
CENTRE = Alignment(horizontal="center", vertical="center", wrap_text=True)
GRIS_CALCUL = PatternFill("solid", fgColor="F2F2F2")
PREMIERE = 6   # première ligne de données des feuilles de saisie

COULEUR_CRITICITE = {"Critique": "C00000", "Haute": "ED7D31", "Moyenne": "2E75B6", "Faible": "548235"}
COULEUR_STATUT = {S.REUSSI: ("C6EFCE", "006100"), S.A_VERIFIER: ("FFEB9C", "7F6000"), S.PARTIEL: ("FFEB9C", "7F6000"),
                  S.PREUVE_INSUFFISANTE: ("FCE4D6", "833C0B"), S.COLLECTE_IMPOSSIBLE: ("FFC7CE", "9C0006"),
                  S.EN_ECHEC: ("FFC7CE", "9C0006"), S.NON_EXECUTE: ("E7E6E6", "595959")}
MENTION_A_QUALIFIER = "À QUALIFIER"


# --------------------------------------------------------------------------- outils de mise en forme

def police(gras=False, couleur="000000", taille=9, italique=False):
    return Font(name=POLICE, bold=gras, color=couleur, size=taille, italic=italique)


def remplissage(couleur):
    return PatternFill("solid", fgColor=couleur)


def titre_feuille(ws, titre, note, avertissement=None):
    ws["A1"] = titre
    ws["A1"].font = police(True, BLEU, 14)
    ws.row_dimensions[1].height = 24
    ws["A2"] = note
    ws["A2"].font = police(False, "595959", 9, True)
    if avertissement:
        ws["A3"] = avertissement
        ws["A3"].font = police(True, "C00000", 9)


def entetes(ws, groupes, colonnes, largeurs, ligne_groupe=4, ligne_entete=5):
    """groupes : [(col_début, col_fin, texte, couleur_foncée, couleur_claire)]."""
    for debut, fin, texte, fonce, clair in groupes:
        for c in range(debut, fin + 1):
            cel = ws.cell(row=ligne_groupe, column=c)
            cel.fill = remplissage(fonce)
            cel.font = police(True, "FFFFFF", 10)
            cel.alignment = Alignment(vertical="center")
            e = ws.cell(row=ligne_entete, column=c)
            e.fill = remplissage(clair)
        ws.cell(row=ligne_groupe, column=debut, value=texte)
    for i, (nom, largeur) in enumerate(zip(colonnes, largeurs), 1):
        e = ws.cell(row=ligne_entete, column=i, value=nom)
        e.font = police(True, "1F1F1F", 10)
        e.alignment = CENTRE
        e.border = BORD
        ws.column_dimensions[L(i)].width = largeur
    ws.row_dimensions[ligne_groupe].height = 19.5
    ws.row_dimensions[ligne_entete].height = 36


def cellule(ws, ligne, col, valeur, calcul=False, format_nombre=None, centre=False):
    c = ws.cell(row=ligne, column=col, value=valeur)
    c.font = police(taille=10 if not calcul else 10)
    c.alignment = CENTRE if centre else HAUT
    c.border = BORD
    if calcul:
        c.fill = GRIS_CALCUL
    if format_nombre:
        c.number_format = format_nombre
    return c


def liste_validation(ws, plage, valeurs):
    dv = DataValidation(type="list", formula1='"' + ",".join(valeurs) + '"', allow_blank=True)
    dv.error = "Choisir une valeur de la liste."
    dv.errorTitle = "Valeur non prévue"
    dv.add(plage)
    ws.add_data_validation(dv)


def validation_date(ws, plage):
    dv = DataValidation(type="date", operator="greaterThan", formula1="43831", allow_blank=True)
    dv.error = "Saisir une date (jj/mm/aaaa)."
    for morceau in plage.split():
        dv.add(morceau)
    ws.add_data_validation(dv)


def couleurs_valeurs(ws, plage, correspondances):
    """correspondances : {valeur: (fond, police)}."""
    for valeur, (fond, texte) in correspondances.items():
        ws.conditional_formatting.add(plage, CellIsRule(operator="equal", formula=[f'"{valeur}"'],
                                                        fill=remplissage(fond), font=Font(color=texte)))


ETATS_COULEURS = {"Conforme": ("C6EFCE", "006100"), "Partiellement conforme": ("FFEB9C", "7F6000"),
                  "Non conforme": ("FFC7CE", "9C0006"), "Non vérifié": ("E7E6E6", "595959")}
REMEDIATION_COULEURS = {"Terminée": ("C6EFCE", "006100"), "En cours": ("DDEBF7", "1F4E78"),
                        "Non démarrée": ("FCE4D6", "833C0B"), "Acceptée": ("E4DFEC", "3F3151"),
                        "Non applicable": ("E7E6E6", "595959")}


def _date(iso: Optional[str]):
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso).replace(tzinfo=None)
    except ValueError:
        return None


def _texte(valeur) -> str:
    if valeur is None:
        return ""
    if isinstance(valeur, (list, tuple)):
        return " ; ".join(str(v) for v in valeur)
    return str(valeur)


def _hauteur(textes_largeurs, minimum=30, maximum=409):
    """Hauteur de ligne approximative pour que le texte renvoyé à la ligne reste lisible."""
    lignes = 1
    for texte, largeur in textes_largeurs:
        if not texte:
            continue
        n = 0
        for morceau in str(texte).split("\n"):
            n += max(1, -(-len(morceau) // max(1, int(largeur * 1.15))))
        lignes = max(lignes, n)
    return max(minimum, min(maximum, 12.75 * lignes + 4))


# --------------------------------------------------------------------------- INVENTAIRE_AUDIT

INV_COLONNES = ["ID serveur", "Nom serveur", "Adresse IP", "OS", "Version OS", "Rôle / Fonction", "Environnement",
                "Criticité", "Domaine / Hors domaine", "Responsable / Administrateur", "Date prévue audit",
                "Date audit initial", "Statut audit", "Outils utilisés", "Nombre de constats", "Critiques", "Élevés",
                "Moyens", "Faibles", "Statut remédiation", "Date re-audit", "Statut après re-audit", "Commentaire"]
INV_LARGEURS = [15, 20, 15, 10, 26, 28, 15, 11, 16, 24, 13, 13, 12, 34, 11, 10, 9, 9, 9, 15, 13, 20, 42]


def feuille_inventaire(wb, donnees, fin_inv, fin_ana, avertissement):
    ws = wb.active
    ws.title = "INVENTAIRE_AUDIT"
    ws.sheet_properties.tabColor = "1F3864"
    titre_feuille(ws, "INVENTAIRE_AUDIT — Périmètre et avancement par serveur",
                  "Un serveur = une ligne. Colonnes grisées (Nombre de constats → Faibles) calculées automatiquement "
                  "depuis le registre ANALYSE (un constat transversal est compté pour chaque serveur concerné) : ne pas "
                  "saisir. Colonnes Rôle, Environnement, Criticité, Domaine et Responsable : à compléter par l'auditeur "
                  "(ou via le fichier d'inventaire). Conventions et synthèse : feuille DASHBOARD.", avertissement)
    entetes(ws, [(1, 10, "IDENTIFICATION ET PÉRIMÈTRE", "1F3864", "D9E2F3"),
                 (11, 14, "PLANIFICATION ET AUDIT INITIAL", "1F6F78", "D5ECEE"),
                 (15, 19, "CONSTATS (calcul automatique)", "44546A", "DDE1E7"),
                 (20, 22, "REMÉDIATION ET RE-AUDIT", "385723", "E2EFDA"),
                 (23, 23, "DIVERS", "7F7F7F", "EDEDED")], INV_COLONNES, INV_LARGEURS)
    plage_a = f"ANALYSE!$A${PREMIERE}:$A${fin_ana}"
    plage_c = f"ANALYSE!$C${PREMIERE}:$C${fin_ana}"
    plage_h = f"ANALYSE!$H${PREMIERE}:$H${fin_ana}"
    for i, s in enumerate(donnees["serveurs"]):
        r = PREMIERE + i
        inv = s.get("inventaire") or {}
        cherche = f'ISNUMBER(SEARCH(" "&$A{r}&" ;"," "&{plage_a}&" ;"))'
        commentaire = (f"Collecte LSAF : session {s['session']} ; {s['nb_controles_avec_preuve']}/{s['nb_controles_attendus']} "
                       f"contrôles avec preuve ; exécution en root : {'oui' if s.get('execute_en_root') else 'non'}.")
        if inv.get("commentaire"):
            commentaire = inv["commentaire"] + "\n" + commentaire
        valeurs = [s["id"], inv.get("nom") or s["libelle"], inv.get("adresse_ip") or s.get("adresse_ip"), s.get("os") or "Linux",
                   s.get("version_os"), inv.get("role"), inv.get("environnement"), inv.get("criticite"), inv.get("domaine"),
                   inv.get("responsable"), _date(inv.get("date_prevue")), _date(s.get("date_collecte")), "En cours",
                   s.get("outils_utilises"),
                   f'=IF($A{r}="","",SUMPRODUCT({cherche}*({plage_c}<>"")))',
                   f'=IF($A{r}="","",SUMPRODUCT({cherche}*({plage_h}="Critique")))',
                   f'=IF($A{r}="","",SUMPRODUCT({cherche}*({plage_h}="Haute")))',
                   f'=IF($A{r}="","",SUMPRODUCT({cherche}*({plage_h}="Moyenne")))',
                   f'=IF($A{r}="","",SUMPRODUCT({cherche}*({plage_h}="Faible")))',
                   None, None, None, commentaire]
        for c, v in enumerate(valeurs, 1):
            cellule(ws, r, c, v, calcul=15 <= c <= 19, format_nombre="dd/mm/yyyy" if c in (11, 12, 21) else None,
                    centre=15 <= c <= 19)
        ws.row_dimensions[r].height = 39.75
    plage = lambda col: f"{col}{PREMIERE}:{col}{fin_inv}"  # noqa: E731
    liste_validation(ws, plage("D"), ["Linux", "Windows"])
    liste_validation(ws, plage("G"), ["Production", "Préproduction", "Test"])
    liste_validation(ws, plage("H"), CRITICITES)
    liste_validation(ws, plage("I"), ["Domaine", "Hors domaine"])
    liste_validation(ws, plage("M"), ["À faire", "En cours", "Terminé"])
    liste_validation(ws, plage("T"), STATUTS_REMEDIATION)
    liste_validation(ws, plage("V"), ETATS)
    validation_date(ws, f"K{PREMIERE}:L{fin_inv} U{PREMIERE}:U{fin_inv}")
    ws.conditional_formatting.add(plage("A"), FormulaRule(formula=[f'AND($A{PREMIERE}<>"",COUNTIF($A${PREMIERE}:$A${fin_inv},$A{PREMIERE})>1)'],
                                                          fill=remplissage("FFC7CE"), font=Font(color="9C0006")))
    couleurs_valeurs(ws, plage("H"), {"Critique": ("C00000", "FFFFFF"), "Haute": ("F8CBAD", "833C0B"),
                                      "Moyenne": ("FFF2CC", "7F6000"), "Faible": ("DDEBF7", "1F4E78")})
    couleurs_valeurs(ws, plage("M"), {"Terminé": ("C6EFCE", "006100"), "En cours": ("DDEBF7", "1F4E78"),
                                      "À faire": ("FCE4D6", "833C0B")})
    ws.conditional_formatting.add(plage("P"), CellIsRule(operator="greaterThan", formula=["0"], font=Font(color="C00000", bold=True)))
    couleurs_valeurs(ws, plage("T"), REMEDIATION_COULEURS)
    couleurs_valeurs(ws, plage("V"), ETATS_COULEURS)
    ws.freeze_panes = "C6"
    ws.auto_filter.ref = f"A5:W{max(PREMIERE, PREMIERE + len(donnees['serveurs']) - 1)}"
    return ws


# --------------------------------------------------------------------------- CONTROLES_ET_PREUVES

CTL_COLONNES = ["ID constat / contrôle", "ID serveur", "Nom serveur", "OS", "Domaine / Hors domaine", "Domaine de contrôle",
                "Élément contrôlé", "Configuration / Valeur observée", "État initial", "Date et heure du contrôle",
                "Méthode de contrôle", "Outil utilisé", "Preuve",
                "Contrôle LSAF", "Statut de collecte LSAF", "Points à vérifier / limites", "Fichier JSON", "Intégrité de la preuve (SHA-256)"]
CTL_LARGEURS = [13, 15, 18, 10, 15, 24, 32, 62, 18, 17, 18, 20, 46, 11, 18, 50, 40, 22]


def feuille_controles(wb, donnees, fin_inv, fin_ctl, avertissement):
    ws = wb.create_sheet("CONTROLES_ET_PREUVES")
    ws.sheet_properties.tabColor = "1F6F78"
    titre_feuille(ws, "CONTROLES_ET_PREUVES — Contrôles réalisés, valeurs observées et preuves",
                  "Un contrôle = une ligne. Colonnes A à M : structure du registre. LSAF remplit la valeur observée, la "
                  "date, la méthode, l'outil et le nom exact du fichier de preuve. L'ÉTAT INITIAL (colonne I) reste à "
                  "renseigner par l'auditeur : LSAF ne déclare jamais un contrôle conforme. Colonnes N à R : traçabilité "
                  "de la collecte LSAF (ne pas modifier). Colonnes grisées (Nom serveur, OS, Domaine) automatiques.",
                  avertissement)
    entetes(ws, [(1, 6, "IDENTIFICATION", "1F3864", "D9E2F3"),
                 (7, 12, "ÉTAT RÉELLEMENT OBSERVÉ (avant remédiation)", "1F6F78", "D5ECEE"),
                 (13, 13, "TRAÇABILITÉ DES PREUVES", "5B3F8C", "E4DFEC"),
                 (14, 18, "COLLECTE LSAF (automatique — ne pas modifier)", "7F7F7F", "EDEDED")], CTL_COLONNES, CTL_LARGEURS)
    inv = "INVENTAIRE_AUDIT"
    for i, c in enumerate(donnees["controles"]):
        r = PREMIERE + i
        recherche = lambda col: (f'=IF($B{r}="","",IFERROR(INDEX({inv}!${col}${PREMIERE}:${col}${fin_inv},'  # noqa: E731
                                 f'MATCH($B{r},{inv}!$A${PREMIERE}:$A${fin_inv},0))&"","ID inconnu"))')
        preuve = c.get("preuve") if c["statut"] in S.AVEC_PREUVE else None
        if preuve and c.get("annexes"):
            preuve = " ; ".join([preuve] + list(c["annexes"]))
        if c.get("valeur_observee"):
            valeur = c["valeur_observee"]
        else:
            valeur = f"Aucune valeur exploitable — {S.LIBELLES.get(c['statut'], c['statut']).lower()}."
        points = list(c.get("a_verifier") or []) + [x for x in (c.get("limites") or []) if not x.startswith("DONNEES SYNTHETIQUES")]
        integrite = {"verifiee": "vérifiée", "modifiee": "MODIFIÉE", "absente": "empreinte absente",
                     "non_verifiable": "non vérifiable"}.get(c.get("integrite") or "", c.get("integrite") or "")
        if c.get("sha256"):
            integrite = f"{integrite} — {c['sha256'][:16]}…"
        valeurs = [f"C-{i + 1:04d}", c["id_serveur"], recherche("B"), recherche("D"), recherche("I"), c["domaine"], c["element"],
                   valeur, None, _date(c.get("date_collecte")), c.get("methode"), c.get("outil"), preuve,
                   c["controle"], S.LIBELLES.get(c["statut"], c["statut"]), "\n".join(f"• {p}" for p in points) or None,
                   c.get("fichier_json"), integrite or None]
        for col, v in enumerate(valeurs, 1):
            cellule(ws, r, col, v, calcul=col in (3, 4, 5), format_nombre="dd/mm/yyyy hh:mm" if col == 10 else None,
                    centre=col in (14, 15))
        ws.row_dimensions[r].height = _hauteur([(valeur, 62), (valeurs[15], 50), (preuve, 46)], minimum=32.25)
    liste_validation(ws, f"I{PREMIERE}:I{fin_ctl}", ETATS)
    validation_date(ws, f"J{PREMIERE}:J{fin_ctl}")
    ws.conditional_formatting.add(f"A{PREMIERE}:A{fin_ctl}", FormulaRule(
        formula=[f'OR(AND($A{PREMIERE}<>"",COUNTIF($A${PREMIERE}:$A${fin_ctl},$A{PREMIERE})>1),AND($A{PREMIERE}="",$B{PREMIERE}<>""))'],
        fill=remplissage("FFC7CE"), font=Font(color="9C0006")))
    ws.conditional_formatting.add(f"B{PREMIERE}:B{fin_ctl}", FormulaRule(formula=[f'$C{PREMIERE}="ID inconnu"'], fill=remplissage("FFC7CE")))
    couleurs_valeurs(ws, f"I{PREMIERE}:I{fin_ctl}", ETATS_COULEURS)
    ws.conditional_formatting.add(f"M{PREMIERE}:M{fin_ctl}", FormulaRule(
        formula=[f'AND($M{PREMIERE}<>"",ISERROR(SEARCH(".",$M{PREMIERE})))'], fill=remplissage("FFF2CC")))
    ws.conditional_formatting.add(f"M{PREMIERE}:M{fin_ctl}", FormulaRule(
        formula=[f'AND($B{PREMIERE}<>"",LEN(TRIM($M{PREMIERE}))=0)'], fill=remplissage("FFC7CE")))
    couleurs_valeurs(ws, f"O{PREMIERE}:O{fin_ctl}", {S.LIBELLES[k]: v for k, v in COULEUR_STATUT.items()})
    ws.freeze_panes = "I6"
    ws.auto_filter.ref = f"A5:R{max(PREMIERE, PREMIERE + len(donnees['controles']) - 1)}"
    return ws


# --------------------------------------------------------------------------- ANALYSE

ANA_COLONNES = ["ID serveur", "Domaine de contrôle", "Élément contrôlé", "Référence de contrôle", "Type de référence", "Constat",
                "Risque / Impact", "Niveau de priorité", "Recommandation", "Action de remédiation proposée", "Responsable",
                "Échéance", "Statut remédiation", "Date de vérification", "Résultat après remédiation", "État après",
                "Preuve après", "Référence preuve après", "Commentaire"]
ANA_LARGEURS = [17, 18, 38, 46, 20, 80, 58, 12, 46, 62, 18, 13, 16, 34.6, 40, 18, 42, 28, 34]


def texte_constat(piste: dict, serveurs: dict, non_concluants: list) -> str:
    """Constat factuel d'une piste C18 : uniquement des faits observés et leurs preuves."""
    titre = piste["titre"][0].lower() + piste["titre"][1:]
    lignes = [f"Croisement des contrôles {', '.join(piste['controles'])} (règle {piste['regle']}, axe « {piste['axe']} ») : "
              f"{titre}, observé sur {len(piste['hotes'])} serveur(s).", ""]
    for hote, id_srv in zip(piste["hotes"], piste["ids_serveurs"]):
        lignes.append(f"{id_srv} ({hote}) :")
        for f in piste["faits"].get(hote, []):
            if f["controle"] == "C18":
                lignes.append(f"• Point de vigilance : {f['texte']}")
                continue
            preuve = f" (preuve : {f['preuve']})" if f.get("preuve") else ""
            lignes.append(f"• [{f['controle']}] {f['texte']}{preuve}")
        lignes.append("")
    if non_concluants:
        lignes.append("Règle non concluante (données manquantes) pour : " + ", ".join(non_concluants) + ".")
    return "\n".join(lignes).strip()


def lignes_analyse(donnees: dict) -> list[dict]:
    """Une ligne ANALYSE par piste C18, triée par nombre de serveurs concernés puis par règle."""
    libelles = {s["id"]: s["libelle"] for s in donnees["serveurs"]}
    pistes = sorted(donnees["c18"]["pistes"], key=lambda p: (-len(p["hotes"]), p["regle"]))
    lignes = []
    for n, p in enumerate(pistes, 1):
        non_concluants = [f"{e['id_serveur']} ({libelles.get(e['id_serveur'], e['serveur'])})"
                          for e in donnees["c18"]["evaluations"] if e["regle"] == p["regle"] and e["resultat"] == "non concluante"]
        lignes.append({
            "id_serveurs": " ; ".join(p["ids_serveurs"]),
            "domaine": p["domaine"],
            "element": f"F{n:02d} – {p['titre']}",
            "constat": texte_constat(p, libelles, non_concluants),
            "commentaire": (f"{MENTION_A_QUALIFIER} — piste générée par la règle {p['regle']} (axe « {p['axe']} »). "
                            "Compléter la référence (D, E), le risque (G), le niveau de priorité (H), la recommandation et "
                            "l'action (I, J), le responsable et l'échéance (K, L). Supprimer la ligne si la piste n'est pas "
                            "retenue ; retirer cette mention une fois la ligne qualifiée."),
            "regle": p["regle"],
        })
    return lignes


def feuille_analyse(wb, donnees, fin_ana, avertissement):
    ws = wb.create_sheet("ANALYSE")
    ws.sheet_properties.tabColor = "9C5700"
    titre_feuille(ws, "ANALYSE — Évaluation, risque, recommandation, remédiation et vérification",
                  "Registre des findings C18 : 1 ligne = 1 finding (éventuellement transversal). Colonne A : ID serveur(s) "
                  "séparés par « ; » ; colonne C : identifiant F## et intitulé ; la traçabilité vers les contrôles et les "
                  "preuves TXT figure dans le constat. Les lignes générées par LSAF sont des PISTES « À QUALIFIER » : "
                  "l'auditeur renseigne référence, risque, priorité, recommandation, action, responsable et échéance, "
                  "trie le registre par criticité, et supprime les pistes non retenues. Colonnes « Vérification après "
                  "remédiation » à renseigner uniquement après remédiation effective.", avertissement)
    entetes(ws, [(1, 3, "IDENTIFICATION DU FINDING", "1F3864", "D9E2F3"),
                 (4, 8, "ÉVALUATION", "9C5700", "FCE4D6"),
                 (9, 13, "RECOMMANDATION ET REMÉDIATION", "385723", "E2EFDA"),
                 (14, 19, "VÉRIFICATION APRÈS REMÉDIATION", "44546A", "DDE1E7")], ANA_COLONNES, ANA_LARGEURS)
    lignes = lignes_analyse(donnees)
    for i, l in enumerate(lignes):
        r = PREMIERE + i
        valeurs = [l["id_serveurs"], l["domaine"], l["element"], None, None, l["constat"], None, None, None, None, None,
                   None, None, None, None, None, None, None, l["commentaire"]]
        for c, v in enumerate(valeurs, 1):
            cellule(ws, r, c, v, format_nombre="dd/mm/yyyy" if c in (12, 14) else None, centre=c == 8)
        ws.row_dimensions[r].height = _hauteur([(l["constat"], 80), (l["commentaire"], 34)], minimum=60)
    plage = lambda col: f"{col}{PREMIERE}:{col}{fin_ana}"  # noqa: E731
    liste_validation(ws, plage("H"), CRITICITES)
    liste_validation(ws, plage("E"), TYPES_REFERENCE)
    liste_validation(ws, plage("M"), STATUTS_REMEDIATION)
    liste_validation(ws, plage("P"), ETATS)
    validation_date(ws, f"L{PREMIERE}:L{fin_ana} N{PREMIERE}:N{fin_ana}")
    ws.conditional_formatting.add(f"A{PREMIERE}:S{fin_ana}", FormulaRule(
        formula=[f'LEFT($S{PREMIERE},{len(MENTION_A_QUALIFIER)})="{MENTION_A_QUALIFIER}"'], fill=remplissage("FFF8E1")))
    couleurs_valeurs(ws, plage("H"), {k: (v, "FFFFFF") for k, v in COULEUR_CRITICITE.items()})
    ws.conditional_formatting.add(plage("L"), FormulaRule(
        formula=[f'AND($L{PREMIERE}<>"",$L{PREMIERE}<TODAY(),$M{PREMIERE}<>"Terminée",$M{PREMIERE}<>"Acceptée",$M{PREMIERE}<>"Non applicable")'],
        font=Font(color="C00000", bold=True)))
    couleurs_valeurs(ws, plage("M"), REMEDIATION_COULEURS)
    couleurs_valeurs(ws, plage("P"), ETATS_COULEURS)
    ws.freeze_panes = "C6"
    ws.auto_filter.ref = f"A5:S{max(PREMIERE, PREMIERE + len(lignes) - 1)}"
    return ws, lignes


# --------------------------------------------------------------------------- DASHBOARD

def _kpi(ws, col, texte, formule, sous_formule, fond, couleur_valeur):
    c1, c2 = L(col), L(col + 1)
    for ligne in (3, 4, 5):
        ws.merge_cells(f"{c1}{ligne}:{c2}{ligne}")
    t = ws[f"{c1}3"]
    t.value = texte
    t.font = police(True, "595959" if fond == "F2F2F2" else "FFFFFF", 9)
    v = ws[f"{c1}4"]
    v.value = formule
    v.font = police(True, couleur_valeur, 24)
    s = ws[f"{c1}5"]
    s.value = sous_formule
    s.font = police(False, "595959" if fond == "F2F2F2" else "FFFFFF", 8)
    for ligne in (3, 4, 5):
        for c in (col, col + 1):
            cel = ws.cell(row=ligne, column=c)
            cel.fill = remplissage(fond)
            cel.alignment = CENTRE


def _bandeau(ws, ligne, col_debut, col_fin, texte):
    ws.merge_cells(start_row=ligne, start_column=col_debut, end_row=ligne, end_column=col_fin)
    c = ws.cell(row=ligne, column=col_debut, value=texte)
    c.font = police(True, "FFFFFF", 10)
    for col in range(col_debut, col_fin + 1):
        ws.cell(row=ligne, column=col).fill = remplissage(BLEU)
    ws.row_dimensions[ligne].height = 19.5


def _entete_tableau(ws, ligne, colonnes):
    """colonnes : [(col, texte, fusion_jusqua_col|None)]"""
    for col, texte, fusion in colonnes:
        if fusion:
            ws.merge_cells(start_row=ligne, start_column=col, end_row=ligne, end_column=fusion)
        c = ws.cell(row=ligne, column=col, value=texte)
        c.font = police(True, "1F1F1F", 9)
        c.alignment = Alignment(horizontal="left" if col in (2, 16) else "center", vertical="center", wrap_text=True)
        for x in range(col, (fusion or col) + 1):
            ws.cell(row=ligne, column=x).fill = remplissage("D9E2F3")
            ws.cell(row=ligne, column=x).border = BORD


def _ligne(ws, ligne, valeurs, total=False, pourcent_cols=(), fusion_b=False):
    for col, v in valeurs:
        c = ws.cell(row=ligne, column=col, value=v)
        c.font = police(total, "000000", 10)
        c.border = BORD
        c.alignment = Alignment(horizontal="left" if col in (2, 16) else "center", vertical="center", wrap_text=col in (2, 16))
        if total:
            c.fill = GRIS_CALCUL
        if col in pourcent_cols:
            c.number_format = "0%"
    if fusion_b:
        ws.merge_cells(start_row=ligne, start_column=2, end_row=ligne, end_column=3)
        ws.cell(row=ligne, column=3).border = BORD
        if total:
            ws.cell(row=ligne, column=3).fill = GRIS_CALCUL


def _graphique(ws, titre, categories, series, ancre, empile=False, horizontal=False, couleurs=None, couleurs_series=None,
               noms_series=None, hauteur=7.5, largeur=None):
    if largeur is None:
        largeur = 10.5 if ancre.startswith("H") else 15
    g = BarChart()
    g.type = "bar" if horizontal else "col"
    g.grouping = "stacked" if empile else "clustered"
    if empile:
        g.overlap = 100
    g.title = titre
    g.style = 10
    g.height, g.width = hauteur, largeur
    g.legend = None if not empile else g.legend
    for i, ref in enumerate(series):
        g.add_data(ref, titles_from_data=False)
        if noms_series:
            from openpyxl.chart.series import SeriesLabel
            g.series[-1].tx = SeriesLabel(v=noms_series[i])
    g.set_categories(categories)
    if couleurs_series:
        for s, couleur in zip(g.series, couleurs_series):
            s.graphicalProperties.solidFill = couleur
            s.graphicalProperties.line.solidFill = couleur
    elif couleurs and g.series:
        s = g.series[0]
        for idx, couleur in enumerate(couleurs):
            pt = DataPoint(idx=idx)
            pt.graphicalProperties.solidFill = couleur
            pt.graphicalProperties.line.solidFill = couleur
            s.dPt.append(pt)
    else:
        for s in g.series:
            s.graphicalProperties.solidFill = BLEU
    if not empile:
        g.dataLabels = DataLabelList()
        g.dataLabels.showVal = True
        g.dataLabels.showSerName = False
        g.dataLabels.showCatName = False
        g.dataLabels.showLegendKey = False
        g.dataLabels.showPercent = False
    g.y_axis.majorGridlines = None
    g.y_axis.delete = False
    g.x_axis.delete = False
    ws.add_chart(g, ancre)
    return g


def feuille_dashboard(wb, donnees, fin_inv, fin_ctl, fin_ana, avertissement):
    ws = wb.create_sheet("DASHBOARD")
    ws.sheet_properties.tabColor = "385723"
    ws.sheet_view.showGridLines = False
    for col, largeur in {"A": 2, "B": 14, "C": 16, "D": 12, "E": 11, "F": 11, "G": 11, "H": 9, "I": 9, "J": 9, "K": 9,
                         "L": 9, "M": 9, "N": 3, "O": 3, "P": 34, "Q": 11, "Z": 3, "AA": 32, "AB": 28, "AC": 30, "AD": 28,
                         "AE": 3, "AF": 13, "AG": 13}.items():
        ws.column_dimensions[col].width = largeur
    ws["B1"] = "DASHBOARD — État de l'audit des serveurs"
    ws["B1"].font = police(True, BLEU, 16)
    ws.row_dimensions[1].height = 25.5
    if avertissement:
        ws["B2"] = avertissement
        ws["B2"].font = police(True, "C00000", 9)

    CP = "CONTROLES_ET_PREUVES"
    ctl_b = f"{CP}!$B${PREMIERE}:$B${fin_ctl}"
    ctl_m = f"{CP}!$M${PREMIERE}:$M${fin_ctl}"
    ctl_i = f"{CP}!$I${PREMIERE}:$I${fin_ctl}"
    ctl_f = f"{CP}!$F${PREMIERE}:$F${fin_ctl}"
    ctl_o = f"{CP}!$O${PREMIERE}:$O${fin_ctl}"
    ana_a = f"ANALYSE!$A${PREMIERE}:$A${fin_ana}"
    ana_b = f"ANALYSE!$B${PREMIERE}:$B${fin_ana}"
    ana_c = f"ANALYSE!$C${PREMIERE}:$C${fin_ana}"
    ana_h = f"ANALYSE!$H${PREMIERE}:$H${fin_ana}"
    ana_s = f"ANALYSE!$S${PREMIERE}:$S${fin_ana}"
    inv_a = f"INVENTAIRE_AUDIT!$A${PREMIERE}:$A${fin_inv}"
    nb_ana = fin_ana - PREMIERE + 1
    af = f"$AF$5:$AF${4 + nb_ana}"
    ag = f"$AG$5:$AG${4 + nb_ana}"
    total_ctl = f'SUMPRODUCT(({ctl_b}<>"")*1)'
    avec_preuve = f'SUMPRODUCT(({ctl_b}<>"")*(LEN(TRIM({ctl_m}))>0))'
    a_qualifier = f'COUNTIF({ana_s},"{MENTION_A_QUALIFIER}*")'

    # Indicateurs (ligne 3 à 5)
    _kpi(ws, 2, "SERVEURS AUDITÉS", f'=SUMPRODUCT(({inv_a}<>"")*(COUNTIF({ctl_b},{inv_a})>0))',
         f'="sur "&SUMPRODUCT(({inv_a}<>"")*1)&" au périmètre (INVENTAIRE_AUDIT)"', "F2F2F2", BLEU)
    _kpi(ws, 4, "CONTRÔLES ENREGISTRÉS", f"={total_ctl}",
         f'=SUMPRODUCT(({ctl_b}<>"")*({ctl_i}<>""))&" avec état initial renseigné"', "F2F2F2", BLEU)
    _kpi(ws, 6, "FINDINGS C18", f'=SUMPRODUCT(({ana_c}<>"")*1)',
         f'="dont "&{a_qualifier}&" à qualifier"', "F2F2F2", BLEU)
    _kpi(ws, 8, "CONTRÔLES AVEC PREUVE", f"={avec_preuve}",
         f'=IF({total_ctl}=0,"",TEXT({avec_preuve}/{total_ctl},"0%")&" du total")', "F2F2F2", "385723")
    _kpi(ws, 10, "CONTRÔLES SANS PREUVE", f"={total_ctl}-{avec_preuve}",
         f'=IF({total_ctl}=0,"",TEXT(({total_ctl}-{avec_preuve})/{total_ctl},"0%")&" du total")', "F2F2F2", "C00000")
    _kpi(ws, 12, "CONTRÔLES À ÉVALUER", f'={total_ctl}-SUMPRODUCT(({ctl_b}<>"")*({ctl_i}<>""))',
         "État initial non renseigné", "F2F2F2", "9C5700")
    # FINDINGS TRANSVERSAUX (colonne P)
    for ligne, valeur, taille in ((3, "FINDINGS TRANSVERSAUX", 9), (4, f'=COUNTIF({af},">=2")', 24),
                                  (5, f'="sur "&SUMPRODUCT(({ana_c}<>"")*1)&" findings (≥ 2 serveurs)"', 8)):
        c = ws.cell(row=ligne, column=16, value=valeur)
        c.font = police(ligne != 5, "FFFFFF", taille)
        c.fill = remplissage(BLEU)
        c.alignment = CENTRE
    for i, crit in enumerate(CRITICITES):
        col = 17 + 2 * i
        _kpi(ws, col, crit.upper(), f'=COUNTIF({ana_h},"{crit}")',
             f'="dont "&COUNTIFS({ana_h},"{crit}",{af},">=2")&" transversal(aux)"', COULEUR_CRITICITE[crit], "FFFFFF")
    ws.row_dimensions[3].height = 18
    ws.row_dimensions[4].height = 37.5
    ws.row_dimensions[5].height = 18

    # Colonnes de calcul AF / AG (nombre de serveurs par finding, rang transversal)
    ws["AF3"] = "Calcul (ne pas modifier)"
    ws["AF3"].font = police(True, "595959", 9)
    ws["AF4"], ws["AG4"] = "Nb serveurs du finding", "Rang transversal"
    for k in range(nb_ana):
        r_ana = PREMIERE + k
        r = 5 + k
        ws.cell(row=r, column=32, value=f'=IF(ANALYSE!$C{r_ana}="","",LEN(ANALYSE!$A{r_ana})-LEN(SUBSTITUTE(ANALYSE!$A{r_ana},";",""))+1)')
        ws.cell(row=r, column=33, value=f'=IF(AF{r}="","",IF(AF{r}>=2,COUNTIF($AF$5:AF{r},">=2"),""))')
        for col in (32, 33):
            ws.cell(row=r, column=col).font = police(False, "7F7F7F", 8)

    # Listes de référence (AA à AD)
    ws["AA2"] = "Listes de référence (alimentent les listes déroulantes et les tableaux)"
    ws["AA2"].font = police(True, BLEU, 10)
    for col, (titre, valeurs) in enumerate((("Domaines de contrôle", DOMAINES), ("Méthodes de contrôle", METHODES),
                                            ("Outils utilisés", OUTILS), ("Types de référence", TYPES_REFERENCE)), 27):
        c = ws.cell(row=3, column=col, value=titre)
        c.font = police(True, "1F1F1F", 9)
        c.fill = remplissage("D9E2F3")
        for k, v in enumerate(valeurs):
            x = ws.cell(row=4 + k, column=col, value=v)
            x.font = police(False, "595959", 9)

    serveurs = donnees["serveurs"]
    n = max(1, len(serveurs))

    # ---- colonne de gauche (B..M) : tableaux 1 à 5 + statut LSAF, graphiques en H
    ligne = 7
    _bandeau(ws, ligne, 2, 13, "1. CONTRÔLES PAR SERVEUR")
    _entete_tableau(ws, ligne + 1, [(2, "ID serveur", None), (3, "Nom serveur", None), (4, "Statut audit", None),
                                    (5, "Contrôles", None), (6, "Avec preuve", None), (7, "Findings C18", None)])
    d1 = ligne + 2
    for k in range(n):
        r = d1 + k
        idx = f"ROWS(B${d1}:B{r})"
        _ligne(ws, r, [
            (2, f'=IFERROR(INDEX({inv_a},{idx})&"","")'),
            (3, f'=IFERROR(INDEX(INVENTAIRE_AUDIT!$B${PREMIERE}:$B${fin_inv},{idx})&"","")'),
            (4, f'=IFERROR(INDEX(INVENTAIRE_AUDIT!$M${PREMIERE}:$M${fin_inv},{idx})&"","")'),
            (5, f'=IF($B{r}="","",SUMPRODUCT(({ctl_b}=$B{r})*1))'),
            (6, f'=IF($B{r}="","",SUMPRODUCT(({ctl_b}=$B{r})*(LEN(TRIM({ctl_m}))>0)))'),
            (7, f'=IF($B{r}="","",SUMPRODUCT(ISNUMBER(SEARCH(" "&$B{r}&" ;"," "&{ana_a}&" ;"))*({ana_c}<>"")))'),
        ])
    tot1 = d1 + n
    _ligne(ws, tot1, [(2, "Total"), (3, None), (4, None), (5, f"=SUM(E{d1}:E{tot1 - 1})"), (6, f"=SUM(F{d1}:F{tot1 - 1})"),
                      (7, f"=SUM(G{d1}:G{tot1 - 1})")], total=True)
    ws.cell(row=tot1 + 1, column=2, value="Un finding transversal est compté pour chaque serveur concerné.").font = police(False, "595959", 8, True)
    _graphique(ws, "Contrôles par serveur", Reference(ws, min_col=3, min_row=d1, max_row=tot1 - 1),
               [Reference(ws, min_col=5, min_row=d1, max_row=tot1 - 1)], f"H{ligne}")
    ligne = max(tot1 + 4, ligne + 16)

    _bandeau(ws, ligne, 2, 13, "2. ÉTAT INITIAL DES CONTRÔLES (évaluation par l'auditeur)")
    _entete_tableau(ws, ligne + 1, [(2, "État initial", 3), (4, "Contrôles", None), (5, "% du total", None)])
    d2 = ligne + 2
    etats = ETATS + ["Non renseigné (à évaluer)"]
    tot2 = d2 + len(etats)
    for k, e in enumerate(etats):
        r = d2 + k
        f = (f'=SUMPRODUCT(({ctl_b}<>"")*({ctl_i}=$B{r}))' if k < len(ETATS)
             else f"={total_ctl}-SUM(D{d2}:D{r - 1})")
        _ligne(ws, r, [(2, e), (4, f), (5, f'=IF($D${tot2}=0,"",D{r}/$D${tot2})')], pourcent_cols=(5,), fusion_b=True)
    _ligne(ws, tot2, [(2, "Total"), (4, f"=SUM(D{d2}:D{tot2 - 1})"), (5, f'=IF($D${tot2}=0,"",D{tot2}/$D${tot2})')],
           total=True, pourcent_cols=(5,), fusion_b=True)
    _graphique(ws, "État initial des contrôles", Reference(ws, min_col=2, min_row=d2, max_row=tot2 - 1),
               [Reference(ws, min_col=4, min_row=d2, max_row=tot2 - 1)], f"H{ligne}",
               couleurs=["548235", "FFC000", "C00000", "A5A5A5", "D9D9D9"])
    ligne = max(tot2 + 4, ligne + 16)

    _bandeau(ws, ligne, 2, 13, "3. FINDINGS C18 PAR NIVEAU DE CRITICITÉ (registre ANALYSE)")
    _entete_tableau(ws, ligne + 1, [(2, "Niveau de priorité", 3), (4, "Findings", None), (5, "% du total", None)])
    d3 = ligne + 2
    tot3 = d3 + len(CRITICITES) + 1
    for k, crit in enumerate(CRITICITES):
        r = d3 + k
        _ligne(ws, r, [(2, crit), (4, f'=COUNTIF({ana_h},$B{r})'), (5, f'=IF($D${tot3}=0,"",D{r}/$D${tot3})')],
               pourcent_cols=(5,), fusion_b=True)
    r = d3 + len(CRITICITES)
    _ligne(ws, r, [(2, "Criticité non renseignée (à qualifier)"), (4, f'=SUMPRODUCT(({ana_c}<>"")*({ana_h}=""))'),
                   (5, f'=IF($D${tot3}=0,"",D{r}/$D${tot3})')], pourcent_cols=(5,), fusion_b=True)
    _ligne(ws, tot3, [(2, "Total des findings"), (4, f"=SUM(D{d3}:D{tot3 - 1})"), (5, f'=IF($D${tot3}=0,"",D{tot3}/$D${tot3})')],
           total=True, pourcent_cols=(5,), fusion_b=True)
    _graphique(ws, "Findings C18 par criticité", Reference(ws, min_col=2, min_row=d3, max_row=d3 + 3),
               [Reference(ws, min_col=4, min_row=d3, max_row=d3 + 3)], f"H{ligne}",
               couleurs=[COULEUR_CRITICITE[c] for c in CRITICITES])
    ligne = max(tot3 + 4, ligne + 16)

    _bandeau(ws, ligne, 2, 13, "4. COUVERTURE DES PREUVES")
    _entete_tableau(ws, ligne + 1, [(2, "Contrôles", 3), (4, "Nombre", None), (5, "% du total", None)])
    d4 = ligne + 2
    tot4 = d4 + 2
    _ligne(ws, d4, [(2, "Avec preuve"), (4, f"={avec_preuve}"), (5, f'=IF($D${tot4}=0,"",D{d4}/$D${tot4})')], pourcent_cols=(5,), fusion_b=True)
    _ligne(ws, d4 + 1, [(2, "Sans preuve"), (4, f"={total_ctl}-{avec_preuve}"), (5, f'=IF($D${tot4}=0,"",D{d4 + 1}/$D${tot4})')],
           pourcent_cols=(5,), fusion_b=True)
    _ligne(ws, tot4, [(2, "Total"), (4, f"=SUM(D{d4}:D{d4 + 1})"), (5, f'=IF($D${tot4}=0,"",D{tot4}/$D${tot4})')],
           total=True, pourcent_cols=(5,), fusion_b=True)
    _ligne(ws, tot4 + 1, [(2, "dont preuve sans nom de fichier"),
                          (4, f'=SUMPRODUCT(({ctl_b}<>"")*(LEN(TRIM({ctl_m}))>0)*ISERROR(SEARCH(".",{ctl_m})))')], fusion_b=True)
    ws.cell(row=tot4 + 2, column=2, value="Cellules « Preuve » vides : surlignées en rouge ; sans nom de fichier : en jaune. "
                                          "Un contrôle sans preuve n'est jamais considéré comme conforme.").font = police(False, "595959", 8, True)
    _graphique(ws, "Couverture des preuves", Reference(ws, min_col=2, min_row=d4, max_row=d4 + 1),
               [Reference(ws, min_col=4, min_row=d4, max_row=d4 + 1)], f"H{ligne}", couleurs=["548235", "C00000"])
    ligne = max(tot4 + 5, ligne + 16)

    _bandeau(ws, ligne, 2, 13, "5. THÈMES DE SÉCURITÉ COUVERTS (domaines de contrôle)")
    _entete_tableau(ws, ligne + 1, [(2, "Domaine de contrôle", 3), (4, "Contrôles", None), (5, "% du total", None)])
    d5 = ligne + 2
    tot5 = d5 + len(DOMAINES) + 1
    for k in range(len(DOMAINES)):
        r = d5 + k
        _ligne(ws, r, [(2, f"=$AA${4 + k}"), (4, f'=SUMPRODUCT(({ctl_b}<>"")*({ctl_f}=$B{r}))'),
                       (5, f'=IF($D${tot5}=0,"",D{r}/$D${tot5})')], pourcent_cols=(5,), fusion_b=True)
    r = d5 + len(DOMAINES)
    _ligne(ws, r, [(2, "Non renseigné ou hors liste"), (4, f"={total_ctl}-SUM(D{d5}:D{r - 1})"),
                   (5, f'=IF($D${tot5}=0,"",D{r}/$D${tot5})')], pourcent_cols=(5,), fusion_b=True)
    _ligne(ws, tot5, [(2, "Total"), (4, f"=SUM(D{d5}:D{tot5 - 1})"), (5, f'=IF($D${tot5}=0,"",D{tot5}/$D${tot5})')],
           total=True, pourcent_cols=(5,), fusion_b=True)
    _graphique(ws, "Contrôles par domaine de sécurité", Reference(ws, min_col=2, min_row=d5, max_row=d5 + len(DOMAINES) - 1),
               [Reference(ws, min_col=4, min_row=d5, max_row=d5 + len(DOMAINES) - 1)], f"H{ligne}", horizontal=True,
               hauteur=11)
    ligne = max(tot5 + 4, ligne + 24)

    _bandeau(ws, ligne, 2, 13, "10. STATUT DE COLLECTE LSAF (traçabilité automatique)")
    _entete_tableau(ws, ligne + 1, [(2, "Statut de collecte", 3), (4, "Contrôles", None), (5, "% du total", None)])
    d10 = ligne + 2
    tot10 = d10 + len(S.TOUS)
    for k, st in enumerate(S.TOUS):
        r = d10 + k
        _ligne(ws, r, [(2, S.LIBELLES[st]), (4, f'=COUNTIF({ctl_o},$B{r})'), (5, f'=IF($D${tot10}=0,"",D{r}/$D${tot10})')],
               pourcent_cols=(5,), fusion_b=True)
    _ligne(ws, tot10, [(2, "Total"), (4, f"=SUM(D{d10}:D{tot10 - 1})"), (5, f'=IF($D${tot10}=0,"",D{tot10}/$D${tot10})')],
           total=True, pourcent_cols=(5,), fusion_b=True)
    ws.cell(row=tot10 + 1, column=2, value="Statut technique de la collecte (feuille CONTROLES_ET_PREUVES, colonne O) : "
                                           "il ne préjuge pas de la conformité.").font = police(False, "595959", 8, True)
    _graphique(ws, "Statut de collecte LSAF", Reference(ws, min_col=2, min_row=d10, max_row=tot10 - 1),
               [Reference(ws, min_col=4, min_row=d10, max_row=tot10 - 1)], f"H{ligne}",
               couleurs=["548235", "FFC000", "FFC000", "ED7D31", "C00000", "C00000", "A5A5A5"])
    fin_gauche = max(tot10 + 3, ligne + 16)

    # ---- colonne de droite (P..Y) : tableaux 6 à 9
    ligne = 7
    _bandeau(ws, ligne, 16, 25, "6. FINDINGS C18 PAR SERVEUR ET PAR CRITICITÉ")
    _entete_tableau(ws, ligne + 1, [(16, "Serveur", None)] + [(17 + k, c, None) for k, c in enumerate(CRITICITES)] + [(21, "Total", None)])
    for k in range(n):
        r = ligne + 2 + k
        rg = d1 + k
        cells = [(16, f'=IF($B{rg}="","",$C{rg}&"  ("&$B{rg}&")")')]
        for j, crit in enumerate(CRITICITES):
            cells.append((17 + j, f'=IF($B{rg}="","",SUMPRODUCT(ISNUMBER(SEARCH(" "&$B{rg}&" ;"," "&{ana_a}&" ;"))*({ana_h}="{crit}")))'))
        cells.append((21, f'=IF($B{rg}="","",SUM(Q{r}:T{r}))'))
        _ligne(ws, r, cells)
    fin6 = ligne + 2 + n
    ws.cell(row=fin6, column=16, value="Un finding transversal est compté pour chaque serveur concerné.").font = police(False, "595959", 8, True)
    _graphique(ws, "Findings par serveur et criticité", Reference(ws, min_col=16, min_row=ligne + 2, max_row=fin6 - 1),
               [Reference(ws, min_col=17 + j, min_row=ligne + 2, max_row=fin6 - 1) for j in range(4)], f"P{fin6 + 2}",
               empile=True, couleurs_series=[COULEUR_CRITICITE[c] for c in CRITICITES], noms_series=CRITICITES)
    ligne = fin6 + 17

    _bandeau(ws, ligne, 16, 25, "7. FINDINGS PAR NOMBRE DE SERVEURS CONCERNÉS (transversalité)")
    _entete_tableau(ws, ligne + 1, [(16, "Serveurs concernés", None)] + [(17 + k, c, None) for k, c in enumerate(CRITICITES)]
                    + [(21, "Non qualifié", None), (22, "Total", None)])
    d7 = ligne + 2
    for k in range(n):
        r = d7 + k
        cells = [(16, k + 1)]
        for j, crit in enumerate(CRITICITES):
            cells.append((17 + j, f'=COUNTIFS({af},$P{r},{ana_h},"{crit}")'))
        cells.append((21, f'=COUNTIFS({af},$P{r},{ana_h},"")'))
        cells.append((22, f"=SUM(Q{r}:U{r})"))
        _ligne(ws, r, cells)
    fin7 = d7 + n
    _ligne(ws, fin7, [(16, "Total")] + [(17 + j, f"=SUM({L(17 + j)}{d7}:{L(17 + j)}{fin7 - 1})") for j in range(6)], total=True)
    _graphique(ws, "Findings par nombre de serveurs concernés", Reference(ws, min_col=16, min_row=d7, max_row=fin7 - 1),
               [Reference(ws, min_col=17 + j, min_row=d7, max_row=fin7 - 1) for j in range(5)], f"P{fin7 + 2}",
               empile=True, couleurs_series=[COULEUR_CRITICITE[c] for c in CRITICITES] + ["BFBFBF"],
               noms_series=CRITICITES + ["Non qualifié"])
    ligne = fin7 + 17

    _bandeau(ws, ligne, 16, 25, "8. FINDINGS TRANSVERSAUX (communs à au moins 2 serveurs) – ordre du registre (20 premiers)")
    _entete_tableau(ws, ligne + 1, [(16, "Finding (ID et intitulé)", 23), (24, "Criticité", None), (25, "Nb serveurs", None)])
    d8 = ligne + 2
    for k in range(20):
        r = d8 + k
        ws.merge_cells(start_row=r, start_column=16, end_row=r, end_column=23)
        _ligne(ws, r, [(16, f'=IFERROR(INDEX({ana_c},MATCH({k + 1},{ag},0)),"")'),
                       (24, f'=IFERROR(INDEX({ana_h},MATCH({k + 1},{ag},0))&"","")'),
                       (25, f'=IFERROR(INDEX({af},MATCH({k + 1},{ag},0)),"")')])
    couleurs_valeurs(ws, f"X{d8}:X{d8 + 19}", {k: (v, "FFFFFF") for k, v in COULEUR_CRITICITE.items()})
    ligne = d8 + 22

    _bandeau(ws, ligne, 16, 25, "9. RÉPARTITION DES FINDINGS PAR DOMAINE SSI ET CRITICITÉ")
    _entete_tableau(ws, ligne + 1, [(16, "Domaine de contrôle", None)] + [(17 + k, c, None) for k, c in enumerate(CRITICITES)]
                    + [(21, "Total", None)])
    d9 = ligne + 2
    for k in range(len(DOMAINES)):
        r = d9 + k
        cells = [(16, f"=$AA${4 + k}")]
        for j, crit in enumerate(CRITICITES):
            cells.append((17 + j, f'=SUMPRODUCT(({ana_b}=$P{r})*({ana_h}="{crit}"))'))
        cells.append((21, f"=SUM(Q{r}:T{r})"))
        _ligne(ws, r, cells)
    fin9 = d9 + len(DOMAINES)
    _ligne(ws, fin9, [(16, "Total")] + [(17 + j, f"=SUM({L(17 + j)}{d9}:{L(17 + j)}{fin9 - 1})") for j in range(5)], total=True)
    _graphique(ws, "Findings par domaine SSI et criticité", Reference(ws, min_col=16, min_row=d9, max_row=fin9 - 1),
               [Reference(ws, min_col=17 + j, min_row=d9, max_row=fin9 - 1) for j in range(4)], f"P{fin9 + 2}",
               empile=True, horizontal=True, couleurs_series=[COULEUR_CRITICITE[c] for c in CRITICITES],
               noms_series=CRITICITES, hauteur=11)
    fin_droite = fin9 + 24

    # ---- notes et conventions
    ligne = max(fin_gauche, 0) + 1
    _bandeau(ws, ligne, 2, 13, "NOTES ET CONVENTIONS")
    notes = [
        "1. INVENTAIRE_AUDIT : chaque serveur a un ID unique (SRV-LINUX-01, SRV-LINUX-02…), attribué par LSAF dans l'ordre alphabétique des noms.",
        "2. CONTROLES_ET_PREUVES : 1 ligne = 1 contrôle sur 1 serveur — faits, valeur observée, état initial, preuve. Aucune analyse de risque dans cette feuille.",
        "3. ANALYSE : registre des findings C18. LSAF y propose des pistes « À QUALIFIER » ; l'auditeur les qualifie (référence, risque, priorité, "
        "recommandation, action, responsable, échéance), trie Critique → Haute → Moyenne → Faible puis par nombre de serveurs, et supprime les pistes non retenues.",
        "4. Finding = ligne de ANALYSE avec un identifiant F## en colonne C. « Élevés » (INVENTAIRE_AUDIT) = priorité « Haute » (ANALYSE). "
        "Couleurs de criticité : rouge Critique, orange Haute, bleu Moyenne, vert Faible.",
        "5. Colonnes grisées = calculées automatiquement : ne pas saisir. LSAF ne renseigne jamais l'état initial, la criticité ni les références.",
        "6. Statut de collecte LSAF : Réussi = commandes exécutées et preuve exploitable (ce n'est pas une conformité) ; À vérifier, Partiel, "
        "Preuve insuffisante, Collecte impossible, En échec, Non exécuté : voir la feuille LIMITES_COLLECTE.",
    ]
    for k, t in enumerate(notes):
        ws.merge_cells(start_row=ligne + 1 + k, start_column=2, end_row=ligne + 1 + k, end_column=13)
        c = ws.cell(row=ligne + 1 + k, column=2, value=t)
        c.font = police(False, "404040", 9)
        c.alignment = HAUT
        ws.row_dimensions[ligne + 1 + k].height = 26
    ligne = ligne + 2 + len(notes)
    _bandeau(ws, ligne, 2, 13, "CONVENTION DE NOMMAGE DES PREUVES")
    conventions = [
        "Colonne Preuve : nom exact du fichier, sans chemin ; plusieurs fichiers dans la même cellule séparés par « ; ».",
        "Format LSAF : <CONTRÔLE>_<SERVEUR>_<AAAAMMJJ>_<HHMMSS>.txt (sortie brute) et .json (exécution structurée, empreinte SHA-256).",
        "Exemple fictif : C09_SRV-EXEMPLE-01_20261102_101500.txt ; C09_SRV-EXEMPLE-01_20261102_101500.json",
        "Les preuves ne sont pas stockées dans le classeur : seule la référence est saisie. Les preuves restent dans le dossier de session.",
    ]
    for k, t in enumerate(conventions):
        ws.merge_cells(start_row=ligne + 1 + k, start_column=2, end_row=ligne + 1 + k, end_column=13)
        c = ws.cell(row=ligne + 1 + k, column=2, value=t)
        c.font = police(False, "404040", 9)
    r = ligne + 1 + len(conventions)
    ws.cell(row=r, column=2, value="Dossier racine des preuves (à renseigner) :").font = police(True, "404040", 9)
    ws.merge_cells(start_row=r, start_column=5, end_row=r, end_column=13)
    ws.cell(row=r, column=5).border = BORD
    del fin_droite
    return ws


# --------------------------------------------------------------------------- feuilles ajoutées par LSAF

def feuille_c18_croisements(wb, donnees, avertissement):
    ws = wb.create_sheet("C18_CROISEMENTS")
    ws.sheet_properties.tabColor = "44546A"
    titre_feuille(ws, "C18_CROISEMENTS — Résultat de chaque règle de croisement, serveur par serveur",
                  "Une ligne = une règle sur un serveur. « Déclenchée » : la combinaison de faits décrite par la règle est "
                  "observée dans les preuves (piste à qualifier dans ANALYSE). « Non déclenchée » : la combinaison n'est pas "
                  "observée. « Non concluante » : données manquantes — ce n'est pas une absence de problème.", avertissement)
    colonnes = ["Règle", "Intitulé de la règle", "Axe d'analyse", "Contrôles croisés", "ID serveur", "Serveur",
                "Résultat", "Faits observés", "Preuves", "Détail"]
    largeurs = [8, 44, 34, 18, 14, 20, 15, 90, 46, 40]
    entetes(ws, [(1, 4, "RÈGLE", "1F3864", "D9E2F3"), (5, 7, "SERVEUR ET RÉSULTAT", "44546A", "DDE1E7"),
                 (8, 10, "FAITS ET PREUVES", "5B3F8C", "E4DFEC")], colonnes, largeurs)
    regles = {r["id"]: r for r in donnees["c18"]["regles"]}
    evaluations = sorted(donnees["c18"]["evaluations"], key=lambda e: (e["regle"], e["id_serveur"]))
    for i, e in enumerate(evaluations):
        r = PREMIERE + i
        rg = regles.get(e["regle"], {})
        faits = "\n".join((f"• Point de vigilance : {f['texte']}" if f["controle"] == "C18"
                            else f"• [{f['controle']}] {f['texte']}") for f in e["faits"])
        preuves = " ; ".join(sorted({f["preuve"] for f in e["faits"] if f.get("preuve")}))
        valeurs = [e["regle"], rg.get("titre"), rg.get("axe"), ", ".join(rg.get("controles", [])), e["id_serveur"],
                   e["serveur"], e["resultat"], faits or None, preuves or None, e.get("detail") or None]
        for c, v in enumerate(valeurs, 1):
            cellule(ws, r, c, v, centre=c in (1, 5, 7))
        ws.row_dimensions[r].height = _hauteur([(faits, 90), (preuves, 46), (rg.get("titre"), 44)], minimum=30)
    fin = PREMIERE + max(0, len(evaluations) - 1)
    couleurs_valeurs(ws, f"G{PREMIERE}:G{fin}", {"déclenchée": ("FCE4D6", "833C0B"), "non déclenchée": ("E2EFDA", "385723"),
                                                 "non concluante": ("E7E6E6", "595959")})
    ws.freeze_panes = "C6"
    ws.auto_filter.ref = f"A5:J{fin}"


def feuille_c18_transversal(wb, donnees, avertissement):
    ws = wb.create_sheet("C18_TRANSVERSAL")
    ws.sheet_properties.tabColor = "44546A"
    titre_feuille(ws, "C18_TRANSVERSAL — Éléments identiques observés sur plusieurs serveurs (comparaison entre serveurs)",
                  "Comparaison automatique des valeurs factuelles extraites des preuves (CVE, avertissements Lynis, services "
                  "UNSAFE, paramètres…). Un élément commun à plusieurs serveurs n'est pas en soi un constat : il aide à "
                  "identifier les faiblesses systémiques à qualifier.", avertissement)
    colonnes = ["Thème", "Élément observé", "Nb serveurs", "ID serveur(s)", "Serveur(s)"]
    entetes(ws, [(1, 2, "ÉLÉMENT", "1F3864", "D9E2F3"), (3, 5, "SERVEURS CONCERNÉS", "44546A", "DDE1E7")], colonnes,
            [34, 70, 12, 40, 50])
    lignes = sorted(donnees["c18"]["transversal"], key=lambda t: (-t["nb_serveurs"], t["theme"], t["valeur"]))
    for i, t in enumerate(lignes):
        r = PREMIERE + i
        for c, v in enumerate([t["theme"], t["valeur"], t["nb_serveurs"], " ; ".join(t["ids_serveurs"]), " ; ".join(t["serveurs"])], 1):
            cellule(ws, r, c, v, centre=c == 3)
    ws.freeze_panes = "B6"
    ws.auto_filter.ref = f"A5:E{PREMIERE + max(0, len(lignes) - 1)}"


def feuille_limites(wb, donnees, avertissement):
    ws = wb.create_sheet("LIMITES_COLLECTE")
    ws.sheet_properties.tabColor = "7F7F7F"
    titre_feuille(ws, "LIMITES_COLLECTE — Anomalies, contrôles non réalisés et limites d'interprétation",
                  "À reprendre dans la section « Hors périmètre et limites » du rapport. Une absence de preuve n'est jamais "
                  "une conformité.", avertissement)
    colonnes = ["Serveur", "Contrôle", "Type", "Description"]
    entetes(ws, [(1, 4, "LIMITES ET ANOMALIES", "7F7F7F", "EDEDED")], colonnes, [22, 11, 22, 120])
    lignes = []
    for s in donnees["serveurs"]:
        for a in s.get("anomalies", []):
            lignes.append((s["libelle"], a.get("controle") or "—", f"Anomalie ({a['niveau']})", f"[{a['code']}] {a['message']}"))
    for c in donnees["controles"]:
        if c["statut"] not in (S.REUSSI,):
            lignes.append((c["serveur"], c["controle"], f"Statut : {S.LIBELLES.get(c['statut'], c['statut'])}",
                           "\n".join(c.get("a_verifier") or []) or S.DEFINITIONS.get(c["statut"], "")))
    vus = set()
    for lim in donnees.get("limites", []):
        if lim["texte"].startswith("DONNEES SYNTHETIQUES"):
            continue
        cle = (lim["serveur"], lim["controle"], lim["texte"])
        if cle in vus:
            continue
        vus.add(cle)
        lignes.append((lim["serveur"], lim["controle"] or "—", "Limite d'interprétation", lim["texte"]))
    for i, l in enumerate(lignes):
        r = PREMIERE + i
        for c, v in enumerate(l, 1):
            cellule(ws, r, c, v, centre=c == 2)
        ws.row_dimensions[r].height = _hauteur([(l[3], 120)], minimum=18)
    ws.freeze_panes = "A6"
    ws.auto_filter.ref = f"A5:D{PREMIERE + max(0, len(lignes) - 1)}"


# --------------------------------------------------------------------------- point d'entrée

def generer_classeur(donnees: dict, chemin: Path) -> Path:
    """Écrit le classeur à partir des données consolidées (lsaf.consolidation.consolider)."""
    avertissement = None
    if donnees.get("synthetique"):
        avertissement = ("DONNÉES SYNTHÉTIQUES — serveurs fictifs générés par « lsaf demo » : aucun résultat d'audit réel.")
    nb_srv = len(donnees["serveurs"])
    nb_ctl = len(donnees["controles"])
    nb_ana = len(donnees["c18"]["pistes"])
    fin_inv = max(204, PREMIERE + nb_srv + 50)
    fin_ctl = max(982, PREMIERE + nb_ctl + 200)
    fin_ana = max(982, PREMIERE + nb_ana + 200)
    wb = Workbook()
    feuille_inventaire(wb, donnees, fin_inv, fin_ana, avertissement)
    feuille_controles(wb, donnees, fin_inv, fin_ctl, avertissement)
    feuille_analyse(wb, donnees, fin_ana, avertissement)
    feuille_dashboard(wb, donnees, fin_inv, fin_ctl, fin_ana, avertissement)
    feuille_c18_croisements(wb, donnees, avertissement)
    feuille_c18_transversal(wb, donnees, avertissement)
    feuille_limites(wb, donnees, avertissement)
    wb.properties.creator = "LSAF"
    wb.properties.title = "Registre d'audit de sécurité Linux"
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    wb.save(chemin)
    return chemin
