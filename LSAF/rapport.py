"""Génération du rapport d'audit Word (python-docx).

Le rapport est construit à partir du classeur qualifié et, pour les informations
Lynis, du fichier consolidé. Les indicateurs sont recalculés depuis le classeur ;
une valeur absente du classeur est indiquée « N.R. » (non renseigné). Le rapport
définitif est refusé tant que des pistes restent « À QUALIFIER » (sauf --brouillon).
"""

from __future__ import annotations

import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

from .config import CONFIDENTIALITES
from .controles import CONTROLES, CRITICITES, PAR_ID, cle_tri
from .lecture_classeur import Classeur, trier_findings

BLEU = RGBColor(0x1F, 0x38, 0x64)
BLEU2 = RGBColor(0x2E, 0x75, 0xB6)
ROUGE = RGBColor(0xC0, 0x00, 0x00)
GRIS = RGBColor(0x59, 0x59, 0x59)
BLANC = RGBColor(0xFF, 0xFF, 0xFF)
COULEUR = {"Critique": "C00000", "Haute": "ED7D31", "Moyenne": "2E75B6", "Faible": "548235"}
ROMAINS = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"]
NR = "N.R."
LARGEUR_UTILE = 17.0

ECHELLE_PAR_DEFAUT = {
    "Critique": ("Faiblesse démontrée par les preuves, permettant une atteinte grave et directe à la confidentialité, "
                 "l'intégrité ou la disponibilité, sans prérequis significatif.", "Traitement immédiat"),
    "Haute": ("Faiblesse ou exposition significative, exploitable dans des conditions réalistes ou touchant un serveur "
              "critique.", "Traitement prioritaire"),
    "Moyenne": ("Écart aux bonnes pratiques réduisant la capacité de protection, de détection ou de réaction, sans "
                "exploitation directe démontrée.", "Traitement planifié"),
    "Faible": ("Écart mineur ou de bonne hygiène, à impact limité.", "Amélioration continue"),
}

DEMARCHE = [
    ("1. Observation", "Collecte de la configuration réelle de chaque serveur par des commandes en lecture seule (collecteur LSAF)."),
    ("2. Preuve", "Conservation de chaque sortie dans un fichier horodaté, nommé selon la convention et protégé par une empreinte SHA-256."),
    ("3. Analyse", "Extraction des valeurs factuelles et vérification de leur cohérence entre contrôles (croisements C18)."),
    ("4. Référence", "Confrontation de l'écart à un référentiel reconnu ou à la documentation officielle de la technologie."),
    ("5. Constat", "Formulation factuelle de l'écart, avec les serveurs concernés et les fichiers de preuve."),
    ("6. Risque", "Qualification du risque et du niveau de priorité par l'auditeur, selon le contexte et l'exposition du serveur."),
    ("7. Recommandation", "Mesure attendue pour supprimer ou réduire le risque."),
    ("8. Remédiation", "Action concrète, responsable et échéance, suivies dans le registre."),
    ("9. Vérification", "Nouvelle collecte après remédiation et comparaison avec l'état initial."),
]

INTERPRETATION = [
    "Lynis : l'indice de durcissement est un indicateur global, à lire comme une tendance et non comme un pourcentage de "
    "sécurité ; un avertissement ou une suggestion est vérifié dans la configuration réelle avant d'être retenu.",
    "systemd-analyze security : un score élevé (« UNSAFE ») indique un faible confinement du service, pas une vulnérabilité ; "
    "il est qualifié selon le rôle, les privilèges et l'exposition réseau du service.",
    "Debsecan : outil conçu pour Debian, qui compare les paquets installés aux données de sécurité Debian ; sur une autre "
    "distribution, ses résultats sont des pistes à confirmer avec les sources de la distribution.",
    "Absence d'un mécanisme : l'absence d'un outil (audit, intégrité, antimalware) est rapportée comme telle, sans présumer "
    "des mesures compensatoires qui n'ont pas été observées.",
    "Absence de preuve : un contrôle non exécuté ou sans preuve exploitable n'est jamais considéré comme conforme.",
]

GLOSSAIRE = [
    ("C18", "Analyse croisée des résultats des contrôles C01 à C17, par serveur puis entre serveurs."),
    ("Constat (finding)", "Écart qualifié, appuyé sur des preuves, identifié F01, F02…"),
    ("Constat transversal", "Constat observé sur au moins deux serveurs."),
    ("Indice de durcissement", "Indicateur global calculé par Lynis à partir des tests réalisés."),
    ("N.R.", "Non renseigné dans le registre d'audit."),
    ("Preuve", "Fichier de sortie brute d'une commande, nommé <CONTRÔLE>_<SERVEUR>_<DATE>_<HEURE>.txt."),
    ("SHA-256", "Empreinte cryptographique permettant de vérifier qu'une preuve n'a pas été modifiée."),
    ("UNSAFE", "Niveau d'exposition élevé attribué par systemd-analyze security à un service peu confiné."),
]


# --------------------------------------------------------------------------- utilitaires XML

def _ombrer(cellule, couleur):
    tc_pr = cellule._tc.get_or_add_tcPr()
    for ancien in tc_pr.findall(qn("w:shd")):
        tc_pr.remove(ancien)
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), couleur)
    tc_pr.append(shd)


def _ligne_insecable(ligne):
    ligne._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))


def _repeter_entete(ligne):
    ligne._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))


def _champ(paragraphe, instruction, taille=8):
    run = paragraphe.add_run()
    run.font.size = Pt(taille)
    debut = OxmlElement("w:fldChar")
    debut.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = instruction
    sep = OxmlElement("w:fldChar")
    sep.set(qn("w:fldCharType"), "separate")
    texte = OxmlElement("w:t")
    texte.text = "1" if "PAGE" in instruction else "Clic droit sur ce texte puis « Mettre à jour les champs » pour afficher le sommaire."
    fin = OxmlElement("w:fldChar")
    fin.set(qn("w:fldCharType"), "end")
    for el in (debut, instr, sep, texte, fin):
        run._r.append(el)
    return run


def _bordure_basse(paragraphe, couleur="1F3864", taille=8):
    p_pr = paragraphe._p.get_or_add_pPr()
    bdr = OxmlElement("w:pBdr")
    bas = OxmlElement("w:bottom")
    bas.set(qn("w:val"), "single")
    bas.set(qn("w:sz"), str(taille))
    bas.set(qn("w:space"), "1")
    bas.set(qn("w:color"), couleur)
    bdr.append(bas)
    p_pr.append(bdr)


def _largeurs(tableau, largeurs_cm):
    total = sum(largeurs_cm)
    if total > LARGEUR_UTILE:
        largeurs_cm = [w * LARGEUR_UTILE / total for w in largeurs_cm]
    tableau.autofit = False
    grille = tableau._tbl.tblGrid
    for gc, w in zip(grille.findall(qn("w:gridCol")), largeurs_cm):
        gc.set(qn("w:w"), str(int(Cm(w).twips)))
    for ligne in tableau.rows:
        for cel, w in zip(ligne.cells, largeurs_cm):
            cel.width = Cm(w)
    disposition = OxmlElement("w:tblLayout")
    disposition.set(qn("w:type"), "fixed")
    tableau._tbl.tblPr.append(disposition)


def _texte_cellule(cel, texte, gras=False, couleur=None, taille=8.5, alignement=None):
    cel.text = ""
    p = cel.paragraphs[0]
    for n, ligne in enumerate(str(texte if texte not in (None, "") else "").split("\n")):
        if n:
            p = cel.add_paragraph()
        r = p.add_run(ligne)
        r.bold = gras
        r.font.size = Pt(taille)
        if couleur is not None:
            r.font.color.rgb = couleur
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.space_before = Pt(0)
        if alignement is not None:
            p.alignment = alignement


def _nr(v: str) -> str:
    return v.strip() if v and v.strip() else NR


# --------------------------------------------------------------------------- graphiques (matplotlib)

def _figure_barres(chemin, categories, series, titre, empile=False, horizontal=False, couleurs=None, noms=None):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    hauteur = max(2.6, 0.32 * len(categories) + 1.2) if horizontal else 2.8
    fig, ax = plt.subplots(figsize=(6.3, hauteur), dpi=200)
    base = [0] * len(categories)
    positions = list(range(len(categories)))
    for i, valeurs in enumerate(series):
        couleur = (couleurs[i] if couleurs and len(series) > 1 else None)
        if len(series) == 1 and couleurs:
            couleur = couleurs
        if horizontal:
            barres = ax.barh(positions, valeurs, left=base if empile else None, color=couleur,
                             label=noms[i] if noms else None, height=0.6)
        else:
            barres = ax.bar(positions, valeurs, bottom=base if empile else None, color=couleur,
                            label=noms[i] if noms else None, width=0.6)
        if not empile:
            for b, v in zip(barres, valeurs):
                if v:
                    if horizontal:
                        ax.text(b.get_width() + 0.05, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=7)
                    else:
                        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.05, str(v), ha="center", va="bottom", fontsize=7)
        if empile:
            base = [a + b for a, b in zip(base, valeurs)]
    if empile:
        for p, total in zip(positions, base):
            if total:
                if horizontal:
                    ax.text(total + 0.05, p, str(total), va="center", fontsize=7)
                else:
                    ax.text(p, total + 0.05, str(total), ha="center", va="bottom", fontsize=7)
    if horizontal:
        ax.set_yticks(positions, categories, fontsize=7)
        ax.invert_yaxis()
    else:
        ax.set_xticks(positions, categories, fontsize=7)
    ax.tick_params(axis="both", labelsize=7)
    ax.set_title(titre, fontsize=9, color="#1F3864", fontweight="bold")
    for cote in ("top", "right"):
        ax.spines[cote].set_visible(False)
    from matplotlib.ticker import MaxNLocator
    (ax.xaxis if horizontal else ax.yaxis).set_major_locator(MaxNLocator(integer=True))
    if noms and len(series) > 1:
        ax.legend(fontsize=7, frameon=False, ncol=len(series), loc="upper center", bbox_to_anchor=(0.5, -0.12 if not horizontal else -0.08))
    fig.tight_layout()
    fig.savefig(chemin)
    plt.close(fig)
    return chemin


# --------------------------------------------------------------------------- rapport

class Rapport:
    def __init__(self, classeur: Classeur, consolide: Optional[dict], config: dict, brouillon: bool,
                 modele: Optional[Path] = None):
        self.c = classeur
        self.cons = consolide or {}
        self.cfg = config or {}
        self.brouillon = brouillon
        self.ind = classeur.indicateurs()
        self.findings = trier_findings(classeur.findings)
        self.temp = Path(tempfile.mkdtemp(prefix="lsaf-rapport-"))
        self.n_fig = 0
        self.n_h1 = 0
        self.n_h2 = 0
        if modele:
            self.doc = Document(str(modele))
            corps = self.doc.element.body
            for el in list(corps):
                if el.tag != qn("w:sectPr"):
                    corps.remove(el)
            self.avec_modele = True
        else:
            self.doc = Document()
            self.avec_modele = False
            self._styles()
        self.synthetique = bool(self.cons.get("synthetique")) or any(
            "SYNTH" in (s.commentaire or "").upper() for s in classeur.serveurs)

    # ------------------------------------------------------------------ styles et blocs
    def _styles(self):
        st = self.doc.styles
        normal = st["Normal"]
        normal.font.name = "Arial"
        normal.font.size = Pt(10)
        normal.element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), "Arial")
        normal.paragraph_format.space_after = Pt(4)
        normal.paragraph_format.line_spacing = 1.15
        for nom, taille, couleur in (("Heading 1", 15, BLEU), ("Heading 2", 12, BLEU2), ("Heading 3", 10.5, BLEU)):
            s = st[nom]
            s.font.name = "Arial"
            s.font.size = Pt(taille)
            s.font.bold = True
            s.font.color.rgb = couleur
            rf = s.element.get_or_add_rPr().get_or_add_rFonts()
            for a in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
                rf.set(qn(a), "Arial")
            s.paragraph_format.keep_with_next = True
        sec = self.doc.sections[0]
        sec.orientation = WD_ORIENT.PORTRAIT
        sec.page_height, sec.page_width = Cm(29.7), Cm(21.0)
        sec.left_margin = sec.right_margin = sec.top_margin = Cm(2.0)
        sec.bottom_margin = Cm(3.35)

    def p(self, texte="", gras=False, italique=False, couleur=None, taille=None, alignement=None, style=None):
        para = self.doc.add_paragraph(style=style) if style else self.doc.add_paragraph()
        if texte:
            r = para.add_run(texte)
            r.bold, r.italic = gras, italique
            if couleur is not None:
                r.font.color.rgb = couleur
            if taille:
                r.font.size = Pt(taille)
        para.alignment = alignement if alignement is not None else WD_ALIGN_PARAGRAPH.JUSTIFY
        return para

    def puce(self, texte, gras_debut: Optional[str] = None):
        try:
            para = self.doc.add_paragraph(style="List Bullet")
        except KeyError:
            para = self.doc.add_paragraph()
            para.add_run("▪ ")
        if gras_debut:
            para.add_run(gras_debut).bold = True
        para.add_run(texte)
        para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        return para

    def saut_page(self):
        self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    def h1(self, texte):
        if self.n_h1:
            self.saut_page()
        h = self.doc.add_heading(f"{ROMAINS[self.n_h1]}. {texte}", level=1)
        _bordure_basse(h)
        self.n_h1 += 1
        self.n_h2 = 0
        return h

    def h2(self, texte, numeroter=True):
        self.n_h2 += 1
        return self.doc.add_heading(f"{self.n_h1}.{self.n_h2} {texte}" if numeroter else texte, level=2)

    def h3(self, texte):
        return self.doc.add_heading(texte, level=3)

    def tableau(self, entetes, lignes, largeurs=None, couleur_entete="1F3864", remplissages=None, taille=8.5, zebre=True):
        t = self.doc.add_table(rows=1, cols=len(entetes))
        try:
            t.style = "Table Grid"
        except KeyError:
            pass
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        e = t.rows[0]
        _repeter_entete(e)
        for i, h in enumerate(entetes):
            _texte_cellule(e.cells[i], h, gras=True, couleur=BLANC, taille=taille)
            _ombrer(e.cells[i], couleur_entete)
        for ri, valeurs in enumerate(lignes):
            ligne = t.add_row()
            _ligne_insecable(ligne)
            for i, v in enumerate(valeurs):
                fond = (remplissages or {}).get((ri, i))
                if fond in COULEUR.values():
                    _texte_cellule(ligne.cells[i], v, gras=True, couleur=BLANC, taille=taille)
                else:
                    _texte_cellule(ligne.cells[i], v, taille=taille)
                if fond:
                    _ombrer(ligne.cells[i], fond)
                elif zebre and ri % 2 == 1:
                    _ombrer(ligne.cells[i], "F2F5FA")
        if largeurs:
            _largeurs(t, largeurs)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return t

    def encadre(self, titre, texte, couleur="1F3864", fond="EEF2F8"):
        t = self.doc.add_table(rows=1, cols=1)
        c = t.rows[0].cells[0]
        c.text = ""
        r = c.paragraphs[0].add_run(titre)
        r.bold = True
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor.from_string(couleur)
        for ligne in str(texte).split("\n"):
            para = c.add_paragraph()
            run = para.add_run(ligne)
            run.font.size = Pt(9)
            para.paragraph_format.space_after = Pt(1)
            para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        _ombrer(c, fond)
        tc_pr = c._tc.get_or_add_tcPr()
        bords = OxmlElement("w:tcBorders")
        for cote in ("top", "left", "bottom", "right"):
            b = OxmlElement(f"w:{cote}")
            b.set(qn("w:val"), "single")
            b.set(qn("w:sz"), "36" if cote == "left" else "4")
            b.set(qn("w:color"), couleur if cote == "left" else fond)
            bords.append(b)
        tc_pr.append(bords)
        _largeurs(t, [LARGEUR_UTILE])
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    def figure(self, chemin, legende):
        self.n_fig += 1
        self.doc.add_picture(str(chemin), width=Cm(15.5))
        self.doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        self.p(f"Figure {self.n_fig} – {legende}", italique=True, couleur=GRIS, taille=8.5, alignement=WD_ALIGN_PARAGRAPH.CENTER)

    def nouvelle_figure(self, nom):
        return self.temp / f"{nom}.png"

    # ------------------------------------------------------------------ données utiles
    def texte(self, cle):
        return ((self.cfg.get("textes") or {}).get(cle) or "").strip()

    def noms_serveurs(self, ids):
        return ", ".join(self.c.nom(i) for i in ids)

    def libelle_crit(self, f):
        return f.priorite if f.priorite in CRITICITES else "À qualifier"

    def dates_audit(self):
        dates = sorted({s.date_audit[:10] for s in self.c.serveurs if s.date_audit})
        if not dates:
            return NR
        return dates[0] if len(dates) == 1 else f"du {dates[0]} au {dates[-1]}"

    def serveur_cons(self, id_srv):
        return next((s for s in self.cons.get("serveurs", []) if s.get("id") == id_srv), {})

    @staticmethod
    def controles_cites(texte):
        trouves = set(re.findall(r"\bC\d{2}(?:-\d{2})?\b", texte or "")) - {"C18"}
        return sorted(trouves, key=cle_tri)

    # ------------------------------------------------------------------ en-tête / pied de page
    def entete_pied(self):
        sec = self.doc.sections[0]
        if self.avec_modele:
            return
        hp = sec.header.paragraphs[0]
        hp.text = ""
        if self.cfg.get("logo"):
            hp.add_run().add_picture(self.cfg["logo"], height=Cm(0.9))
            hp.add_run("    ")
        r = hp.add_run(self.cfg.get("intitule") or "Rapport d'audit de sécurité – Serveurs Linux")
        r.font.size = Pt(8)
        r.font.color.rgb = GRIS
        if self.brouillon:
            r2 = hp.add_run("    VERSION DE TRAVAIL – NON VALIDÉE")
            r2.bold = True
            r2.font.size = Pt(8)
            r2.font.color.rgb = ROUGE
        _bordure_basse(hp, "1F3864", 6)
        pied = sec.footer
        choix = self.cfg.get("confidentialite") or "Interne"
        t = pied.add_table(rows=2, cols=4, width=Cm(12))
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        try:
            t.style = "Table Grid"
        except KeyError:
            pass
        ligne_titre = t.rows[0]
        fusion = ligne_titre.cells[0].merge(ligne_titre.cells[3])
        _texte_cellule(fusion, "Critère de diffusion", gras=True, couleur=BLANC, taille=7.5, alignement=WD_ALIGN_PARAGRAPH.CENTER)
        _ombrer(fusion, "002060")
        for i, niveau in enumerate(CONFIDENTIALITES):
            cel = t.rows[1].cells[i]
            actif = niveau == choix
            _texte_cellule(cel, niveau, gras=actif, couleur=BLANC if actif else GRIS, taille=7.5, alignement=WD_ALIGN_PARAGRAPH.CENTER)
            if actif:
                _ombrer(cel, "C00000")
        _largeurs(t, [3.0, 3.0, 3.0, 3.0])
        fp = pied.paragraphs[0] if pied.paragraphs and not pied.paragraphs[0].text else pied.add_paragraph()
        fp = pied.add_paragraph()
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = fp.add_run("Page ")
        r.font.size = Pt(8)
        _champ(fp, "PAGE")
        r = fp.add_run(" / ")
        r.font.size = Pt(8)
        _champ(fp, "NUMPAGES")
        if self.cfg.get("image_pied_de_page"):
            ip = pied.add_paragraph()
            ip.alignment = WD_ALIGN_PARAGRAPH.CENTER
            ip.add_run().add_picture(self.cfg["image_pied_de_page"], width=Cm(17))

    # ------------------------------------------------------------------ couverture et gestion du document
    def couverture(self):
        if self.cfg.get("logo"):
            self.doc.add_picture(self.cfg["logo"], height=Cm(2.5))
            self.doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        for _ in range(3):
            self.doc.add_paragraph()
        self.p("RAPPORT D'AUDIT DE SÉCURITÉ", gras=True, couleur=BLEU, taille=24, alignement=WD_ALIGN_PARAGRAPH.CENTER)
        self.p("Serveurs Linux – Configuration, durcissement et exposition", couleur=BLEU2, taille=14, alignement=WD_ALIGN_PARAGRAPH.CENTER)
        self.p("Contrôles C01 à C17 et analyse croisée C18", couleur=GRIS, taille=11, alignement=WD_ALIGN_PARAGRAPH.CENTER)
        if self.brouillon:
            self.p("VERSION DE TRAVAIL – pistes non qualifiées, ne pas diffuser", gras=True, couleur=ROUGE, taille=11,
                   alignement=WD_ALIGN_PARAGRAPH.CENTER)
        if self.synthetique:
            self.p("DONNÉES SYNTHÉTIQUES – serveurs fictifs, aucun résultat d'audit réel", gras=True, couleur=ROUGE, taille=10,
                   alignement=WD_ALIGN_PARAGRAPH.CENTER)
        self.doc.add_paragraph()
        n = len(self.c.serveurs)
        lignes = [
            ("Entité auditée", _nr(self.cfg.get("organisation", ""))),
            ("Intitulé de l'audit", self.cfg.get("intitule") or "Audit de sécurité technique des serveurs Linux"),
            ("Périmètre", f"{n} serveur{'s' if n > 1 else ''} Linux : {', '.join(s.nom for s in self.c.serveurs)}"),
            ("Date de l'audit", self.dates_audit()),
            ("Version du document", str(self.cfg.get("version") or ("0.1 (travail)" if self.brouillon else "1.0"))),
            ("Auteur", _nr(self.cfg.get("auteur", ""))),
            ("Niveau de confidentialité", self.cfg.get("confidentialite") or "Interne"),
        ]
        t = self.doc.add_table(rows=0, cols=2)
        try:
            t.style = "Table Grid"
        except KeyError:
            pass
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        for libelle, valeur in lignes:
            ligne = t.add_row()
            _texte_cellule(ligne.cells[0], libelle, gras=True, taille=9.5)
            _ombrer(ligne.cells[0], "D9E2F3")
            _texte_cellule(ligne.cells[1], valeur, taille=9.5)
        _largeurs(t, [5.0, 11.0])
        self.saut_page()

    def gestion_document(self):
        self.p("Gestion du document", gras=True, couleur=BLEU, taille=15, alignement=WD_ALIGN_PARAGRAPH.LEFT)
        self.p("Historique des versions", gras=True, couleur=BLEU2, taille=12, alignement=WD_ALIGN_PARAGRAPH.LEFT)
        historique = self.cfg.get("historique") or [{
            "version": self.cfg.get("version") or ("0.1" if self.brouillon else "1.0"),
            "date": datetime.now().strftime("%d/%m/%Y"),
            "auteur": self.cfg.get("auteur") or NR,
            "modification": "Version de travail générée par LSAF" if self.brouillon else "Création du rapport",
        }]
        self.tableau(["Version", "Date", "Auteur", "Nature de la modification"],
                     [[str(h.get("version", "")), str(h.get("date", "")), str(h.get("auteur", "")), str(h.get("modification", ""))]
                      for h in historique], [2.5, 3, 4.5, 7])
        self.p("Documents associés", gras=True, couleur=BLEU2, taille=12, alignement=WD_ALIGN_PARAGRAPH.LEFT)
        self.tableau(["Document", "Rôle"], [
            [self.c.chemin.name, "Registre d'audit : inventaire, contrôles et preuves, analyse (findings) et tableau de bord. "
                                 "Source de toutes les données du présent rapport."],
            ["Preuves techniques (fichiers TXT et JSON)", "Sorties brutes des commandes collectées sur chaque serveur, horodatées "
                                                          "et protégées par une empreinte SHA-256 (dossiers de session LSAF)."],
        ], [6, 11])
        self.encadre("Confidentialité",
                     "Ce document décrit des faiblesses de configuration de systèmes d'information. Il est destiné aux seules "
                     "personnes chargées de leur traitement et ne doit pas être diffusé au-delà du niveau de confidentialité "
                     "indiqué en pied de page.", couleur="C00000", fond="FBEAEA")
        self.saut_page()
        self.p("Sommaire", gras=True, couleur=BLEU, taille=15, alignement=WD_ALIGN_PARAGRAPH.LEFT)
        _champ(self.doc.add_paragraph(), 'TOC \\o "1-2" \\h \\z \\u', taille=10)

    # ------------------------------------------------------------------ I. Introduction
    def introduction(self):
        self.h1("Introduction")
        self.h2("Contexte")
        self.p(self.texte("contexte") or
               ("Le présent rapport restitue les résultats d'un audit de sécurité technique de serveurs Linux. L'audit a porté "
                "sur la configuration réelle des systèmes, observée à partir de commandes natives exécutées en lecture seule, "
                "de l'outil d'audit Lynis et de l'outil Debsecan, selon une méthodologie de dix-huit contrôles (C01 à C18)."))
        self.h2("Objectifs de l'audit")
        for t in ("Évaluer le niveau de sécurité de la configuration de chaque serveur (système, réseau, comptes, services, "
                  "journalisation, durcissement).",
                  "Identifier les écarts par rapport aux bonnes pratiques et aux référentiels reconnus.",
                  "Qualifier ces écarts en risques, avec un niveau de priorité justifié par les preuves et le contexte.",
                  "Identifier les faiblesses communes à plusieurs serveurs afin de traiter les causes à la racine.",
                  "Proposer un plan de remédiation priorisé et vérifiable."):
            self.puce(t)
        self.h2("Finalité de la démarche")
        self.p("Le rapport est un document d'aide à la décision : il permet d'arbitrer les priorités de traitement à partir de "
               "constats démontrés par des preuves, et fournit aux équipes techniques les éléments nécessaires à la remédiation "
               "et à sa vérification.")
        if self.texte("politique_interne"):
            self.encadre("Positionnement de la politique interne", self.texte("politique_interne"))

    # ------------------------------------------------------------------ II. Périmètre
    def perimetre(self):
        self.h1("Périmètre de l'audit")
        self.h2("Serveurs audités")
        n = len(self.c.serveurs)
        self.p(f"Le périmètre comprend {n} serveur{'s' if n > 1 else ''} Linux, déclaré{'s' if n > 1 else ''} dans la feuille "
               "INVENTAIRE_AUDIT du registre d'audit.")
        lignes, remp = [], {}
        for i, s in enumerate(self.c.serveurs):
            lignes.append([s.id, s.nom, _nr(s.ip), _nr(s.version_os or s.os), _nr(s.environnement), _nr(s.criticite), _nr(s.role)])
            if s.criticite in COULEUR:
                remp[(i, 5)] = COULEUR[s.criticite]
        self.tableau(["ID", "Serveur", "Adresse IP", "Système", "Env.", "Criticité", "Rôle / fonction"], lignes,
                     [2.3, 2.7, 2.4, 3.3, 1.9, 1.7, 3.0], remplissages=remp)
        self.h2("Périmètre technique couvert")
        self.p("Pour chaque serveur, les domaines suivants ont été examinés :")
        for t in ("Système et ressources : identification de l'OS et du noyau, virtualisation, ressources (C01, C02).",
                  "Gestion des versions : paquets, noyau actif, redémarrage requis, sources APT, logiciels installés (C03, C04).",
                  "Réseau et exposition : interfaces, routage, DNS, services actifs, ports en écoute, pare-feu local (C05 à C08).",
                  "Accès et identités : configuration SSH effective, comptes, groupes privilégiés, fichiers sensibles (C09 à C11).",
                  "Exploitation et détection : journalisation, synchronisation horaire, tâches planifiées, agents de sécurité (C12 à C15).",
                  "Vulnérabilités et durcissement : Debsecan, audit Lynis et ses sept sous-contrôles (C16, C17, C17-01 à C17-07).",
                  "Analyse croisée : croisement des contrôles et consolidation transversale des constats (C18)."):
            self.puce(t)
        self.h2("Hors périmètre et limites")
        self.p("Les éléments suivants n'ont pas été couverts ou ne l'ont été que partiellement :")
        limites = list(self.cfg.get("hors_perimetre") or [])
        limites.append("Aucun test d'intrusion ni test applicatif n'a été réalisé : l'exploitabilité effective des écarts "
                       "n'a pas été démontrée par l'attaque.")
        limites.append("Les contrôles reflètent l'état des serveurs à la date de collecte.")
        non_realises = {}
        for ctl in self.c.controles:
            if ctl.statut_lsaf and ctl.statut_lsaf not in ("Réussi",):
                non_realises.setdefault(ctl.statut_lsaf, []).append(f"{ctl.controle_lsaf} ({self.c.nom(ctl.id_serveur)})")
        for statut, liste in sorted(non_realises.items()):
            liste = sorted(set(liste))
            limites.append(f"Contrôles au statut de collecte « {statut} » : {', '.join(liste)}. Le détail figure dans la "
                           "feuille LIMITES_COLLECTE du registre.")
        sans_preuve = sum(1 for c in self.c.controles if not c.preuve.strip())
        if sans_preuve:
            limites.append(f"{sans_preuve} ligne(s) de contrôle sans preuve : ces contrôles ne sont pas considérés comme conformes.")
        for t in limites:
            self.puce(t)

    # ------------------------------------------------------------------ III. Méthodologie
    def methodologie(self):
        self.h1("Méthodologie")
        self.h2("Démarche d'audit")
        self.p("L'audit suit une chaîne de traitement unique, appliquée à chaque élément examiné, qui garantit la traçabilité "
               "entre la preuve, le constat et la recommandation.")
        self.tableau(["Étape", "Contenu"], [list(x) for x in DEMARCHE], [3.5, 13.5])
        self.h2("Les contrôles C01 à C18")
        principaux = [c for c in CONTROLES if not c.id.startswith("C17-")]
        self.tableau(["Réf.", "Contrôle", "Éléments examinés"], [[c.id, c.intitule, c.objet] for c in principaux], [1.5, 5, 10.5])
        self.h2("Détail du contrôle C17 (Lynis)")
        self.p("Le C17 exploite l'audit Lynis comme source d'information technique. Chaque résultat significatif est vérifié "
               "par une commande native dans le sous-contrôle correspondant avant d'être retenu.")
        sous = [c for c in CONTROLES if c.id == "C17" or c.id.startswith("C17-")]
        self.tableau(["Réf.", "Sous-contrôle", "Objet"], [[c.id, c.intitule, c.objet] for c in sous], [1.7, 5, 10.3])
        self.h2("Interprétation des résultats d'outils")
        self.p("Un résultat d'outil n'est jamais présenté automatiquement comme une vulnérabilité. Il est vérifié dans la "
               "preuve, corroboré par les autres contrôles et confronté au contexte du serveur.")
        for t in INTERPRETATION:
            nom, _, reste = t.partition(" : ")
            self.puce(" : " + reste, gras_debut=nom)
        self.h2("Échelle de criticité")
        self.p("Le niveau de priorité de chaque constat est attribué par l'auditeur selon l'échelle suivante, en tenant compte "
               "du rôle et de la criticité du serveur, de l'exposition réseau et de l'exploitabilité observée.")
        echelle = self.cfg.get("echelle_criticite") or {}
        lignes, remp = [], {}
        for i, crit in enumerate(CRITICITES):
            d, t = ECHELLE_PAR_DEFAUT[crit]
            perso = echelle.get(crit) or {}
            lignes.append([crit, perso.get("definition") or d, perso.get("traitement") or t])
            remp[(i, 0)] = COULEUR[crit]
        self.tableau(["Niveau", "Définition retenue", "Traitement attendu"], lignes, [2.3, 11, 3.7], remplissages=remp)
        self.h2("Référentiels utilisés")
        refs = self.cfg.get("referentiels")
        if refs:
            self.tableau(["Référentiel", "Version", "Utilisation"],
                         [[r.get("nom", ""), _nr(str(r.get("version", "") or "")), r.get("utilisation", "")] for r in refs],
                         [6, 2.5, 8.5])
        else:
            cites = sorted({f.type_reference for f in self.c.findings if f.type_reference})
            if cites:
                self.p("Types de référence cités dans le registre : " + ", ".join(cites) + ". Les références précises figurent "
                       "dans chaque fiche de constat et en annexe D.")
            else:
                self.p("Aucun référentiel n'est renseigné dans le registre (colonne « Type de référence » de la feuille ANALYSE).")

    # ------------------------------------------------------------------ IV. Synthèse exécutive
    def tuiles(self):
        t = self.doc.add_table(rows=1, cols=5)
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        valeurs = [(str(self.ind["findings"]), "CONSTATS", "1F3864")] + [
            (str(self.ind["par_criticite"][c]), c.upper(), COULEUR[c]) for c in CRITICITES]
        for cel, (v, libelle, fond) in zip(t.rows[0].cells, valeurs):
            cel.text = ""
            p1 = cel.paragraphs[0]
            p1.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p1.add_run(v)
            r.bold = True
            r.font.size = Pt(22)
            r.font.color.rgb = BLANC
            p2 = cel.add_paragraph()
            p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p2.add_run(libelle)
            r.bold = True
            r.font.size = Pt(8)
            r.font.color.rgb = BLANC
            _ombrer(cel, fond)
        _largeurs(t, [3.4] * 5)
        self.doc.add_paragraph()

    def synthese(self):
        self.h1("Synthèse exécutive")
        self.tuiles()
        n = len(self.c.serveurs)
        envs = {}
        for s in self.c.serveurs:
            if s.environnement:
                envs[s.environnement] = envs.get(s.environnement, 0) + 1
        detail_env = f" ({', '.join(f'{v} en {k.lower()}' for k, v in envs.items())})" if envs else ""
        pc = self.ind["par_criticite"]
        phrase = (f"L'audit a porté sur {n} serveur{'s' if n > 1 else ''} Linux{detail_env} et a donné lieu à "
                  f"{self.ind['findings']} constat{'s' if self.ind['findings'] > 1 else ''} : {pc['Critique']} critique(s), "
                  f"{pc['Haute']} de priorité haute, {pc['Moyenne']} de priorité moyenne et {pc['Faible']} de priorité faible. "
                  f"{self.ind['transversaux']} constat(s) concernent au moins deux serveurs.")
        if self.ind["non_qualifies"]:
            phrase += f" {self.ind['non_qualifies']} piste(s) restent à qualifier."
        self.p(phrase)
        if self.texte("appreciation"):
            self.encadre("Appréciation générale", self.texte("appreciation"), couleur="C00000", fond="FBEAEA")
        self.h2("Principaux risques")
        majeurs = [f for f in self.findings if f.priorite in ("Critique", "Haute")]
        if majeurs:
            lignes, remp = [], {}
            for i, f in enumerate(majeurs):
                portee = f"{f.nb_serveurs} serveurs" if f.nb_serveurs > 1 else self.noms_serveurs(f.ids_serveurs)
                lignes.append([f"{f.code} – {f.priorite} ({portee})", f"{f.intitule}\n{_nr(f.risque)}"])
            self.tableau(["Constat", "Risque principal"], lignes, [4.5, 12.5], remplissages=remp)
        else:
            self.p("Aucun constat de priorité critique ou haute n'est enregistré dans le registre.")
        chemin = _figure_barres(self.nouvelle_figure("criticite"), CRITICITES, [[pc[c] for c in CRITICITES]],
                                "Constats par niveau de priorité", couleurs=[f"#{COULEUR[c]}" for c in CRITICITES])
        self._figure_couleurs_simples(chemin, pc)
        self.figure(chemin, f"Répartition des {self.ind['findings']} constats par criticité")
        self.h2("Priorités de remédiation")
        etiquettes = {"Critique": "Immédiat : ", "Haute": "Prioritaire : ", "Moyenne": "Planifié : ", "Faible": "Amélioration continue : "}
        for crit in CRITICITES:
            groupe = [f for f in self.findings if f.priorite == crit]
            if groupe:
                self.puce("; ".join(f"{f.intitule} ({f.code})" for f in groupe) + ".", gras_debut=etiquettes[crit])
        manquants = sum(1 for f in self.findings if not f.responsable or not f.echeance)
        if manquants:
            self.p(f"Responsable ou échéance non renseignés dans le registre pour {manquants} constat(s) : à définir lors de la "
                   "validation du plan de remédiation (mention « N.R. » dans le plan).", italique=True, couleur=GRIS, taille=9)

    def _figure_couleurs_simples(self, chemin, pc):
        """Redessine la figure 1 avec une couleur par barre (matplotlib n'accepte qu'une couleur par série)."""
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import MaxNLocator
        fig, ax = plt.subplots(figsize=(6.3, 2.6), dpi=200)
        valeurs = [pc[c] for c in CRITICITES]
        barres = ax.bar(CRITICITES, valeurs, color=[f"#{COULEUR[c]}" for c in CRITICITES], width=0.6)
        for b, v in zip(barres, valeurs):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.05, str(v), ha="center", va="bottom", fontsize=7)
        ax.set_title("Constats par niveau de priorité", fontsize=9, color="#1F3864", fontweight="bold")
        ax.tick_params(labelsize=7)
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        for cote in ("top", "right"):
            ax.spines[cote].set_visible(False)
        fig.tight_layout()
        fig.savefig(chemin)
        plt.close(fig)

    # ------------------------------------------------------------------ V. Résultats globaux
    def resultats(self):
        self.h1("Résultats globaux")
        self.h2("Contrôles réalisés")
        par_srv = {s.id: [c for c in self.c.controles if c.id_serveur == s.id] for s in self.c.serveurs}
        total = sum(len(v) for v in par_srv.values())
        self.p(f"Le registre compte {total} ligne(s) de contrôle, dont {self.ind['controles_avec_preuve']} avec une preuve "
               f"référencée. Le contrôle C16 occupe deux lignes par serveur (analyse Debsecan et qualification des correctifs).")
        lignes = []
        for s in self.c.serveurs:
            ly = (self.serveur_cons(s.id).get("lynis") or {})
            lignes.append([s.nom, str(len(par_srv[s.id])), str(sum(1 for c in par_srv[s.id] if c.preuve.strip())),
                           _nr(str(ly.get("version") or "")), _nr(str(ly.get("tests") or "")), _nr(str(ly.get("indice") or ""))])
        self.tableau(["Serveur", "Lignes de contrôle", "Avec preuve", "Version Lynis", "Tests Lynis", "Indice Lynis"], lignes,
                     [4, 2.6, 2.4, 2.6, 2.6, 2.8])
        self.p("Indice Lynis : indicateur global de durcissement, à lire comme une tendance et non comme un pourcentage de "
               "conformité. N.R. : information non disponible (Lynis non exécuté ou fichier consolide.json absent).",
               italique=True, couleur=GRIS, taille=8.5)
        self.h2("Répartition par criticité")
        tot = self.ind["findings"] or 1
        lignes, remp = [], {}
        for i, crit in enumerate(CRITICITES):
            n = self.ind["par_criticite"][crit]
            lignes.append([crit, str(n), f"{round(100 * n / tot)} %", str(self.ind["transversaux_par_criticite"][crit])])
            remp[(i, 0)] = COULEUR[crit]
        if self.ind["non_qualifies"]:
            lignes.append(["À qualifier", str(self.ind["non_qualifies"]), f"{round(100 * self.ind['non_qualifies'] / tot)} %",
                           str(sum(1 for f in self.findings if f.priorite not in CRITICITES and f.nb_serveurs >= 2))])
        lignes.append(["Total", str(self.ind["findings"]), "100 %" if self.ind["findings"] else "0 %", str(self.ind["transversaux"])])
        self.tableau(["Criticité", "Constats", "Part", "dont transversaux"], lignes, [4, 3, 3, 4], remplissages=remp)
        self.h2("Répartition par serveur")
        self.p("Un constat transversal est compté pour chacun des serveurs concernés ; le total par serveur peut donc dépasser "
               "le nombre de constats.")
        lignes = []
        for s in self.c.serveurs:
            v = self.ind["par_serveur"][s.id]
            env = " / ".join(x for x in (s.environnement, s.criticite) if x) or NR
            lignes.append([s.nom, env] + [str(v[c]) for c in CRITICITES] + [str(sum(v.values()))])
        self.tableau(["Serveur", "Env. / criticité", "Critique", "Haute", "Moyenne", "Faible", "Total"], lignes,
                     [3.6, 3.4, 2, 2, 2, 2, 2])
        chemin = _figure_barres(self.nouvelle_figure("serveurs"), [s.nom for s in self.c.serveurs],
                                [[self.ind["par_serveur"][s.id][c] for s in self.c.serveurs] for c in CRITICITES],
                                "Constats par serveur et par criticité", empile=True,
                                couleurs=[f"#{COULEUR[c]}" for c in CRITICITES], noms=CRITICITES)
        self.figure(chemin, "Constats par serveur et par criticité")
        self.h2("Transversalité des constats")
        lignes = []
        nb_max = max(self.ind["par_nb_serveurs"]) if self.ind["par_nb_serveurs"] else 1
        for n in range(1, nb_max + 1):
            v = self.ind["par_nb_serveurs"][n]
            lignes.append([f"{n} serveur{'s' if n > 1 else ''}"] + [str(v[c]) for c in CRITICITES] + [str(sum(v.values()))])
        self.tableau(["Serveurs concernés", "Critique", "Haute", "Moyenne", "Faible", "Total"], lignes, [4, 2.4, 2.4, 2.4, 2.4, 2.4])
        chemin = _figure_barres(self.nouvelle_figure("transversalite"), [str(n) for n in range(1, nb_max + 1)],
                                [[self.ind["par_nb_serveurs"][n][c] for n in range(1, nb_max + 1)] for c in CRITICITES],
                                "Constats selon le nombre de serveurs concernés", empile=True,
                                couleurs=[f"#{COULEUR[c]}" for c in CRITICITES], noms=CRITICITES)
        self.figure(chemin, "Constats selon le nombre de serveurs concernés")
        self.h2("Domaines de sécurité concernés")
        doms = self.ind["par_domaine"]
        if doms:
            noms = sorted(doms, key=lambda d: -sum(doms[d].values()))
            chemin = _figure_barres(self.nouvelle_figure("domaines"), noms, [[doms[d][c] for d in noms] for c in CRITICITES],
                                    "Constats par domaine de sécurité et criticité", empile=True, horizontal=True,
                                    couleurs=[f"#{COULEUR[c]}" for c in CRITICITES], noms=CRITICITES)
            self.figure(chemin, "Constats par domaine de sécurité et criticité")
            maxi = max(sum(doms[d].values()) for d in noms)
            if maxi:
                plus = [d for d in noms if sum(doms[d].values()) == maxi]
                self.p(f"Domaine(s) le(s) plus représenté(s) : {', '.join(plus)} ({maxi} constat(s) qualifié(s) chacun).")
        else:
            self.p("Aucun constat enregistré.")

    # ------------------------------------------------------------------ VI. Analyse détaillée
    def fiche(self, f):
        self.h3(f"{f.code} – {f.intitule}")
        t = self.doc.add_table(rows=8, cols=2)
        try:
            t.style = "Table Grid"
        except KeyError:
            pass
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        crit = self.libelle_crit(f)
        fond = COULEUR.get(f.priorite, "7F7F7F")
        entete = t.rows[0].cells[0].merge(t.rows[0].cells[1])
        _texte_cellule(entete, f"Fiche {f.code}  ·  Criticité {crit}  ·  {f.nb_serveurs} serveur{'s' if f.nb_serveurs > 1 else ''}",
                       gras=True, couleur=BLANC, taille=9.5)
        _ombrer(entete, fond)
        ctl = self.controles_cites(f.constat)
        ref = f.reference.strip()
        if f.type_reference:
            ref = f"{ref}\n(type : {f.type_reference})" if ref else f"(type : {f.type_reference})"
        action = _nr(f.action)
        suivi = f"Responsable : {_nr(f.responsable)}  ·  Échéance : {_nr(f.echeance)}  ·  Statut : {_nr(f.statut)}"
        lignes = [
            ("Priorité", f"{crit} – serveur(s) concerné(s) : {self.noms_serveurs(f.ids_serveurs)} ({' ; '.join(f.ids_serveurs)})"),
            ("Contrôles mobilisés", ", ".join(ctl) if ctl else NR),
            ("Constat et éléments observés", _nr(f.constat)),
            ("Risque / impact", _nr(f.risque)),
            ("Référence(s)", _nr(ref)),
            ("Recommandation", _nr(f.recommandation)),
            ("Action de remédiation", f"{action}\n{suivi}"),
        ]
        for i, (libelle, valeur) in enumerate(lignes, 1):
            _texte_cellule(t.rows[i].cells[0], libelle, gras=True, taille=8.5)
            _ombrer(t.rows[i].cells[0], "D9E2F3")
            _texte_cellule(t.rows[i].cells[1], valeur, taille=8.5)
        _largeurs(t, [3.8, 13.2])
        self.doc.add_paragraph().paragraph_format.space_after = Pt(4)

    def analyse_detaillee(self):
        self.h1("Analyse détaillée des constats")
        self.p("Chaque constat est présenté selon une structure identique. Les éléments observés reprennent les valeurs relevées "
               "dans les preuves ; les fichiers de preuve sont cités dans le constat et récapitulés en annexe C.")
        titres = {"Critique": "Constats critiques", "Haute": "Constats de priorité haute", "Moyenne": "Constats de priorité moyenne",
                  "Faible": "Constats de priorité faible"}
        for crit in CRITICITES:
            groupe = [f for f in self.findings if f.priorite == crit]
            self.h2(titres[crit])
            if not groupe:
                self.p("Aucun constat de ce niveau.")
            for f in groupe:
                self.fiche(f)
        restants = [f for f in self.findings if f.priorite not in CRITICITES]
        if restants:
            self.h2("Pistes non qualifiées (version de travail)")
            for f in restants:
                self.fiche(f)

    # ------------------------------------------------------------------ VII. Analyse transversale C18
    def transversal(self):
        self.h1("Analyse transversale C18")
        self.h2("Vue d'ensemble")
        self.p("La matrice ci-dessous indique, pour chaque constat, les serveurs concernés (●).")
        srv = self.c.serveurs
        lignes, remp = [], {}
        for i, f in enumerate(self.findings):
            lignes.append([f.code, f.intitule] + ["●" if s.id in f.ids_serveurs else "" for s in srv])
            if f.priorite in COULEUR:
                remp[(i, 0)] = COULEUR[f.priorite]
        largeur_srv = min(2.2, 8.5 / max(1, len(srv)))
        self.tableau(["Réf.", "Constat"] + [s.nom for s in srv], lignes, [1.4, LARGEUR_UTILE - 1.4 - largeur_srv * len(srv)]
                     + [largeur_srv] * len(srv), remplissages=remp, taille=7.5)
        n = len(srv)
        self.h2("Faiblesses communes à tous les serveurs" if n > 1 else "Faiblesses communes")
        communs = [f for f in self.findings if n > 1 and f.nb_serveurs == n]
        if communs:
            for f in communs:
                self.puce(f" – {self.libelle_crit(f)} : {f.intitule}", gras_debut=f.code)
        else:
            self.p("Aucun constat n'est commun à l'ensemble des serveurs audités." if n > 1 else "Un seul serveur audité.")
        plusieurs = [f for f in self.findings if 1 < f.nb_serveurs < n]
        if plusieurs:
            self.p("Constats communs à plusieurs serveurs (sans les concerner tous) :")
            for f in plusieurs:
                self.puce(f" – {self.libelle_crit(f)} – {self.noms_serveurs(f.ids_serveurs)} : {f.intitule}", gras_debut=f.code)
        self.h2("Combinaisons de faiblesses par serveur")
        lignes = []
        for s in srv:
            liste = [f for f in self.findings if s.id in f.ids_serveurs]
            combi = ", ".join(f"{f.code} ({self.libelle_crit(f)})" for f in liste) or "Aucun constat"
            domaines = sorted({f.domaine for f in liste if f.domaine})
            v = self.ind["par_serveur"][s.id]
            analyse = (f"{len(liste)} constat(s) : {v['Critique']} critique(s), {v['Haute']} haute(s), {v['Moyenne']} moyenne(s), "
                       f"{v['Faible']} faible(s). Domaines : {', '.join(domaines) or NR}.")
            lignes.append([s.nom, combi, analyse])
        self.tableau(["Serveur", "Constats combinés", "Analyse"], lignes, [3, 6.5, 7.5])
        self.h2("Domaines présentant une exposition globale")
        lignes = []
        for dom in sorted({f.domaine for f in self.findings if f.domaine}):
            liste = [f for f in self.findings if f.domaine == dom]
            touches = sorted({i for f in liste for i in f.ids_serveurs})
            lignes.append([dom, ", ".join(f.code for f in liste),
                           f"{len(liste)} constat(s) ; {len(touches)} serveur(s) concerné(s) sur {n}."])
        if lignes:
            self.tableau(["Domaine", "Constats", "Synthèse"], lignes, [5, 4, 8])
        else:
            self.p("Aucun constat enregistré.")
        self.h2("Priorités transversales")
        trans = [f for f in self.findings if f.nb_serveurs >= 2]
        if trans:
            self.p("Les constats transversaux, classés par niveau de priorité puis par nombre de serveurs concernés, sont à "
                   "traiter de préférence par une mesure commune (configuration de référence, déploiement centralisé) :")
            for f in trans:
                self.puce(f" – {self.libelle_crit(f)} – {f.nb_serveurs} serveurs : {f.intitule}", gras_debut=f.code)
        else:
            self.p("Aucun constat transversal.")

    # ------------------------------------------------------------------ VIII. Plan de remédiation
    def plan(self):
        self.h1("Plan de remédiation")
        self.p("Les actions sont reprises du registre d'audit. Responsable, échéance et statut ne sont indiqués que s'ils y "
               "sont renseignés (N.R. : non renseigné).")
        for crit in CRITICITES:
            groupe = [f for f in self.findings if f.priorite == crit]
            self.h2(f"Priorité {crit.lower()} ({len(groupe)} action{'s' if len(groupe) > 1 else ''})")
            if not groupe:
                self.p("Aucune action de ce niveau.")
                continue
            self.tableau(["Réf.", "Constat", "Action recommandée", "Serveurs", "Resp.", "Éch.", "Statut"],
                         [[f.code, f.intitule, _nr(f.action or f.recommandation), self.noms_serveurs(f.ids_serveurs),
                           _nr(f.responsable), _nr(f.echeance), _nr(f.statut)] for f in groupe],
                         [1.2, 4.0, 5.2, 2.6, 1.4, 1.4, 1.6], couleur_entete=COULEUR[crit], taille=7.5)

    # ------------------------------------------------------------------ IX. Conclusion
    def conclusion(self):
        self.h1("Conclusion")
        pc = self.ind["par_criticite"]
        n = len(self.c.serveurs)
        self.p(f"L'audit de {n} serveur{'s' if n > 1 else ''} Linux a conduit à {self.ind['findings']} constat(s), dont "
               f"{pc['Critique']} critique(s) et {pc['Haute']} de priorité haute ; {self.ind['transversaux']} constat(s) "
               f"concernent plusieurs serveurs et relèvent de mesures communes.")
        if self.texte("conclusion"):
            for para in self.texte("conclusion").split("\n\n"):
                self.p(para)
        if self.texte("pilotage"):
            self.encadre("Recommandation de pilotage", self.texte("pilotage"))
        self.p("Une nouvelle collecte LSAF après remédiation permettra de vérifier l'efficacité des actions et de renseigner les "
               "colonnes « Vérification après remédiation » du registre.")

    # ------------------------------------------------------------------ X. Annexes
    def annexes(self):
        self.h1("Annexes")
        self.doc.add_heading("Annexe A – Périmètre détaillé", level=2)
        lignes = []
        for s in self.c.serveurs:
            val = {c.controle_lsaf: c.valeur for c in self.c.controles if c.id_serveur == s.id}
            lignes.append([f"{s.nom} ({s.id})", _nr(val.get("C01", "")), _nr(val.get("C02", "")), _nr(val.get("C05", ""))])
        self.tableau(["Serveur", "Système (C01)", "Ressources (C02)", "Réseau (C05)"], lignes, [3, 4.5, 4.5, 5], taille=7.5)
        self.doc.add_heading("Annexe B – Matrice des contrôles", level=2)
        self.p("✔ : contrôle réalisé avec preuve référencée ; — : pas de preuve (contrôle non réalisé ou non exploitable).")
        cles = []
        for c in self.c.controles:
            cle = (c.controle_lsaf or c.element, c.element)
            if cle not in cles:
                cles.append(cle)
        cles.sort(key=lambda k: (cle_tri(k[0]) if re.match(r"^C\d{2}", k[0] or "") else (99, 0), k[1]))
        lignes = []
        for cid, element in cles:
            ligne = [cid, PAR_ID[cid].intitule if cid in PAR_ID and not element.startswith("Qualification") else element]
            for s in self.c.serveurs:
                trouve = [c for c in self.c.controles if c.id_serveur == s.id and (c.controle_lsaf or c.element) == cid
                          and c.element == element]
                ligne.append("✔" if trouve and trouve[0].preuve.strip() else "—")
            lignes.append(ligne)
        n = max(1, len(self.c.serveurs))
        lsrv = min(2.2, 9 / n)
        self.tableau(["Réf.", "Contrôle"] + [s.nom for s in self.c.serveurs], lignes,
                     [1.6, LARGEUR_UTILE - 1.6 - lsrv * n] + [lsrv] * n, taille=7.5)
        self.doc.add_heading("Annexe C – Synthèse des preuves", level=2)
        self.p("Fichiers de preuve référencés dans la feuille CONTROLES_ET_PREUVES (dossier de session LSAF de chaque serveur).")
        for s in self.c.serveurs:
            self.h3(f"{s.nom} ({s.id})")
            self.tableau(["Réf.", "Élément contrôlé", "Fichier(s) de preuve"],
                         [[c.controle_lsaf or c.id, c.element, _nr(c.preuve).replace(" ; ", "\n")]
                          for c in self.c.controles if c.id_serveur == s.id], [1.6, 6.4, 9], taille=7)
        self.doc.add_heading("Annexe D – Références méthodologiques", level=2)
        refs = sorted({r.strip() for f in self.c.findings for r in re.split(r"\n|;", f.reference) if r.strip()})
        if refs:
            self.p("Références citées dans le registre (colonne « Référence de contrôle ») :")
            for r in refs:
                self.puce(r)
        else:
            self.p("Aucune référence n'est renseignée dans le registre.")
        self.p("Documentation des outils utilisés : Lynis (CISOfy), systemd-analyze (projet systemd), Debsecan (projet Debian), "
               "pages de manuel des commandes natives (ss, sshd, sysctl, journalctl, apt).")
        self.doc.add_heading("Annexe E – Glossaire", level=2)
        self.tableau(["Terme", "Définition"], [list(x) for x in GLOSSAIRE], [4, 13])

    # ------------------------------------------------------------------ assemblage
    def construire(self) -> Document:
        self.entete_pied()
        self.couverture()
        self.gestion_document()
        self.saut_page()
        self.n_h1 = 0
        self.introduction()
        self.perimetre()
        self.methodologie()
        self.synthese()
        self.resultats()
        self.analyse_detaillee()
        self.transversal()
        self.plan()
        self.conclusion()
        self.annexes()
        self.doc.core_properties.title = "Rapport d'audit de sécurité – Serveurs Linux"
        self.doc.core_properties.author = self.cfg.get("auteur") or "LSAF"
        self.doc.core_properties.comments = "Généré par LSAF à partir du registre " + self.c.chemin.name
        return self.doc


class RapportRefuse(Exception):
    """Le classeur n'est pas entièrement qualifié et --brouillon n'a pas été demandé."""

    def __init__(self, problemes):
        super().__init__(f"{len(problemes)} point(s) bloquant(s)")
        self.problemes = problemes


def generer_rapport(classeur: Classeur, chemin: Path, consolide: Optional[dict] = None, config: Optional[dict] = None,
                    brouillon: bool = False, modele: Optional[Path] = None) -> Path:
    problemes = classeur.problemes_qualification()
    if problemes and not brouillon:
        raise RapportRefuse(problemes)
    r = Rapport(classeur, consolide, config or {}, brouillon, modele)
    doc = r.construire()
    # Demande à Word de mettre à jour les champs (sommaire, numéros de page) à l'ouverture.
    reglages = doc.settings.element
    maj = OxmlElement("w:updateFields")
    maj.set(qn("w:val"), "true")
    reglages.append(maj)
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    doc.save(chemin)
    return chemin
