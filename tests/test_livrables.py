"""Classeur Excel, rapport Word, nommage et cohérence (données synthétiques)."""

import shutil
import subprocess
from datetime import datetime

import pytest
from openpyxl import load_workbook

from lsaf.classeur import ANA_COLONNES, CTL_COLONNES, INV_COLONNES, MENTION_A_QUALIFIER, generer_classeur
from lsaf.consolidation import consolider
from lsaf.lecture_classeur import lire_classeur
from lsaf.nommage import chemin_libre, libelle_livrable
from lsaf.rapport import RapportRefuse, generer_rapport
from lsaf.synthetique import INVENTAIRE_DEMO, qualifier_demo
from lsaf.verification import verifier_coherence


@pytest.fixture
def donnees(sessions_demo):
    return consolider(sessions_demo, INVENTAIRE_DEMO, "DEMO", ecrire_resultats=False)


@pytest.fixture
def classeur(donnees, tmp_path):
    return generer_classeur(donnees, tmp_path / "LSAF_Audit_DEMO_20261102.xlsx")


def entetes(ws, n):
    return [ws.cell(row=5, column=c).value for c in range(1, n + 1)]


def test_structure_du_registre(classeur):
    wb = load_workbook(classeur)
    assert wb.sheetnames[:4] == ["INVENTAIRE_AUDIT", "CONTROLES_ET_PREUVES", "ANALYSE", "DASHBOARD"]
    assert entetes(wb["INVENTAIRE_AUDIT"], 23) == INV_COLONNES
    assert entetes(wb["CONTROLES_ET_PREUVES"], 13) == CTL_COLONNES[:13]
    assert entetes(wb["ANALYSE"], 19) == ANA_COLONNES
    assert wb["INVENTAIRE_AUDIT"]["A6"].value == "SRV-LINUX-01"
    # 25 lignes par serveur (C16 sur deux lignes)
    ctl = wb["CONTROLES_ET_PREUVES"]
    assert sum(1 for r in range(6, ctl.max_row + 1) if ctl.cell(row=r, column=2).value) == 75


def test_lsaf_ne_qualifie_jamais(classeur):
    wb = load_workbook(classeur)
    ctl, ana = wb["CONTROLES_ET_PREUVES"], wb["ANALYSE"]
    assert all(ctl.cell(row=r, column=9).value is None for r in range(6, ctl.max_row + 1))   # état initial
    lignes = [r for r in range(6, ana.max_row + 1) if ana.cell(row=r, column=3).value]
    assert lignes
    for r in lignes:
        for col in (4, 5, 7, 8, 9, 10, 11, 12):   # référence, type, risque, priorité, reco, action, resp., échéance
            assert ana.cell(row=r, column=col).value is None
        assert ana.cell(row=r, column=19).value.startswith(MENTION_A_QUALIFIER)
        assert ana.cell(row=r, column=3).value.startswith("F")


def test_sans_preuve_jamais_conforme(classeur):
    wb = load_workbook(classeur)
    ctl = wb["CONTROLES_ET_PREUVES"]
    for r in range(6, ctl.max_row + 1):
        if ctl.cell(row=r, column=15).value == "Collecte impossible":
            assert not ctl.cell(row=r, column=13).value
            assert ctl.cell(row=r, column=9).value is None


@pytest.mark.skipif(shutil.which("soffice") is None, reason="LibreOffice absent : formules non recalculées")
def test_formules_du_dashboard(classeur, tmp_path):
    subprocess.run(["soffice", "--headless", "--convert-to", "xlsx", "--outdir", str(tmp_path / "calc"), str(classeur)],
                   capture_output=True, timeout=180)
    calc = next((tmp_path / "calc").glob("*.xlsx"))
    wb = load_workbook(calc, data_only=True)
    d = wb["DASHBOARD"]
    assert d["B4"].value == 3          # serveurs audités
    assert d["D4"].value == 75         # contrôles enregistrés
    assert d["F4"].value == 11         # findings C18 (pistes)
    assert d["P4"].value == 11         # transversaux
    for ws in wb:
        for ligne in ws.iter_rows():
            for c in ligne:
                assert not (isinstance(c.value, str) and c.value.startswith("#")), (ws.title, c.coordinate, c.value)


def test_rapport_refuse_tant_que_non_qualifie(classeur, donnees, tmp_path):
    with pytest.raises(RapportRefuse) as e:
        generer_rapport(lire_classeur(classeur), tmp_path / "r.docx", donnees)
    assert any(MENTION_A_QUALIFIER in p for p in e.value.problemes)
    brouillon = generer_rapport(lire_classeur(classeur), tmp_path / "b.docx", donnees, brouillon=True)
    bilan = verifier_coherence(classeur, brouillon, donnees, brouillon=True)
    assert bilan.ok, bilan.erreurs


def test_rapport_qualifie_et_coherence(classeur, donnees, tmp_path):
    qualifie = qualifier_demo(classeur, tmp_path / "q.xlsx")
    c = lire_classeur(qualifie)
    assert c.problemes_qualification() == []
    rapport = generer_rapport(c, tmp_path / "r.docx", donnees, {"confidentialite": "Confidentiel"})
    bilan = verifier_coherence(qualifie, rapport, donnees)
    assert bilan.ok, bilan.erreurs
    from docx import Document
    texte = "\n".join(p.text for p in Document(str(rapport)).paragraphs)
    for titre in ("I. Introduction", "II. Périmètre de l'audit", "III. Méthodologie", "IV. Synthèse exécutive",
                  "V. Résultats globaux", "VI. Analyse détaillée des constats", "VII. Analyse transversale C18",
                  "VIII. Plan de remédiation", "IX. Conclusion", "X. Annexes"):
        assert titre in texte


def test_incoherence_detectee(classeur, donnees, tmp_path):
    qualifie = qualifier_demo(classeur, tmp_path / "q.xlsx")
    rapport = generer_rapport(lire_classeur(qualifie), tmp_path / "r.docx", donnees)
    wb = load_workbook(qualifie)
    wb["ANALYSE"]["H6"] = "Critique"          # modification du classeur après génération du rapport
    wb.save(qualifie)
    assert not verifier_coherence(qualifie, rapport, donnees).ok


def test_nommage_sans_ecrasement(tmp_path):
    date = datetime(2026, 11, 2)
    assert libelle_livrable(["HOST-EXAMPLE"]) == "HOST-EXAMPLE"
    assert libelle_livrable(["A", "B"]) == "MULTI-2SRV"
    p1 = chemin_libre(tmp_path, "LSAF_Audit", "HOST-EXAMPLE", ".xlsx", date)
    assert p1.name == "LSAF_Audit_HOST-EXAMPLE_20261102.xlsx"
    p1.write_text("x")
    assert chemin_libre(tmp_path, "LSAF_Audit", "HOST-EXAMPLE", ".xlsx", date).name == "LSAF_Audit_HOST-EXAMPLE_20261102_2.xlsx"


def test_commande_demo(tmp_path):
    from lsaf.cli import main
    assert main(["demo", "-o", str(tmp_path / "demo")]) == 0
    with pytest.raises(SystemExit):          # la démonstration n'écrase jamais un dossier existant
        main(["demo", "-o", str(tmp_path / "demo")])
