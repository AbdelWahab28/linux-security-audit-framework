"""Règles de croisement C18 : pistes factuelles, jamais de criticité."""

from lsaf.c18 import DECLENCHEE, NON_CONCLUANTE, REGLES
from lsaf.consolidation import consolider
from lsaf.synthetique import generer_session


def evaluations(donnees, regle):
    return {e["serveur"]: e["resultat"] for e in donnees["c18"]["evaluations"] if e["regle"] == regle}


def test_definition_des_regles():
    assert len(REGLES) == 11
    for r in REGLES:
        assert r.axe and r.titre
        assert r.controles


def test_pistes_profil_faible_et_durci(sessions_demo):
    d = consolider(sessions_demo, None, None, ecrire_resultats=False)
    assert evaluations(d, "R01") == {"SRV-EXEMPLE-01": DECLENCHEE, "SRV-EXEMPLE-02": "non déclenchée", "SRV-EXEMPLE-03": DECLENCHEE}
    assert evaluations(d, "R03")["SRV-EXEMPLE-02"] == "non déclenchée"
    assert evaluations(d, "R09")["SRV-EXEMPLE-01"] == DECLENCHEE
    # Lynis absent sur SRV-EXEMPLE-03 : la règle Lynis ne peut pas conclure
    assert evaluations(d, "R11")["SRV-EXEMPLE-03"] == NON_CONCLUANTE


def test_les_pistes_ne_contiennent_aucune_qualification(sessions_demo):
    d = consolider(sessions_demo, None, None, ecrire_resultats=False)
    for p in d["c18"]["pistes"]:
        assert not {"criticite", "priorite", "risque", "recommandation", "reference"} & set(p)
        for hote, faits in p["faits"].items():
            assert faits, hote


def test_transversal_compare_les_serveurs(sessions_demo):
    d = consolider(sessions_demo, None, None, ecrire_resultats=False)
    cve = [t for t in d["c18"]["transversal"] if t["valeur"] == "CVE-2099-0001"]
    assert cve and cve[0]["serveurs"] == ["SRV-EXEMPLE-01", "SRV-EXEMPLE-03"]


def test_donnees_manquantes_non_concluant(tmp_path):
    s = generer_session(tmp_path, "SRV-EXEMPLE-05", "faible", controles=["C01", "C06"])
    d = consolider([s], None, None, ecrire_resultats=False)
    assert evaluations(d, "R01")["SRV-EXEMPLE-05"] == NON_CONCLUANTE
    assert not d["c18"]["pistes"] or all("R01" != p["regle"] for p in d["c18"]["pistes"])


def test_consolidation_refuse_deux_sessions_du_meme_serveur(tmp_path):
    import pytest
    from lsaf.consolidation import ErreurConsolidation
    a = generer_session(tmp_path, "SRV-EXEMPLE-01", "faible", "20261102_101500")
    b = generer_session(tmp_path, "SRV-EXEMPLE-01", "faible", "20261102_111500")
    with pytest.raises(ErreurConsolidation):
        consolider([a, b], None, None, ecrire_resultats=False)
