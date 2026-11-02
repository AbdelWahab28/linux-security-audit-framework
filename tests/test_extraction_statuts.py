"""Extraction des valeurs factuelles et statuts de contrôle."""

from lsaf import statuts as S
from lsaf.analyse import analyser_session
from lsaf.session import charger_session
from lsaf.synthetique import generer_session


def resultats(chemin):
    return {r.controle: r for r in analyser_session(charger_session(chemin), ecrire=False)}


def test_valeurs_extraites_profil_faible(session_faible):
    r = resultats(session_faible)
    assert "Ubuntu 22.04.4 LTS" in r["C01"].resume
    assert r["C03"].valeurs["redemarrage_requis"] is True
    assert "aucun filtrage restrictif identifié" in r["C08"].resume
    assert "permitrootlogin without-password" in r["C09"].resume
    assert "PASS_MAX_DAYS 99999" in r["C17-02"].resume
    assert r["C17"].valeurs["indice_durcissement"] == 58
    tls = r["C17-05"].valeurs["tls"][0]
    assert tls["connecte"] and tls["certificat"]["expire_a_la_collecte"] and tls["certificat"]["emetteur_egal_sujet"]


def test_profil_durci(session_durcie):
    r = resultats(session_durcie)
    assert "filtrage restrictif identifié" in r["C08"].resume
    assert "aucun" not in r["C08"].resume.split("synthèse :")[1]
    assert r["C17-05"].valeurs["tls"][0]["certificat"]["expire_a_la_collecte"] is False


def test_statut_reussi_ne_signifie_pas_conforme(session_faible):
    r = resultats(session_faible)
    # « Réussi » = collecte exploitable ; aucun résultat ne porte d'état de conformité
    assert r["C09"].statut == S.REUSSI
    assert "conforme" not in r["C09"].en_dict()


def test_controle_non_execute(tmp_path):
    s = generer_session(tmp_path, "SRV-EXEMPLE-09", "faible", controles=["C01", "C02"])
    r = resultats(s)
    assert r["C01"].statut == S.REUSSI
    assert r["C09"].statut == S.NON_EXECUTE
    assert r["C09"].statut not in S.AVEC_PREUVE


def test_outil_absent_donne_collecte_impossible(tmp_path):
    s = generer_session(tmp_path, "SRV-EXEMPLE-08", "faible", remplacements={"C17.audit_lynis": ("outil_absent", None, "")})
    r = resultats(s)["C17"]
    assert r.statut == S.COLLECTE_IMPOSSIBLE
    assert any("Lynis n'est pas installé" in x for x in r.limites)


def test_message_d_erreur_dans_une_sortie_donne_a_verifier(tmp_path):
    sortie = "===== SSH - ETAT DU SERVICE =====\nactive\n\n===== SSH - CONFIGURATION EFFECTIVE =====\nsudo: a password is required"
    s = generer_session(tmp_path, "SRV-EXEMPLE-07", "faible", remplacements={"C09.ssh": ("code_non_nul", 1, sortie)})
    r = resultats(s)["C09"]
    assert r.statut != S.REUSSI


def test_debsecan_sur_ubuntu_a_verifier(session_faible):
    r = resultats(session_faible)["C16"]
    assert r.statut == S.A_VERIFIER
    assert any("Debsecan est conçu pour Debian" in x for x in r.a_verifier)


def test_priorite_des_statuts():
    ok = dict(statut_execution="termine", preuve_presente=True, tronquee=False, erreur_analyse=False,
              blocs_cles_executes=True, integrite="verifiee", extraction_complete=True, blocs_degrades=False,
              elements_a_verifier=False)
    assert S.determiner_statut(**ok) == S.REUSSI
    assert S.determiner_statut(**{**ok, "statut_execution": None, "preuve_presente": False}) == S.NON_EXECUTE
    assert S.determiner_statut(**{**ok, "preuve_presente": False}) == S.EN_ECHEC
    assert S.determiner_statut(**{**ok, "tronquee": True}) == S.EN_ECHEC
    assert S.determiner_statut(**{**ok, "blocs_cles_executes": False}) == S.COLLECTE_IMPOSSIBLE
    assert S.determiner_statut(**{**ok, "integrite": "modifiee"}) == S.PREUVE_INSUFFISANTE
    assert S.determiner_statut(**{**ok, "blocs_degrades": True}) == S.PARTIEL
    assert S.determiner_statut(**{**ok, "elements_a_verifier": True}) == S.A_VERIFIER
    # l'absence de preuve n'est jamais un succès
    for variante in ({"preuve_presente": False}, {"tronquee": True}, {"blocs_cles_executes": False}):
        assert S.determiner_statut(**{**ok, **variante}) != S.REUSSI
