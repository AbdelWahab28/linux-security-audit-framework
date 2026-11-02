"""Lecture des preuves, intégrité et complétude des sessions."""

import json

from lsaf.preuves import decouper_sections, lire_preuve
from lsaf.session import charger_session, trouver_sessions


def codes(session):
    return {a.code for a in session.anomalies}


def test_session_synthetique_complete(session_faible):
    s = charger_session(session_faible)
    assert s.hote == "SRV-EXEMPLE-01"
    assert not s.erreurs(), [a.message for a in s.anomalies]
    assert len(s.controles) == 24
    assert all(p.integrite == "verifiee" for p in s.controles.values())


def test_decoupage_des_sections_du_document():
    texte = "===== UFW =====\nStatus: inactive\n----- PORT 443 -----\nCONNECTED\n--- nginx ---\nactive\n### NOYAU\n6.1"
    s = decouper_sections(texte)
    assert s["UFW"] == "Status: inactive"
    assert s["PORT 443"] == "CONNECTED"     # 5 tirets : titre « PORT 443 », pas « -- PORT 443 -- »
    assert s["nginx"] == "active"
    assert s["NOYAU"] == "6.1"


def test_preuve_modifiee_detectee(session_faible):
    txt = next((session_faible / "preuves").glob("C09_*.txt"))
    txt.write_text(txt.read_text() + "ligne ajoutée\n")
    s = charger_session(session_faible)
    assert "PREUVE_MODIFIEE" in codes(s)
    assert s.controles["C09"].integrite == "modifiee"


def test_preuve_tronquee(session_faible):
    txt = next((session_faible / "preuves").glob("C05_*.txt"))
    contenu = txt.read_text()
    txt.write_text(contenu[: contenu.index("LSAF-BLOC FIN")])
    p = lire_preuve(txt)
    assert p.tronque


def test_preuve_absente_et_json_absent(session_faible):
    next((session_faible / "preuves").glob("C10_*.txt")).unlink()
    next((session_faible / "preuves").glob("C11_*.json")).unlink()
    s = charger_session(session_faible)
    assert {"PREUVE_ABSENTE", "JSON_ABSENT"} <= codes(s)


def test_fichier_inattendu_et_simulation(session_faible):
    (session_faible / "preuves" / "notes.txt").write_text("x")
    manifeste = json.loads((session_faible / "session.json").read_text())
    manifeste["parametres"]["simulation"] = True
    (session_faible / "session.json").write_text(json.dumps(manifeste))
    s = charger_session(session_faible)
    assert "FICHIER_INATTENDU" in codes(s)
    assert "SIMULATION" in {a.code for a in s.erreurs()}


def test_trouver_sessions_dans_dossier_parent(sessions_demo):
    parent = sessions_demo[0].parent
    assert len(trouver_sessions([parent])) == 3
