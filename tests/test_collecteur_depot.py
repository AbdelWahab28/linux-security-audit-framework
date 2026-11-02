"""Collecteur (bash) et hygiène du dépôt.

Les tests du collecteur n'exécutent que --simulation (rien n'est exécuté) et les
contrôles d'identification C01/C02 (lecture seule) sur la machine qui lance les
tests. Ne lancez jamais la suite de tests sur un serveur de production.
"""

import json
import os
import re
import shutil
import subprocess
import sys

import pytest

COLLECTEUR = "collecteur/lsaf-collecte.sh"
linux = pytest.mark.skipif(sys.platform != "linux", reason="le collecteur cible Linux")


def lancer(racine, *args):
    env = dict(os.environ)
    return subprocess.run(["bash", str(racine / COLLECTEUR), "-y", *args], capture_output=True, text=True, env=env,
                          stdin=subprocess.DEVNULL, timeout=300)


@linux
def test_simulation_n_execute_rien(racine, tmp_path):
    r = lancer(racine, "--simulation", "-o", str(tmp_path))
    assert r.returncode == 0, r.stderr
    session = next(tmp_path.iterdir())
    for f in (session / "preuves").glob("*.json"):
        ex = json.loads(f.read_text())
        assert all(b["statut"] == "simulation" and b["code_retour"] is None for b in ex["blocs"])


@linux
def test_c01_c02_alias_et_pas_d_ecrasement(racine, tmp_path):
    r = lancer(racine, "-c", "C01,C02", "--alias-hote", "HOST-EXAMPLE", "-o", str(tmp_path))
    assert r.returncode == 0, r.stderr
    sessions = sorted(p.name for p in tmp_path.iterdir())
    assert len(sessions) == 1 and sessions[0].startswith("HOST-EXAMPLE_")
    noms = sorted(p.name for p in (tmp_path / sessions[0] / "preuves").iterdir())
    assert re.match(r"^C01_HOST-EXAMPLE_\d{8}_\d{6}\.json$", noms[0])
    m = json.loads((tmp_path / sessions[0] / "session.json").read_text())
    assert m["controles"]["C09"] == "non_execute"
    r2 = lancer(racine, "-c", "C01", "--alias-hote", "HOST-EXAMPLE", "-o", str(tmp_path))
    assert r2.returncode == 0
    assert len(list(tmp_path.iterdir())) == 2
    from lsaf.analyse import analyser_session
    from lsaf.session import charger_session
    s = charger_session(tmp_path / sessions[0])
    statuts = {x.controle: x.statut for x in analyser_session(s, ecrire=False)}
    assert statuts["C09"] == "non_execute"
    assert statuts["C01"] != "non_execute"


def test_controle_inconnu_refuse(racine, tmp_path):
    r = lancer(racine, "-c", "C99", "-o", str(tmp_path))
    assert r.returncode == 2 and "Contrôle inconnu" in r.stderr + r.stdout


def test_collecteur_en_lecture_seule(racine):
    """Garde-fou statique : aucune commande modifiant le système dans le collecteur."""
    interdits = [r"\brm\s+-", r"\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask)\b",
                 r"\bapt(-get)?\s+(install|remove|upgrade|update|purge|autoremove)\b", r"\bdpkg\s+-(i|r|P)\b",
                 r"\bsysctl\s+-w\b", r"\bufw\s+(enable|disable|allow|deny|reset)\b", r"\biptables\s+-[AIDFX]\b",
                 r"\bnft\s+(add|delete|flush)\b", r"\bcurl\b", r"\bwget\b", r"\bscp\b", r"\brsync\s+-[a-zA-Z]*[avrz]",
                 r"\bpasswd\s+-[lud]\b", r"\buser(del|mod|add)\b", r"\bchmod\b[^\n]*\s/(etc|usr|var|boot|home|root|opt)\b", r"\bchown\s+\S+\s+/(etc|usr|var|boot)",
                 r"(^|[;&|]\s*)(reboot|shutdown|halt|poweroff)\b", r"\bgit\s+push\b", r"\bmkfs\b", r"\bdd\s+if="]
    for chemin in (racine / "collecteur").rglob("*.sh"):
        code = "\n".join(l for l in chemin.read_text().splitlines()
                         if not l.strip().startswith("#") and not re.match(r'^\s*(echo|journal|ajouter_note|printf)\b', l.strip()))
        for motif in interdits:
            assert not re.search(motif, code, flags=re.M), f"{motif} trouvé dans {chemin.name}"


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck absent")
def test_shellcheck(racine):
    fichiers = [str(p) for p in (racine / "collecteur").rglob("*.sh")]
    r = subprocess.run(["shellcheck", "-x", "-S", "warning", *fichiers], capture_output=True, text=True, cwd=racine)
    assert r.returncode == 0, r.stdout


@pytest.mark.skipif(shutil.which("git") is None, reason="git absent")
def test_gitignore_exclut_les_donnees_d_audit(racine, tmp_path):
    shutil.copy(racine / ".gitignore", tmp_path / ".gitignore")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    ignores = ["lsaf-sessions/HOST_20261102_101500/preuves/C01_HOST_20261102_101500.txt",
               "lsaf-sessions/HOST_20261102_101500/session.json", "livrables/LSAF_Audit_X_20261102.xlsx",
               "livrables/LSAF_Consolide_X_20261102.json", "n_importe_ou/LSAF_Rapport_X_20261102.docx", "notes.xlsx",
               "preuves/C09.json", "resultats/C09.json", "journal/collecte.log", "C17_SRV_20261102_101500.lynis.txt",
               "C09_SRV_20261102_101500.txt", "C17-02_SRV_20261102_101500.json", "config/lsaf.yaml", "inventaire.yaml",
               "lsaf-demo/LSAF_Audit_DEMO_brut.xlsx", "SHA256SUMS", ".env", "liste-interdite.txt"]
    conserves = ["README.md", "config/lsaf.exemple.yaml", "exemples/inventaire.exemple.yaml",
                 "lsaf/donnees/session.schema.json", "exemples/session-synthetique/README.md",
                 "exemples/session-synthetique/SRV-EXEMPLE-01_20261102_101500/preuves/C01_SRV-EXEMPLE-01_20261102_101500.txt",
                 "exemples/session-synthetique/SRV-EXEMPLE-01_20261102_101500/session.json", "tests/test_c18.py"]
    for f in ignores + conserves:
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("x")
    r = subprocess.run(["git", "check-ignore", *ignores, *conserves], cwd=tmp_path, capture_output=True, text=True)
    sortie = set(r.stdout.split())
    assert set(ignores) <= sortie, set(ignores) - sortie
    assert not (set(conserves) & sortie), set(conserves) & sortie


def test_verificateur_de_publication(racine):
    r = subprocess.run([sys.executable, str(racine / "outils" / "verifier_publication.py"), str(racine)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
