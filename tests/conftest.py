"""Configuration commune des tests.

Tous les tests utilisent des données SYNTHÉTIQUES (serveurs fictifs) ; seuls les
tests du collecteur exécutent réellement C01/C02 (lecture seule) sur la machine
qui lance les tests. Ne lancez jamais la suite de tests sur un serveur de production.
"""

from pathlib import Path

import pytest

from lsaf.synthetique import generer_demo, generer_session

RACINE = Path(__file__).resolve().parent.parent


@pytest.fixture
def racine():
    return RACINE


@pytest.fixture
def session_faible(tmp_path):
    return generer_session(tmp_path, "SRV-EXEMPLE-01", "faible")


@pytest.fixture
def session_durcie(tmp_path):
    return generer_session(tmp_path, "SRV-EXEMPLE-02", "durci", "20261102_103000", "192.0.2.20")


@pytest.fixture
def sessions_demo(tmp_path):
    return generer_demo(tmp_path / "sessions")
