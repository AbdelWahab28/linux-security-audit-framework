"""Extraction des valeurs observées dans les preuves.

Chaque fonction lit la sortie des commandes d'un contrôle et
retourne uniquement des faits :

* ``valeurs``     : valeurs structurées (servent au classeur et à C18) ;
* ``resume``      : texte de la colonne « Configuration / Valeur observée » ;
* ``a_verifier``  : éléments que l'auditeur doit vérifier (sortie inattendue,
                    commande sans résultat, outil non adapté au système...) ;
* ``limites``     : limites de la collecte constatées dans la preuve ;
* ``complet``     : faux si les valeurs essentielles n'ont pas été trouvées.

Aucune extraction ne porte de jugement de conformité : l'« État initial »
(Conforme / Non conforme...) est décidé par l'auditeur.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Extraction:
    valeurs: dict = field(default_factory=dict)
    resume: str = ""
    a_verifier: list = field(default_factory=list)
    limites: list = field(default_factory=list)
    complet: bool = True


from .systeme import extraire_c01, extraire_c02, extraire_c03, extraire_c04  # noqa: E402
from .reseau import extraire_c05, extraire_c06, extraire_c07, extraire_c08, extraire_c09  # noqa: E402
from .acces import (extraire_c10, extraire_c11, extraire_c12, extraire_c13, extraire_c14,  # noqa: E402
                    extraire_c15, extraire_c16)
from .durcissement import (extraire_c17, extraire_c17_01, extraire_c17_02, extraire_c17_03,  # noqa: E402
                           extraire_c17_04, extraire_c17_05, extraire_c17_06, extraire_c17_07)

EXTRACTEURS = {
    "C01": extraire_c01, "C02": extraire_c02, "C03": extraire_c03, "C04": extraire_c04,
    "C05": extraire_c05, "C06": extraire_c06, "C07": extraire_c07, "C08": extraire_c08, "C09": extraire_c09,
    "C10": extraire_c10, "C11": extraire_c11, "C12": extraire_c12, "C13": extraire_c13, "C14": extraire_c14,
    "C15": extraire_c15, "C16": extraire_c16,
    "C17": extraire_c17, "C17-01": extraire_c17_01, "C17-02": extraire_c17_02, "C17-03": extraire_c17_03,
    "C17-04": extraire_c17_04, "C17-05": extraire_c17_05, "C17-06": extraire_c17_06, "C17-07": extraire_c17_07,
}
